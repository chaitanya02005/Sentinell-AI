const SOURCE = "gemini";

let checking = false;
let approvedText = "";
let approvedUntil = 0;
let responseScanTimer = 0;
let responseObserver = null;
let fileScanInFlight = false;
let extensionSettings = {
  promptProtection: true,
  responseMonitoring: true,
  attachmentScanning: true,
  showPanelPreview: true
};
const responseState = new WeakMap();
const approvedFileInputs = new WeakMap();

console.debug("[Sentinell.AI] Gemini firewall loaded");
loadExtensionSettings();
chrome.storage?.onChanged?.addListener((changes, area) => {
  if (area === "local" && changes.settings?.newValue) {
    extensionSettings = { ...extensionSettings, ...changes.settings.newValue };
    syncResponseMonitoring();
  }
});

document.addEventListener("click", (event) => {
  const button = findButtonFromEvent(event);
  if (!button || !isGeminiSendButton(button)) return;

  const editor = findGeminiEditor();
  const text = getEditorText(editor);
  if (!extensionSettings.promptProtection) return;
  if (!text.trim() || isTemporarilyApproved(text)) return;

  event.preventDefault();
  event.stopPropagation();
  event.stopImmediatePropagation();

  checkPromptAndDecide({
    text,
    submit: () => {
      approveOnce(text);
      setTimeout(() => button.click(), 80);
    }
  });
}, true);

document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey) return;

  const editor = findGeminiEditor();
  if (!editor || !eventPath(event).some((node) => node === editor || editor.contains?.(node))) return;

  const text = getEditorText(editor);
  if (!extensionSettings.promptProtection) return;
  if (!text.trim() || isTemporarilyApproved(text)) return;

  event.preventDefault();
  event.stopPropagation();
  event.stopImmediatePropagation();

  checkPromptAndDecide({
    text,
    submit: () => {
      approveOnce(text);
      const button = findGeminiSendButton();
      if (button) setTimeout(() => button.click(), 80);
    }
  });
}, true);

document.addEventListener("change", (event) => {
  const input = event.target;
  if (!(input instanceof HTMLInputElement) || input.type !== "file") return;
  if (!extensionSettings.attachmentScanning) return;
  if (!input.files || input.files.length === 0) return;

  const signature = fileListSignature(input.files);
  if (approvedFileInputs.get(input) === signature) {
    approvedFileInputs.delete(input);
    return;
  }

  event.preventDefault();
  event.stopPropagation();
  event.stopImmediatePropagation();

  scanFilesBeforeUpload(input, signature);
}, true);

document.addEventListener("drop", (event) => {
  const files = event.dataTransfer?.files;
  if (!extensionSettings.attachmentScanning || !files || files.length === 0) return;

  event.preventDefault();
  event.stopPropagation();
  event.stopImmediatePropagation();

  showPanel({
    title: "Use upload picker",
    message: "Sentinell.AI scans attachments before upload. Use Gemini's file picker so the firewall can approve the file.",
    action: "ERROR",
    kind: "Attachment firewall"
  });
}, true);

async function checkPromptAndDecide({ text, submit }) {
  if (checking) return;
  checking = true;

  try {
    const response = await sendRuntimeMessage({
      type: "CHECK_PROMPT",
      payload: { text, source: SOURCE }
    });

    if (!response?.ok) {
      showPanel({
        title: "Sentinell.AI login required",
        message: response?.error || "Firewall check failed.",
        action: "ERROR"
      });
      return;
    }

    const result = response.result;

    if (result.action === "BLOCK") {
      showPanel({
        title: "Prompt blocked",
        message: `${result.risk_level} risk. ${firstReason(result)}`,
        action: "BLOCK",
        processedPrompt: result.processed_prompt,
        kind: "Prompt firewall"
      });
      return;
    }

    if (result.action === "TOKENIZE" && result.processed_prompt && result.processed_prompt !== text) {
      showPanel({
        title: "Sensitive data masked",
        message: `${result.risk_level} risk. Replace the prompt with the masked version, then send manually.`,
        action: "TOKENIZE",
        processedPrompt: result.processed_prompt,
        kind: "PII masking",
        copyLabel: "Copy masked prompt",
        onReplace: () => replaceGeminiPrompt(result.processed_prompt)
      });
      return;
    }

    submit();
  } finally {
    checking = false;
  }
}

async function scanFilesBeforeUpload(input, signature) {
  if (fileScanInFlight) return;
  fileScanInFlight = true;

  try {
    const files = Array.from(input.files || []);
    showPanel({
      title: "Scanning attachment",
      message: `Checking ${files.length} file${files.length === 1 ? "" : "s"} before upload.`,
      action: "ALLOW",
      kind: "Attachment firewall"
    });

    for (const file of files) {
      const scan = await checkFile(file);
      if (!scan.ok) {
        input.value = "";
        showPanel({
          title: "Attachment blocked",
          message: scan.error || "The file could not be scanned, so upload was stopped.",
          action: "BLOCK",
          processedPrompt: scan.result?.processed_text || "",
          kind: "Attachment firewall",
          copyLabel: "Copy safe text"
        });
        return;
      }

      const result = scan.result;
      if (result.action !== "ALLOW") {
        input.value = "";
        showPanel({
          title: "Attachment blocked",
          message: `${result.risk_level} risk in ${file.name}. ${firstReason(result)}`,
          action: "BLOCK",
          processedPrompt: result.processed_text,
          kind: "Attachment firewall",
          copyLabel: "Copy redacted text"
        });
        return;
      }
    }

    approvedFileInputs.set(input, signature);
    input.dispatchEvent(new Event("change", { bubbles: true }));
    showPanel({
      title: "Attachment approved",
      message: "File scan passed. Gemini can upload the attachment now.",
      action: "ALLOW",
      kind: "Attachment firewall"
    });
  } finally {
    fileScanInFlight = false;
  }
}

async function checkFile(file) {
  const dataUrl = await readFileAsDataUrl(file);
  return sendRuntimeMessage({
    type: "CHECK_FILE",
    payload: {
      source: `${SOURCE}_attachment`,
      file: {
        name: file.name,
        type: file.type,
        size: file.size,
        lastModified: file.lastModified,
        dataUrl
      }
    }
  });
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error || new Error("Could not read file."));
    reader.readAsDataURL(file);
  });
}

function fileListSignature(files) {
  return Array.from(files)
    .map((file) => `${file.name}:${file.size}:${file.lastModified}`)
    .join("|");
}

function findButtonFromEvent(event) {
  return eventPath(event).find((node) => {
    return node instanceof HTMLElement &&
      (node.tagName === "BUTTON" || node.getAttribute("role") === "button");
  }) || null;
}

function eventPath(event) {
  return typeof event.composedPath === "function" ? event.composedPath() : [event.target];
}

function isGeminiSendButton(button) {
  if (button.disabled || button.getAttribute("aria-disabled") === "true") return false;

  const label = getButtonLabel(button);
  if (/stop|pause|cancel|voice|mic|microphone|attach|upload|image|photo|add|menu|settings/.test(label)) {
    return false;
  }

  if (/send|submit/.test(label)) return true;

  const iconText = Array.from(button.querySelectorAll("mat-icon, [data-mat-icon-name], svg title"))
    .map((node) => node.getAttribute("data-mat-icon-name") || node.textContent || "")
    .join(" ")
    .trim()
    .toLowerCase();

  return /\bsend\b|arrow_upward|send_message/.test(iconText);
}

function getButtonLabel(button) {
  return [
    button.getAttribute("aria-label"),
    button.getAttribute("title"),
    button.getAttribute("data-testid"),
    button.getAttribute("data-test-id"),
    button.id,
    button.textContent
  ].filter(Boolean).join(" ").toLowerCase();
}

function findGeminiEditor() {
  const active = document.activeElement;
  const activeEditor = active?.closest?.("[contenteditable='true'], textarea, rich-textarea");
  if (activeEditor && isGeminiEditor(activeEditor)) return normalizeEditor(activeEditor);

  const selectors = [
    "rich-textarea [contenteditable='true']",
    "rich-textarea div[role='textbox']",
    "div[contenteditable='true'][role='textbox']",
    "div[aria-label*='Enter a prompt']",
    "div[aria-label*='Ask Gemini']",
    "textarea",
    "[contenteditable='true']"
  ];

  for (const selector of selectors) {
    const editor = document.querySelector(selector);
    if (editor && isGeminiEditor(editor)) return normalizeEditor(editor);
  }

  return null;
}

function normalizeEditor(element) {
  if (element?.matches?.("rich-textarea")) {
    return element.querySelector("[contenteditable='true'], div[role='textbox'], textarea") || element;
  }
  return element;
}

function isGeminiEditor(element) {
  return Boolean(element) && (
    element.matches?.("textarea") ||
    element.matches?.("[contenteditable='true']") ||
    element.matches?.("rich-textarea") ||
    element.getAttribute?.("role") === "textbox"
  );
}

function getEditorText(editor) {
  if (!editor) return "";
  if ("value" in editor) return editor.value;

  const text = editor.innerText || editor.textContent || "";
  return text.replace(/\u00a0/g, " ").trim();
}

function replaceGeminiPrompt(text) {
  const editor = findGeminiEditor();
  if (!editor) return false;

  editor.focus();

  if ("value" in editor) {
    editor.value = text;
    editor.dispatchEvent(new Event("input", { bubbles: true }));
    editor.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  const selection = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(editor);
  selection.removeAllRanges();
  selection.addRange(range);

  document.execCommand("insertText", false, text);
  editor.dispatchEvent(new InputEvent("input", {
    bubbles: true,
    inputType: "insertText",
    data: text
  }));
  return true;
}

function findGeminiSendButton() {
  return Array.from(document.querySelectorAll("button, [role='button']"))
    .find(isGeminiSendButton) || null;
}

function isTemporarilyApproved(text) {
  return text === approvedText && Date.now() < approvedUntil;
}

function approveOnce(text) {
  approvedText = text;
  approvedUntil = Date.now() + 2500;
}

async function sendRuntimeMessage(message) {
  try {
    return await chrome.runtime.sendMessage(message);
  } catch (error) {
    return {
      ok: false,
      error: "Extension was reloaded. Refresh the Gemini tab and try again."
    };
  }
}

async function loadExtensionSettings() {
  const config = await sendRuntimeMessage({ type: "GET_CONFIG" });
  if (config?.settings) {
    extensionSettings = { ...extensionSettings, ...config.settings };
  }
  syncResponseMonitoring();
}

function startResponseMonitoring() {
  if (!document.documentElement) return;
  if (responseObserver) return;

  responseObserver = new MutationObserver(scheduleResponseScan);
  responseObserver.observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true
  });
  scheduleResponseScan();
}

function stopResponseMonitoring() {
  if (responseObserver) {
    responseObserver.disconnect();
    responseObserver = null;
  }
  window.clearTimeout(responseScanTimer);
}

function syncResponseMonitoring() {
  if (extensionSettings.responseMonitoring) startResponseMonitoring();
  else stopResponseMonitoring();
}

function scheduleResponseScan() {
  if (!extensionSettings.responseMonitoring) return;
  window.clearTimeout(responseScanTimer);
  responseScanTimer = window.setTimeout(scanGeminiResponses, 1200);
}

function scanGeminiResponses() {
  if (!extensionSettings.responseMonitoring) return;
  for (const element of findGeminiResponseCandidates()) {
    const text = getResponseText(element);
    if (text.length < 50 || text.length > 6000) continue;

    const state = responseState.get(element) || {};
    if (state.status === "checking" || state.text === text) continue;

    responseState.set(element, { status: "checking", text });
    checkResponseAndProtect(element, text);
  }
}

function findGeminiResponseCandidates() {
  const selectors = [
    "model-response",
    "message-content",
    "[data-test-id*='response' i]",
    "[data-testid*='response' i]",
    ".model-response-text",
    ".markdown"
  ];

  const raw = Array.from(document.querySelectorAll(selectors.join(",")))
    .filter((element) => {
      return element instanceof HTMLElement &&
        !element.closest(".sentinell-panel") &&
        !element.closest("[contenteditable='true'], textarea, rich-textarea") &&
        !looksLikeUserPrompt(element) &&
        isElementVisible(element);
    });

  return raw.filter((element) => {
    return !raw.some((other) => other !== element && other.contains(element));
  });
}

function looksLikeUserPrompt(element) {
  const label = [
    element.getAttribute("aria-label"),
    element.getAttribute("data-test-id"),
    element.getAttribute("data-testid"),
    element.className,
    element.id
  ].filter(Boolean).join(" ").toLowerCase();

  return /user|query|prompt-input|human/.test(label);
}

function isElementVisible(element) {
  const rect = element.getBoundingClientRect();
  return rect.width > 40 && rect.height > 20;
}

function getResponseText(element) {
  return String(element.innerText || element.textContent || "")
    .replace(/\u00a0/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

async function checkResponseAndProtect(element, text) {
  const response = await sendRuntimeMessage({
    type: "CHECK_RESPONSE",
    payload: { text, source: `${SOURCE}_response` }
  });

  if (!response?.ok) {
    responseState.set(element, { status: "error", text });
    return;
  }

  const result = response.result;
  responseState.set(element, { status: result.action, text });

  if (result.action === "BLOCK") {
    element.classList.add("sentinell-response-hidden");
    showPanel({
      title: "AI response blocked",
      message: `${result.risk_level} risk. ${firstReason(result)}`,
      action: "BLOCK",
      processedPrompt: result.processed_response,
      kind: "Response monitor",
      copyLabel: "Copy safe notice"
    });
    return;
  }

  if (result.action === "REDACT") {
    showPanel({
      title: "AI response contains sensitive data",
      message: `${result.risk_level} risk. Use the redacted version below.`,
      action: "TOKENIZE",
      processedPrompt: result.processed_response,
      kind: "Response monitor",
      copyLabel: "Copy redacted response"
    });
  }
}

function firstReason(result) {
  if (result.reasons && result.reasons.length) return result.reasons[0];
  const semantic = result.agent_trace?.semantic_security_agent;
  return semantic?.reason || "Policy blocked this prompt.";
}

function showPanel({ title, message, action, processedPrompt, onReplace, kind, copyLabel }) {
  document.querySelector(".sentinell-panel")?.remove();

  const panel = document.createElement("section");
  panel.className = `sentinell-panel sentinell-${String(action || "").toLowerCase()}`;
  const showPreview = extensionSettings.showPanelPreview && processedPrompt;
  const icon = action === "BLOCK" ? "!" : action === "TOKENIZE" ? "M" : "OK";
  panel.innerHTML = `
    <header>
      <div class="sentinell-icon">${escapeHtml(icon)}</div>
      <div class="sentinell-title">
        <strong>${escapeHtml(title)}</strong>
        <span>${escapeHtml(kind || "Sentinell.AI")}</span>
      </div>
    </header>
    <main>
      <p>${escapeHtml(message)}</p>
      ${showPreview ? `<textarea readonly>${escapeHtml(processedPrompt)}</textarea>` : ""}
    </main>
    <div class="sentinell-actions">
      ${processedPrompt ? `<button class="sentinell-primary" data-action="copy">${escapeHtml(copyLabel || "Copy safe text")}</button>` : ""}
      ${onReplace ? `<button class="sentinell-primary" data-action="replace">Replace prompt</button>` : ""}
      <button class="sentinell-secondary" data-action="close">Close</button>
    </div>
  `;
  document.body.appendChild(panel);

  panel.addEventListener("click", async (event) => {
    const actionName = event.target?.dataset?.action;
    if (actionName === "copy" && processedPrompt) {
      await navigator.clipboard.writeText(processedPrompt);
      event.target.textContent = "Copied";
    }
    if (actionName === "replace" && onReplace) {
      const replaced = onReplace();
      event.target.textContent = replaced ? "Replaced" : "Could not replace";
    }
    if (actionName === "close") panel.remove();
  });
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
