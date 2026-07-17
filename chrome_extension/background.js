const DEFAULT_BACKEND = "http://127.0.0.1:8000";
const DEFAULT_SETTINGS = {
  promptProtection: true,
  responseMonitoring: true,
  attachmentScanning: true,
  showPanelPreview: true
};

async function getConfig() {
  const data = await chrome.storage.local.get(["backendUrl", "token", "user", "settings"]);
  return {
    backendUrl: data.backendUrl || DEFAULT_BACKEND,
    token: data.token || "",
    user: data.user || null,
    settings: { ...DEFAULT_SETTINGS, ...(data.settings || {}) }
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "LOGIN") {
    handleLogin(message.payload).then(sendResponse);
    return true;
  }

  if (message.type === "CHECK_PROMPT") {
    handleCheckPrompt(message.payload).then(sendResponse);
    return true;
  }

  if (message.type === "CHECK_RESPONSE") {
    handleCheckResponse(message.payload).then(sendResponse);
    return true;
  }

  if (message.type === "CHECK_FILE") {
    handleCheckFile(message.payload).then(sendResponse);
    return true;
  }

  if (message.type === "GET_CONFIG") {
    getConfig().then(sendResponse);
    return true;
  }

  if (message.type === "LOGOUT") {
    chrome.storage.local.remove(["token", "user"]).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message.type === "UPDATE_SETTINGS") {
    updateSettings(message.payload).then(sendResponse);
    return true;
  }
});

async function updateSettings(payload) {
  const { settings } = await getConfig();
  const next = { ...settings };
  for (const key of Object.keys(DEFAULT_SETTINGS)) {
    if (Object.prototype.hasOwnProperty.call(payload || {}, key)) {
      next[key] = Boolean(payload[key]);
    }
  }
  await chrome.storage.local.set({ settings: next });
  return { ok: true, settings: next };
}

async function handleLogin(payload) {
  const backendUrl = (payload.backendUrl || DEFAULT_BACKEND).replace(/\/$/, "");
  try {
    const response = await fetch(`${backendUrl}/extension/login/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: payload.email, password: payload.password })
    });
    const data = await response.json();
    if (!response.ok) {
      return { ok: false, error: data.error || "Login failed." };
    }
    await chrome.storage.local.set({ backendUrl, token: data.token, user: data.user });
    return { ok: true, user: data.user };
  } catch (error) {
    return { ok: false, error: `Could not reach backend: ${error.message}` };
  }
}

async function handleCheckPrompt(payload) {
  const { backendUrl, token } = await getConfig();
  if (!token) {
    return { ok: false, error: "Not logged in to Sentinell.AI extension." };
  }

  try {
    const response = await fetch(`${backendUrl}/firewall/check`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        text: payload.text,
        source: payload.source || "browser_extension"
      })
    });
    const data = await response.json();
    if (!response.ok) {
      return { ok: false, error: data.error || "Firewall check failed." };
    }
    return { ok: true, result: data };
  } catch (error) {
    return { ok: false, error: `Could not reach firewall: ${error.message}` };
  }
}

async function handleCheckResponse(payload) {
  const { backendUrl, token } = await getConfig();
  if (!token) {
    return { ok: false, error: "Not logged in to Sentinell.AI extension." };
  }

  try {
    const response = await fetch(`${backendUrl}/firewall/check-response`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        text: payload.text,
        source: payload.source || "browser_extension"
      })
    });
    const data = await response.json();
    if (!response.ok) {
      return { ok: false, error: data.error || "Response firewall check failed." };
    }
    return { ok: true, result: data };
  } catch (error) {
    return { ok: false, error: `Could not reach response firewall: ${error.message}` };
  }
}

async function handleCheckFile(payload) {
  const { backendUrl, token } = await getConfig();
  if (!token) {
    return { ok: false, error: "Not logged in to Sentinell.AI extension." };
  }

  try {
    const file = payload.file || {};
    const dataResponse = await fetch(file.dataUrl);
    const blob = await dataResponse.blob();
    const formData = new FormData();
    formData.append("document", blob, file.name || "attachment");
    formData.append("source", payload.source || "browser_extension_file");

    const response = await fetch(`${backendUrl}/firewall/check-file`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`
      },
      body: formData
    });
    const data = await response.json();
    if (!response.ok) {
      return { ok: false, error: data.error || "File firewall check failed.", result: data };
    }
    return { ok: true, result: data };
  } catch (error) {
    return { ok: false, error: `Could not scan file: ${error.message}` };
  }
}
