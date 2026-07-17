const form = document.getElementById("loginForm");
const statusCard = document.getElementById("statusCard");
const statusTitle = document.getElementById("statusTitle");
const statusEl = document.getElementById("status");
const signedIn = document.getElementById("signedIn");
const userEmail = document.getElementById("userEmail");
const userRole = document.getElementById("userRole");
const avatar = document.getElementById("avatar");
const logout = document.getElementById("logout");
const loginButton = document.getElementById("loginButton");

const settingInputs = [
  "promptProtection",
  "responseMonitoring",
  "attachmentScanning",
  "showPanelPreview"
].map((id) => document.getElementById(id));

chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (config) => {
  document.getElementById("backendUrl").value = config.backendUrl;
  renderSettings(config.settings || {});
  renderUser(config.user);
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  setStatus("Checking credentials", "Authenticating with Sentinell backend...", "");
  loginButton.disabled = true;
  chrome.runtime.sendMessage({
    type: "LOGIN",
    payload: {
      backendUrl: document.getElementById("backendUrl").value,
      email: document.getElementById("email").value,
      password: document.getElementById("password").value
    }
  }, (response) => {
    loginButton.disabled = false;
    if (!response?.ok) {
      setStatus("Login failed", response?.error || "Check credentials and backend URL.", "error");
      return;
    }
    renderUser(response.user);
  });
});

logout.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "LOGOUT" }, () => renderUser(null));
});

settingInputs.forEach((input) => {
  input.addEventListener("change", () => {
    const settings = Object.fromEntries(settingInputs.map((item) => [item.id, item.checked]));
    chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", payload: settings }, () => {
      setStatus("Settings saved", "Gemini tabs will use the updated protection settings.", "connected");
    });
  });
});

function renderSettings(settings) {
  const defaults = {
    promptProtection: true,
    responseMonitoring: true,
    attachmentScanning: true,
    showPanelPreview: true
  };
  const merged = { ...defaults, ...settings };
  settingInputs.forEach((input) => {
    input.checked = Boolean(merged[input.id]);
  });
}

function renderUser(user) {
  if (!user) {
    setStatus("Login required", "Sign in to enable prompt and response protection.", "error");
    form.hidden = false;
    signedIn.hidden = true;
    return;
  }
  setStatus("Connected", "Prompt firewall and response monitor are ready.", "connected");
  form.hidden = true;
  signedIn.hidden = false;
  userEmail.textContent = user.email || "";
  userRole.textContent = user.role || "";
  avatar.textContent = (user.email || "S").slice(0, 1).toUpperCase();
}

function setStatus(title, message, state) {
  statusTitle.textContent = title;
  statusEl.textContent = message;
  statusCard.classList.remove("connected", "error");
  if (state) statusCard.classList.add(state);
}
