const SENTINEL_BASE_URL = "http://127.0.0.1:5173";

const api = async (path, options = {}, token = "") => {
  const response = await fetch(`${SENTINEL_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {})
    }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "Sentinel Vault request failed");
  return body;
};

const sessionToken = async () => {
  const data = await chrome.storage.session.get("sentinelToken");
  return data.sentinelToken || "";
};

const sameOrigin = (secretUrl, pageUrl) => {
  try {
    const secret = new URL(secretUrl);
    const page = new URL(pageUrl);
    return secret.origin === page.origin || secret.hostname === page.hostname;
  } catch {
    return false;
  }
};

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "sentinel-vault-login") {
    api("/api/login", {
      method: "POST",
      body: JSON.stringify({ email: message.email, password: message.password })
    }).then((login) => chrome.storage.session.set({ sentinelToken: login.token }))
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "sentinel-vault-lock") {
    sessionToken()
      .then((token) => token ? api("/api/logout", { method: "POST" }, token).catch(() => undefined) : undefined)
      .then(() => chrome.storage.session.remove("sentinelToken"))
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "sentinel-vault-matches") {
    sessionToken()
      .then((token) => {
        if (!token) throw new Error("Extension is locked.");
        return api("/api/console", {}, token).then((consoleData) => ({ token, consoleData }));
      })
      .then(({ consoleData }) => {
        const matches = consoleData.secrets
          .filter((secret) => !secret.deletedAt && sameOrigin(secret.url, message.url))
          .slice(0, 8)
          .map((secret) => ({
            id: secret.id,
            name: secret.name,
            username: secret.username,
            url: secret.url,
            risk: secret.risk,
            approvalsRequired: Boolean(secret.approvalsRequired)
          }));
        sendResponse({ ok: true, matches });
      })
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "sentinel-vault-fill") {
    sessionToken()
      .then((token) => {
        if (!token) throw new Error("Extension is locked.");
        return api(`/api/secrets/${message.secretId}/reveal`, { method: "POST" }, token)
          .then((revealed) => ({ token, revealed }));
      })
      .then(({ revealed }) => chrome.scripting.executeScript({
        target: { tabId: message.tabId },
        files: ["content-script.js"]
      }).then(() => revealed))
      .then((revealed) => chrome.tabs.sendMessage(message.tabId, {
        type: "sentinel-vault-autofill",
        username: message.username,
        password: revealed.password
      }))
      .then((fillResult) => sendResponse({ ok: true, ...fillResult }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  return false;
});
