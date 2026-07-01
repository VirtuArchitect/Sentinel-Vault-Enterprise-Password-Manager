const SENTINEL_BASE_URL = "http://127.0.0.1:5173";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "sentinel-vault-status") return false;

  fetch(`${SENTINEL_BASE_URL}/healthz`)
    .then((response) => sendResponse({ ok: response.ok, status: response.status }))
    .catch((error) => sendResponse({ ok: false, error: error.message }));

  return true;
});
