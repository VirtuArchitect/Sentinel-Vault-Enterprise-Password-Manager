const loginPanel = document.getElementById("login-panel");
const matchPanel = document.getElementById("match-panel");
const result = document.getElementById("result");
const matches = document.getElementById("matches");
const origin = document.getElementById("origin");

const activeTab = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
};

const setStatus = (message) => {
  result.textContent = message;
};

const renderMatches = async () => {
  const tab = await activeTab();
  origin.textContent = tab?.url ? new URL(tab.url).origin : "Current site";
  const response = await chrome.runtime.sendMessage({ type: "sentinel-vault-matches", url: tab?.url || "" });
  if (!response?.ok) {
    loginPanel.hidden = false;
    matchPanel.hidden = true;
    setStatus(response?.error || "Unlock the extension to show matching entries.");
    return;
  }

  loginPanel.hidden = true;
  matchPanel.hidden = false;
  matches.textContent = "";
  if (!response.matches.length) {
    setStatus("No matching entries for this site.");
    return;
  }

  setStatus(`${response.matches.length} matching entr${response.matches.length === 1 ? "y" : "ies"} found.`);
  for (const match of response.matches) {
    const item = document.createElement("div");
    item.className = "match";
    const title = document.createElement("strong");
    title.textContent = match.name;
    const meta = document.createElement("span");
    meta.textContent = `${match.username} / ${match.risk}${match.approvalsRequired ? " / approval required" : ""}`;
    const button = document.createElement("button");
    button.textContent = match.approvalsRequired || match.risk === "high" ? "Confirm Fill" : "Fill";
    button.addEventListener("click", async () => {
      setStatus("Requesting audited reveal...");
      const fill = await chrome.runtime.sendMessage({ type: "sentinel-vault-fill", secretId: match.id, username: match.username, tabId: tab.id });
      setStatus(fill?.ok ? "Filled selected page fields." : fill?.error || "Fill failed.");
    });
    item.append(title, meta, button);
    matches.append(item);
  }
};

document.getElementById("login").addEventListener("click", async () => {
  setStatus("Unlocking...");
  const response = await chrome.runtime.sendMessage({
    type: "sentinel-vault-login",
    email: document.getElementById("email").value,
    password: document.getElementById("password").value
  });
  document.getElementById("password").value = "";
  if (!response?.ok) {
    setStatus(response?.error || "Unlock failed.");
    return;
  }
  await renderMatches();
});

document.getElementById("lock").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "sentinel-vault-lock" });
  loginPanel.hidden = false;
  matchPanel.hidden = true;
  matches.textContent = "";
  setStatus("Extension locked.");
});

renderMatches().catch((error) => setStatus(error.message));
