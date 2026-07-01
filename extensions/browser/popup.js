document.getElementById("status").addEventListener("click", () => {
  const result = document.getElementById("result");
  result.textContent = "Checking...";
  chrome.runtime.sendMessage({ type: "sentinel-vault-status" }, (response) => {
    result.textContent = response?.ok ? "Console reachable." : `Console unavailable: ${response?.error || response?.status || "unknown"}`;
  });
});
