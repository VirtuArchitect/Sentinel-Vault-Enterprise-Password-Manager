(() => {
  const sentinelSetValue = (element, value) => {
    const descriptor = Object.getOwnPropertyDescriptor(element.constructor.prototype, "value");
    descriptor?.set?.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const visible = (element) => {
    const style = window.getComputedStyle(element);
    return style.visibility !== "hidden" && style.display !== "none" && element.getClientRects().length > 0;
  };

  const findUsernameField = (passwordField) => {
    const fields = [...document.querySelectorAll("input")]
      .filter((field) => visible(field) && !field.disabled && !field.readOnly);
    const passwordIndex = fields.indexOf(passwordField);
    const candidates = fields.slice(0, Math.max(0, passwordIndex)).reverse();
    return candidates.find((field) => ["email", "text", "tel"].includes(field.type) || /user|email|login|account/i.test(`${field.name} ${field.id} ${field.autocomplete}`));
  };

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "sentinel-vault-autofill") return false;

    const passwordField = [...document.querySelectorAll("input[type='password']")]
      .find((field) => visible(field) && !field.disabled && !field.readOnly);
    if (!passwordField) {
      sendResponse({ fieldsFilled: 0, error: "No usable password field found." });
      return true;
    }

    const usernameField = findUsernameField(passwordField);
    if (usernameField) sentinelSetValue(usernameField, message.username || "");
    sentinelSetValue(passwordField, message.password || "");
    passwordField.focus();
    sendResponse({ fieldsFilled: usernameField ? 2 : 1 });
    return true;
  });
})();
