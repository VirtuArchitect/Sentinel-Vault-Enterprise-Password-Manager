# Browser and Desktop Extension Roadmap

## Browser Autofill

- Use Manifest V3 with a background service worker and least-privilege host permissions.
- Authenticate to the local Sentinel Vault console with short-lived session tokens.
- Match credentials by origin, URL, and vault policy rather than page title.
- Require explicit user confirmation before filling high-risk or approval-required entries.
- Never expose plaintext secrets to extension storage.
- The browser extension now stores the console token in `chrome.storage.session`, fetches URL-matched entries from the local console, reveals only after an explicit Fill action, and injects plaintext only into the active tab.
- Enterprise rollout evidence now captures deployment-specific Chrome and Edge extension IDs, allowed runtime hosts, blocked permissions, staged rollout rings, store review status, rollback testing, and approvals.
- Browser enterprise policies can be rendered from completed rollout evidence with `pnpm render:browser-policy`.

## Clipboard Companion

- Windows companion owns clipboard auto-clear timers and records local clear events.
- Clipboard writes should be opt-in from a reveal or fill action.
- Clear only values written by Sentinel Vault, using a marker hash to avoid destroying unrelated clipboard content.
- The PowerShell companion prototype writes Sentinel-owned clipboard markers and clears only matching values after the TTL expires.
- Tray mode provides a notification-area menu for opening the console and clearing Sentinel-owned clipboard values.

## Offline Read-Only Cache

- Cache metadata and encrypted secret payloads separately.
- Unlock offline cache with a local key protected by Windows DPAPI or future enterprise KMS/HSM.
- Enforce read-only mode while offline and queue no write operations.
- Expire offline cache according to tenant policy.
- The API now exports a per-user AES-GCM encrypted read-only cache artifact and verifies cache signatures without exposing plaintext secret material.
- The Windows companion can DPAPI-protect exported cache artifacts for the current Windows user and inspect the manifest without exposing secret payloads.
- The companion includes a read-only native metadata browser for the DPAPI-protected offline cache index.
- The companion can install an hourly current-user scheduled task to remove expired offline cache artifacts.
- The API supports online rehydration for signed cache entries through live server authorization and audited reveal.

## Native Autotype

- Prefer a broker process with explicit window targeting and user confirmation.
- Do not inject into elevated windows from a non-elevated process.
- Log target application metadata without logging typed secrets.
- Require separate security review before implementing credential provider or UI automation hooks.
- The PowerShell companion now includes a guarded autotype proof of concept that requires a target window title and `-IUnderstandAutotypeRisk` before sending username, tab, and password keystrokes.
- Native companion and credential-provider releases must provide signed-artifact evidence, security-control results, clean install/uninstall results, abuse-case test evidence, rollback testing, and approvals through `pnpm validate:native-companion`.
