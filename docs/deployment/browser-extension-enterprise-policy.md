# Browser Extension Enterprise Policy

Sentinel Vault Autofill is packaged from `extensions/browser` with:

```powershell
pnpm package:extension
pnpm validate:extension-package -- --out ".\artifacts\browser\browser-extension-package-validation.json"
```

The package is written to:

```text
artifacts/browser/sentinel-vault-autofill.zip
```

## Policy Templates

- `deployments/browser/chrome-policy-template.json`
- `deployments/browser/edge-policy-template.json`

Replace `replace-with-extension-id` with the enterprise extension ID assigned by your private Chrome Web Store, Microsoft Edge Add-ons, or managed extension deployment channel.

## Deployment Requirements

- Force install only from an enterprise-controlled extension ID.
- Allow runtime hosts only for the local Sentinel Vault console.
- Block unrelated permissions such as history, bookmarks, and downloads.
- Publish updates through the enterprise browser management channel.
- Validate the extension package hash before release.
- Attach `artifacts/browser/browser-extension-package-validation.json` to store or private-channel review evidence.
- Confirm the local console is distributed with TLS or localhost-only access.

Record rollout evidence with:

```powershell
pnpm release:browser-rollout -- --artifact ".\artifacts\browser\sentinel-vault-autofill.zip" --out ".\artifacts\browser\browser-extension-rollout-evidence.json"
pnpm validate:browser-rollout docs/templates/browser-extension-rollout-evidence.json
```

For pilot or production rollout evidence, replace the placeholder extension IDs with the private Chrome Web Store or Edge Add-ons IDs, confirm the generated package SHA-256, and mark privacy, screenshot redaction, and rollback testing as complete.

Render Chrome and Edge enterprise policies from a completed rollout evidence file:

```powershell
pnpm render:browser-policy -- --evidence ".\evidence\browser-extension-production.json" --out-dir ".\artifacts\browser\policy"
```

The renderer refuses placeholder extension IDs and writes deployable `chrome-policy.json` and `edge-policy.json` files for enabled browsers.

## Store Review Checklist

- Manifest V3 only.
- No wildcard web host permissions.
- `activeTab` is used for explicit user-selected fill operations.
- Session token is stored in `chrome.storage.session`, not persistent extension storage.
- Plaintext secrets are requested only after a Fill action and are not stored.
- High-risk or approval-required entries display `Confirm Fill`.
- Screenshots do not include real credentials or internal host names.
- Privacy statement explains local console communication and no third-party telemetry.
