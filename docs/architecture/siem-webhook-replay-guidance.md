# SIEM Webhook Replay Guidance

Sentinel Vault signs outbound SIEM webhook deliveries with an HMAC envelope so receivers can reject spoofed or replayed events.

## Delivery Headers

Each webhook request includes:

- `X-Sentinel-Delivery-Id`: unique ID for this delivery attempt.
- `X-Sentinel-Timestamp`: UTC ISO timestamp for the delivery attempt.
- `X-Sentinel-Nonce`: random nonce for this delivery attempt.
- `X-Sentinel-Replay-Window`: accepted receiver window in seconds.
- `X-Sentinel-Signature`: `sha256=<hex hmac>` when SIEM signing is configured.

The JSON body also includes a `delivery` object with the delivery ID, timestamp, and replay window.

## Receiver Verification

Receivers should:

1. Require HTTPS and reject unsigned requests when a signing secret is configured.
2. Parse `X-Sentinel-Timestamp` and reject requests outside the advertised replay window. Sentinel Vault currently advertises 300 seconds.
3. Recompute the signature with `HMAC-SHA256(secret, timestamp + "." + nonce + "." + rawBody)`.
4. Compare the computed signature with `X-Sentinel-Signature` using constant-time comparison.
5. Store `X-Sentinel-Delivery-Id` or the tuple of timestamp and nonce for at least the replay window.
6. Reject duplicate delivery IDs or nonces seen inside the replay window.
7. Log rejected deliveries without storing secret material.

## Certification Boundary

Production connector certification should verify SIEM-specific schemas, retry behavior, dead-letter handling, TLS policy, signing-secret rotation, clock-skew tolerance, and receiver-side replay storage.
