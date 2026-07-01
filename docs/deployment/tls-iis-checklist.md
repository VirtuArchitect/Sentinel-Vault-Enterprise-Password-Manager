# TLS and IIS Deployment Checklist

Use this checklist when exposing Sentinel Vault through Windows Web Services/IIS.

## Certificate

- Bind IIS to HTTPS with a certificate issued for the console hostname.
- Prefer an enterprise PKI or public CA certificate with automatic renewal.
- Store private keys in the local machine certificate store with restricted ACLs.
- Remove or redirect HTTP bindings after validation.

## IIS Front End

- Install IIS Web Server, URL Rewrite, and Application Request Routing.
- Enable ARR proxy support before installing Sentinel Vault with `-ConfigureIis`.
- Keep the Node API bound to `127.0.0.1` unless a reverse proxy is not used.
- Confirm `/api/*` rewrites to the local Node API and SPA routes fall back to `index.html`.

## Security Headers

- Keep Sentinel Vault production mode enabled so HSTS and production CSP are emitted.
- Confirm `Strict-Transport-Security` is present only after HTTPS is working.
- Review CSP before enabling external identity, SIEM, or telemetry endpoints.
- Do not add wildcard CORS origins for production deployments.

## Validation

```powershell
.\healthcheck.ps1 -Url "https://sentinel.example.local/healthz"
Invoke-WebRequest "https://sentinel.example.local" -UseBasicParsing
```

Confirm:

- TLS certificate chain is trusted.
- HTTP requests redirect to HTTPS or are disabled.
- Login and `/api/console` work through IIS.
- Scheduled task remains healthy after reboot.
