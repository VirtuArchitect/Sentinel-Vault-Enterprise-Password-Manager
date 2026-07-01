import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const runStatuses = new Set(["not-run", "passed", "failed", "not-applicable"]);
const outputPath = args.get("--out") || "artifacts/windows/tls-iis-evidence.json";
const reportPath = args.get("--report") || "artifacts/windows/tls-iis-review.json";
const status = args.get("--status") || "planned";

assert.ok(allowedStatuses.has(status), "status must be planned, pilot, production, or retired");

const toIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const readText = (filePath) => readFileSync(filePath, "utf8").replace(/^\uFEFF/, "");
const normalizeStatus = (value, fallback = "planned") => {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (["passed", "pass", "ok", "true", "valid", "enabled"].includes(normalized)) {
    return "passed";
  }
  if (["failed", "fail", "false", "invalid", "missing", "disabled"].includes(normalized)) {
    return "failed";
  }
  if (["not-applicable", "not_applicable", "n/a", "skipped"].includes(normalized)) {
    return "not-applicable";
  }
  return fallback;
};
const argStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(checkStatuses.has(value), `${name} must be planned, passed, failed, or not-applicable`);
  return value;
};
const argRunStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(runStatuses.has(value), `${name} must be not-run, passed, failed, or not-applicable`);
  return value;
};
const asBool = (value, fallback) => {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  return fallback;
};

const report = existsSync(reportPath) ? readJson(reportPath) : null;
const iis = report?.iis || {};
const certificate = report?.certificate || {};
const headers = report?.headers || {};
const healthChecks = report?.healthChecks || {};
const samplePath = args.get("--samples");
const sampleText = samplePath && existsSync(samplePath) && !statSync(samplePath).isDirectory() ? readText(samplePath) : "";
const combinedText = `${report ? JSON.stringify(report) : ""}\n${sampleText}`;
const privateKeysFound = /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i.test(combinedText);
const certificatePasswordsFound = /pfxPassword\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{6,}|certificatePassword\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{6,}/i.test(combinedText);
const runtimeSecretsFound = /VAULT_ROOT_KEY\s*[:=]|SESSION_SECRET\s*[:=]|secret(Value)?\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}/i.test(combinedText);

const evidence = {
  format: "sentinel-tls-iis-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  hostname: args.get("--hostname") || report?.hostname || "replace-with-hostname",
  reviewedAt: args.get("--reviewed-at") || report?.reviewedAt || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso()),
  iis: {
    siteName: args.get("--site-name") || iis.siteName || "Sentinel Vault",
    httpsBinding: argStatus("--https-binding", normalizeStatus(iis.httpsBinding)),
    httpRedirect: argStatus("--http-redirect", normalizeStatus(iis.httpRedirect)),
    arrProxyEnabled: argStatus("--arr-proxy-enabled", normalizeStatus(iis.arrProxyEnabled)),
    urlRewriteEnabled: argStatus("--url-rewrite-enabled", normalizeStatus(iis.urlRewriteEnabled)),
    apiProxyValidated: argStatus("--api-proxy-validated", normalizeStatus(iis.apiProxyValidated)),
    staticAssetCachingReviewed: argStatus("--static-asset-caching-reviewed", normalizeStatus(iis.staticAssetCachingReviewed))
  },
  certificate: {
    issuer: args.get("--issuer") || certificate.issuer || "replace-with-issuer",
    subject: args.get("--subject") || certificate.subject || "replace-with-subject",
    thumbprint: args.get("--thumbprint") || certificate.thumbprint || "replace-with-thumbprint",
    notBefore: args.get("--not-before") || certificate.notBefore || "YYYY-MM-DD",
    notAfter: args.get("--not-after") || certificate.notAfter || "YYYY-MM-DD",
    autoRenewal: argStatus("--auto-renewal", normalizeStatus(certificate.autoRenewal)),
    privateKeyAclRestricted: argStatus("--private-key-acl-restricted", normalizeStatus(certificate.privateKeyAclRestricted)),
    chainTrusted: argStatus("--chain-trusted", normalizeStatus(certificate.chainTrusted)),
    revocationCheck: argStatus("--revocation-check", normalizeStatus(certificate.revocationCheck))
  },
  headers: {
    hsts: argStatus("--hsts", normalizeStatus(headers.hsts)),
    contentSecurityPolicy: argStatus("--content-security-policy", normalizeStatus(headers.contentSecurityPolicy)),
    xContentTypeOptions: argStatus("--x-content-type-options", normalizeStatus(headers.xContentTypeOptions)),
    referrerPolicy: argStatus("--referrer-policy", normalizeStatus(headers.referrerPolicy)),
    frameAncestors: argStatus("--frame-ancestors", normalizeStatus(headers.frameAncestors))
  },
  healthChecks: {
    httpsHealthz: argRunStatus("--https-healthz", normalizeStatus(healthChecks.httpsHealthz, "not-run")),
    loginThroughIis: argRunStatus("--login-through-iis", normalizeStatus(healthChecks.loginThroughIis, "not-run")),
    apiConsoleThroughIis: argRunStatus("--api-console-through-iis", normalizeStatus(healthChecks.apiConsoleThroughIis, "not-run")),
    httpToHttpsRedirect: argRunStatus("--http-to-https-redirect", normalizeStatus(healthChecks.httpToHttpsRedirect, "not-run")),
    tlsProtocolReview: argRunStatus("--tls-protocol-review", normalizeStatus(healthChecks.tlsProtocolReview, "not-run"))
  },
  redaction: {
    privateKeysFound: asBool(args.get("--private-keys-found"), privateKeysFound),
    certificatePasswordsFound: asBool(args.get("--certificate-passwords-found"), certificatePasswordsFound),
    runtimeSecretsFound: asBool(args.get("--runtime-secrets-found"), runtimeSecretsFound)
  },
  approvals: {
    windowsOwner: args.get("--windows-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`TLS/IIS evidence written: ${outputPath}`);
