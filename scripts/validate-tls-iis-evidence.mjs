import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/tls-iis-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const runStatuses = new Set(["not-run", "passed", "failed", "not-applicable"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;
const thumbprintPattern = /^[a-f0-9]{40,64}$/i;

assert.equal(evidence.format, "sentinel-tls-iis-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported TLS/IIS evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.hostname, "hostname is required");
assert.ok(evidence.reviewedAt, "reviewedAt is required");
assert.ok(evidence.iis?.siteName, "iis.siteName is required");

for (const name of ["httpsBinding", "httpRedirect", "arrProxyEnabled", "urlRewriteEnabled", "apiProxyValidated", "staticAssetCachingReviewed"]) {
  assert.ok(checkStatuses.has(evidence.iis?.[name]), `Unsupported IIS check result for ${name}`);
}

for (const name of ["issuer", "subject", "thumbprint", "notBefore", "notAfter"]) {
  assert.ok(evidence.certificate?.[name], `certificate.${name} is required`);
}
for (const name of ["autoRenewal", "privateKeyAclRestricted", "chainTrusted", "revocationCheck"]) {
  assert.ok(checkStatuses.has(evidence.certificate?.[name]), `Unsupported certificate check result for ${name}`);
}
for (const name of ["hsts", "contentSecurityPolicy", "xContentTypeOptions", "referrerPolicy", "frameAncestors"]) {
  assert.ok(checkStatuses.has(evidence.headers?.[name]), `Unsupported header check result for ${name}`);
}
for (const name of ["httpsHealthz", "loginThroughIis", "apiConsoleThroughIis", "httpToHttpsRedirect", "tlsProtocolReview"]) {
  assert.ok(runStatuses.has(evidence.healthChecks?.[name]), `Unsupported health check result for ${name}`);
}

assert.equal(typeof evidence.redaction?.privateKeysFound, "boolean", "redaction.privateKeysFound must be boolean");
assert.equal(typeof evidence.redaction?.certificatePasswordsFound, "boolean", "redaction.certificatePasswordsFound must be boolean");
assert.equal(typeof evidence.redaction?.runtimeSecretsFound, "boolean", "redaction.runtimeSecretsFound must be boolean");
assert.ok(evidence.approvals?.windowsOwner, "approvals.windowsOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed TLS/IIS evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.reviewedAt), "reviewedAt must be an ISO timestamp");
  assert.ok(thumbprintPattern.test(evidence.certificate.thumbprint), "certificate.thumbprint must be a certificate thumbprint");
  assert.ok(isoDate.test(evidence.certificate.notBefore), "certificate.notBefore must be YYYY-MM-DD");
  assert.ok(isoDate.test(evidence.certificate.notAfter), "certificate.notAfter must be YYYY-MM-DD");
  assert.ok(Date.parse(evidence.certificate.notAfter) > Date.parse(evidence.reviewedAt), "certificate must not be expired at review time");
  for (const [name, result] of Object.entries(evidence.iis)) {
    if (name === "siteName") continue;
    assert.equal(result, "passed", `${name} must pass for deployed TLS/IIS evidence`);
  }
  for (const name of ["autoRenewal", "privateKeyAclRestricted", "chainTrusted", "revocationCheck"]) {
    assert.equal(evidence.certificate[name], "passed", `${name} must pass for deployed TLS/IIS evidence`);
  }
  for (const [name, result] of Object.entries(evidence.headers)) {
    assert.equal(result, "passed", `${name} header check must pass for deployed TLS/IIS evidence`);
  }
  for (const [name, result] of Object.entries(evidence.healthChecks)) {
    assert.equal(result, "passed", `${name} must pass for deployed TLS/IIS evidence`);
  }
  assert.equal(evidence.redaction.privateKeysFound, false, "TLS/IIS evidence cannot contain private keys");
  assert.equal(evidence.redaction.certificatePasswordsFound, false, "TLS/IIS evidence cannot contain certificate passwords");
  assert.equal(evidence.redaction.runtimeSecretsFound, false, "TLS/IIS evidence cannot contain runtime secrets");
}

console.log(`TLS/IIS evidence validated: ${evidencePath}`);
