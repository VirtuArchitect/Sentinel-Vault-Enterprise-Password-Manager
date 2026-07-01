import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const retentionModes = new Set(["governance", "compliance", "governance-or-compliance"]);
const outputPath = args.get("--out") || "artifacts/security/audit-worm-evidence.json";
const status = args.get("--status") || "planned";
const ledgerPath = args.get("--ledger") || null;

assert.ok(allowedStatuses.has(status), "status must be planned, pilot, production, or retired");

const sha256Hex = (value) => crypto.createHash("sha256").update(value).digest("hex");
const toIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const argStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(checkStatuses.has(value), `${name} must be planned, passed, failed, or not-applicable`);
  return value;
};

const readLedger = (candidate) => {
  if (!candidate || !existsSync(candidate)) {
    return {
      text: "",
      exportedAt: status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso(),
      eventCount: 0,
      payloadHash: "replace-with-sha256",
      signatureAlgorithm: args.get("--signature-algorithm") || "HMAC-SHA256",
      manifestSignaturePresent: "planned",
      localVerification: "planned"
    };
  }

  const text = readFileSync(candidate, "utf8").replace(/^\uFEFF/, "");
  const parsed = JSON.parse(text);
  const ledger = parsed.ledger || parsed;
  const events = Array.isArray(ledger.events) ? ledger.events : [];
  const manifest = ledger.manifest || {};
  const payloadHash = manifest.payloadHash || sha256Hex(JSON.stringify(events));
  return {
    text,
    exportedAt: manifest.exportedAt || manifest.generatedAt || args.get("--exported-at") || toIso(),
    eventCount: Number(manifest.count ?? events.length),
    payloadHash,
    signatureAlgorithm: manifest.signatureAlgorithm || args.get("--signature-algorithm") || "HMAC-SHA256",
    manifestSignaturePresent: manifest.signature ? "passed" : "failed",
    localVerification: manifest.payloadHash === payloadHash && manifest.signature ? "passed" : "planned"
  };
};

const ledger = readLedger(ledgerPath);
const secretValuesFound = /VAULT_ROOT_KEY\s*[:=]|secret(Value)?\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}|Passw0rd!/i.test(ledger.text);
const tokenValuesFound = /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(ledger.text);

const externalSignatureHash = args.get("--external-signature-hash")
  || (args.get("--external-signature") ? sha256Hex(args.get("--external-signature")) : "replace-with-sha256");
const retentionMode = args.get("--retention-mode") || "governance-or-compliance";
assert.ok(retentionModes.has(retentionMode), "retention-mode must be governance, compliance, or governance-or-compliance");

const evidence = {
  format: "sentinel-audit-worm-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  ledgerExport: {
    exportedAt: args.get("--exported-at") || ledger.exportedAt,
    eventCount: Number(args.get("--event-count") || ledger.eventCount),
    payloadHash: args.get("--payload-hash") || ledger.payloadHash,
    signatureAlgorithm: args.get("--signature-algorithm") || ledger.signatureAlgorithm,
    manifestSignaturePresent: argStatus("--manifest-signature-present", ledger.manifestSignaturePresent),
    localVerification: argStatus("--local-verification", ledger.localVerification)
  },
  externalSigning: {
    provider: args.get("--signing-provider") || "replace-with-provider",
    keyId: args.get("--key-id") || "replace-with-key-id",
    algorithm: args.get("--signing-algorithm") || "replace-with-algorithm",
    signatureHash: externalSignatureHash,
    timestampAuthority: args.get("--timestamp-authority") || "replace-with-timestamp-authority",
    verification: argStatus("--external-verification", "planned")
  },
  wormStorage: {
    provider: args.get("--worm-provider") || "replace-with-provider",
    location: args.get("--worm-location") || "replace-with-bucket-container-or-vault",
    retentionMode,
    retentionDays: Number(args.get("--retention-days") || 365),
    objectLockEnabled: argStatus("--object-lock-enabled", "planned"),
    versioningEnabled: argStatus("--versioning-enabled", "planned"),
    deleteProtectionEnabled: argStatus("--delete-protection-enabled", "planned"),
    legalHoldTested: argStatus("--legal-hold-tested", "planned"),
    readbackVerified: argStatus("--readback-verified", "planned")
  },
  redaction: {
    secretValuesFound: args.get("--secret-values-found") === "true" ? true : args.get("--secret-values-found") === "false" ? false : secretValuesFound,
    tokenValuesFound: args.get("--token-values-found") === "true" ? true : args.get("--token-values-found") === "false" ? false : tokenValuesFound,
    screenshotsRedacted: argStatus("--screenshots-redacted", "planned")
  },
  approvals: {
    securityOwner: args.get("--security-owner") || "replace-with-owner",
    recordsOwner: args.get("--records-owner") || "replace-with-owner",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

assert.ok(Number.isInteger(evidence.ledgerExport.eventCount) && evidence.ledgerExport.eventCount >= 0, "event-count must be a non-negative integer");
assert.ok(Number.isInteger(evidence.wormStorage.retentionDays) && evidence.wormStorage.retentionDays >= 1, "retention-days must be a positive integer");

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Audit WORM evidence written: ${outputPath}`);
