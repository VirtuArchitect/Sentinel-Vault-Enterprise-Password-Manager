import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const outputPath = args.get("--out") || "artifacts/security/log-redaction-evidence.json";
const status = args.get("--status") || "planned";
const samplePath = args.get("--samples") || args.get("--sample-dir") || null;

assert.ok(allowedStatuses.has(status), "status must be planned, pilot, production, or retired");

const toIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const argStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(checkStatuses.has(value), `${name} must be planned, passed, failed, or not-applicable`);
  return value;
};

const listSampleFiles = (candidate) => {
  if (!candidate || !existsSync(candidate)) return [];
  const stats = statSync(candidate);
  if (stats.isFile()) return [candidate];
  if (!stats.isDirectory()) return [];
  return readdirSync(candidate)
    .map((entry) => path.join(candidate, entry))
    .filter((entry) => statSync(entry).isFile());
};

const sampleFiles = listSampleFiles(samplePath);
const sampleText = sampleFiles
  .filter((filePath) => statSync(filePath).size <= 1024 * 1024)
  .map((filePath) => readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""))
  .join("\n");

const countMatches = (pattern) => (sampleText.match(pattern) || []).length;
const hasSecretValue = /VAULT_ROOT_KEY\s*[:=]|secret(Value)?\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}|Passw0rd!/i.test(sampleText);
const hasToken = /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(sampleText);
const hasPrivateKey = /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(sampleText);
const hasPlaintextPassword = /password\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}/i.test(sampleText);
const parserFailures = countMatches(/parser(?:Failure| failure)|parse_error|parse error/i);

const eventsShipped = Number(args.get("--events-shipped") || countMatches(/"event"|eventType|deliveryId|audit/i));
const syntheticSecretEvents = Number(args.get("--synthetic-secret-events") || countMatches(/synthetic-secret|secret-redaction-test/i));
const syntheticTokenEvents = Number(args.get("--synthetic-token-events") || countMatches(/synthetic-token|token-redaction-test/i));

const evidence = {
  format: "sentinel-log-redaction-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  collectedAt: args.get("--collected-at") || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso()),
  sink: {
    name: args.get("--sink-name") || "replace-with-log-sink",
    type: args.get("--sink-type") || "siem",
    environment: args.get("--sink-environment") || "replace-with-sink-environment",
    retentionDays: Number(args.get("--retention-days") || 0)
  },
  sources: {
    api: argStatus("--source-api", "planned"),
    siemWebhook: argStatus("--source-siem-webhook", "planned"),
    windowsInstaller: argStatus("--source-windows-installer", "planned"),
    browserExtension: argStatus("--source-browser-extension", "planned"),
    nativeCompanion: argStatus("--source-native-companion", "planned")
  },
  samples: {
    eventsShipped,
    syntheticSecretEvents,
    syntheticTokenEvents,
    parserFailures: Number(args.get("--parser-failures") || parserFailures)
  },
  redaction: {
    recursiveSensitiveFields: argStatus("--recursive-sensitive-fields", "planned"),
    bearerTokens: argStatus("--bearer-tokens", "planned"),
    sentinelServiceTokens: argStatus("--sentinel-service-tokens", "planned"),
    privateKeys: argStatus("--private-keys", "planned"),
    passwordValues: argStatus("--password-values", "planned"),
    errorStacks: argStatus("--error-stacks", "planned"),
    ticketWorkNotes: argStatus("--ticket-work-notes", "planned"),
    auditLedgerExports: argStatus("--audit-ledger-exports", "planned")
  },
  controls: {
    schemaValidated: argStatus("--schema-validated", "planned"),
    receiverSearchCompleted: argStatus("--receiver-search-completed", "planned"),
    alertingConfigured: argStatus("--alerting-configured", "planned"),
    retentionPolicyVerified: argStatus("--retention-policy-verified", "planned"),
    accessReviewCompleted: argStatus("--access-review-completed", "planned")
  },
  findings: {
    secretValuesFound: args.get("--secret-values-found") === "true" ? true : args.get("--secret-values-found") === "false" ? false : hasSecretValue,
    tokensFound: args.get("--tokens-found") === "true" ? true : args.get("--tokens-found") === "false" ? false : hasToken,
    privateKeysFound: args.get("--private-keys-found") === "true" ? true : args.get("--private-keys-found") === "false" ? false : hasPrivateKey,
    plaintextPasswordsFound: args.get("--plaintext-passwords-found") === "true" ? true : args.get("--plaintext-passwords-found") === "false" ? false : hasPlaintextPassword
  },
  approvals: {
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    siemOwner: args.get("--siem-owner") || "replace-with-owner",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

for (const [name, count] of Object.entries(evidence.samples)) {
  assert.ok(Number.isInteger(count) && count >= 0, `${name} must be a non-negative integer`);
}

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Log redaction evidence written: ${outputPath}`);
