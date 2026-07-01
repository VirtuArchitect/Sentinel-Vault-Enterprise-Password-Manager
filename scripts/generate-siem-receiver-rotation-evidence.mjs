import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "pilot", "certified", "expired"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const outputPath = args.get("--out") || "artifacts/integrations/siem-receiver-rotation-evidence.json";
const reportPath = args.get("--report") || "artifacts/integrations/siem-receiver-rotation.json";
const status = args.get("--status") || "planned";

assert.ok(allowedStatuses.has(status), "status must be planned, pilot, certified, or expired");

const toIso = (date = new Date()) => date.toISOString().replace(/\.\d{3}Z$/, "Z");
const addDays = (iso, days) => {
  const date = new Date(iso);
  date.setUTCDate(date.getUTCDate() + days);
  return toIso(date);
};
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const readText = (filePath) => readFileSync(filePath, "utf8").replace(/^\uFEFF/, "");
const argStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(checkStatuses.has(value), `${name} must be planned, passed, failed, or not-applicable`);
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
const normalizeStatus = (value) => {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (["passed", "pass", "accepted", "verified", "rejected"].includes(normalized)) {
    return "passed";
  }
  if (["failed", "fail", "error"].includes(normalized)) {
    return "failed";
  }
  if (["not-applicable", "not_applicable", "n/a"].includes(normalized)) {
    return "not-applicable";
  }
  return "planned";
};

const report = existsSync(reportPath) ? readJson(reportPath) : null;
const receiver = report?.receiver || {};
const rotation = report?.rotation || {};
const samples = report?.samples || {};
const checks = report?.checks || {};
const rotatedAt = args.get("--rotated-at") || rotation.rotatedAt || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso());
const previousKeyRetireAfter = args.get("--previous-key-retire-after")
  || rotation.previousKeyRetireAfter
  || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : addDays(rotatedAt, Number(args.get("--overlap-days") || 7)));
const samplePath = args.get("--samples");
const sampleText = samplePath && existsSync(samplePath) && !statSync(samplePath).isDirectory() ? readText(samplePath) : "";
const combinedText = `${report ? JSON.stringify(report) : ""}\n${sampleText}`;
const signingSecretsFound = /signingSecret\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{12,}|hmacSecret\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{12,}/i.test(combinedText);
const payloadSecretValuesFound = /secret(Value)?\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}|Passw0rd!/i.test(combinedText);
const tokenValuesFound = /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(combinedText);

const evidence = {
  format: "sentinel-siem-receiver-rotation-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  receiver: {
    system: args.get("--system") || receiver.system || "replace-with-siem-system",
    endpointHost: args.get("--endpoint-host") || receiver.endpointHost || "replace-with-host",
    owner: args.get("--receiver-owner") || receiver.owner || "replace-with-owner",
    supportQueue: args.get("--support-queue") || receiver.supportQueue || "replace-with-queue"
  },
  rotation: {
    activeKeyId: args.get("--active-key-id") || rotation.activeKeyId || "replace-with-active-key-id",
    previousKeyId: args.get("--previous-key-id") || rotation.previousKeyId || "replace-with-previous-key-id",
    rotatedAt,
    previousKeyRetireAfter,
    changeTicket: args.get("--change-ticket") || rotation.changeTicket || "replace-with-ticket"
  },
  checks: {
    activeKeyAccepted: argStatus("--active-key-accepted", normalizeStatus(checks.activeKeyAccepted)),
    previousKeyAcceptedDuringWindow: argStatus("--previous-key-accepted-during-window", normalizeStatus(checks.previousKeyAcceptedDuringWindow)),
    previousKeyRejectedAfterWindow: argStatus("--previous-key-rejected-after-window", normalizeStatus(checks.previousKeyRejectedAfterWindow)),
    signatureVerified: argStatus("--signature-verified", normalizeStatus(checks.signatureVerified)),
    timestampRejectedOutsideReplayWindow: argStatus("--timestamp-rejected-outside-replay-window", normalizeStatus(checks.timestampRejectedOutsideReplayWindow)),
    nonceReplayRejected: argStatus("--nonce-replay-rejected", normalizeStatus(checks.nonceReplayRejected)),
    deliveryIdStored: argStatus("--delivery-id-stored", normalizeStatus(checks.deliveryIdStored)),
    redactedLogsReviewed: argStatus("--redacted-logs-reviewed", normalizeStatus(checks.redactedLogsReviewed)),
    receiverAlertingConfirmed: argStatus("--receiver-alerting-confirmed", normalizeStatus(checks.receiverAlertingConfirmed))
  },
  samples: {
    activeDeliveryId: args.get("--active-delivery-id") || samples.activeDeliveryId || "replace-with-delivery-id",
    previousKeyDeliveryId: args.get("--previous-key-delivery-id") || samples.previousKeyDeliveryId || "replace-with-delivery-id",
    replayAttemptId: args.get("--replay-attempt-id") || samples.replayAttemptId || "replace-with-replay-test-id",
    receiverEvidencePath: args.get("--receiver-evidence-path") || samples.receiverEvidencePath || reportPath
  },
  redaction: {
    signingSecretsFound: asBool(args.get("--signing-secrets-found"), signingSecretsFound),
    payloadSecretValuesFound: asBool(args.get("--payload-secret-values-found"), payloadSecretValuesFound),
    tokenValuesFound: asBool(args.get("--token-values-found"), tokenValuesFound)
  },
  approvals: {
    siemOwner: args.get("--siem-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`SIEM receiver rotation evidence written: ${outputPath}`);
