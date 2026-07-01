import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const siemUrl = args.get("--siem-url") || process.env.SIEM_WEBHOOK_URL || "";
const siemSecret = args.get("--siem-secret") || process.env.SIEM_WEBHOOK_SECRET || "";
const itsmUrl = args.get("--itsm-url") || process.env.ITSM_BASE_URL || "";
const ticketRef = String(args.get("--ticket-ref") || process.env.ITSM_TEST_TICKET || "").trim().toUpperCase();
const outputPath = args.get("--out") || "artifacts/integrations/connector-live-preflight.json";
const timeoutMs = Number(args.get("--timeout-ms") || 5000);
const replayWindowSeconds = 300;

assert.ok(siemUrl || itsmUrl, "At least one connector endpoint is required: --siem-url or --itsm-url");
if (itsmUrl) assert.ok(ticketRef, "--ticket-ref or ITSM_TEST_TICKET is required when testing ITSM");

const sha256 = (value) => crypto.createHash("sha256").update(value, "utf8").digest("base64url");
const hmacHex = (value, secret) => crypto.createHmac("sha256", secret).update(value, "utf8").digest("hex");

const parseJson = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const runSiemPreflight = async () => {
  const deliveryId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomBytes(16).toString("base64url");
  const body = JSON.stringify({
    id: `preflight-${deliveryId}`,
    ts: timestamp,
    delivery: { id: deliveryId, ts: timestamp, replayWindowSeconds },
    kind: "preflight",
    event: {
      action: "CONNECTOR_PREFLIGHT",
      target: "SIEM receiver",
      outcome: "allowed",
      detail: "Synthetic Sentinel Vault connector preflight event"
    }
  });
  const headers = {
    "Content-Type": "application/json",
    "User-Agent": "SentinelVault-Connector-Preflight/1.0",
    "X-Sentinel-Delivery-Id": deliveryId,
    "X-Sentinel-Timestamp": timestamp,
    "X-Sentinel-Nonce": nonce,
    "X-Sentinel-Replay-Window": String(replayWindowSeconds)
  };
  if (siemSecret) headers["X-Sentinel-Signature"] = `sha256=${hmacHex(`${timestamp}.${nonce}.${body}`, siemSecret)}`;

  const response = await fetch(siemUrl, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(timeoutMs)
  });
  const responseBody = await parseJson(response);
  return {
    endpointHost: new URL(siemUrl).host,
    status: response.status,
    ok: response.ok,
    deliveryId,
    signed: Boolean(siemSecret),
    replayWindowSeconds,
    requestBodySha256: sha256(body),
    receiver: {
      accepted: responseBody?.accepted ?? response.ok,
      deliveryId: responseBody?.deliveryId || null,
      replayStored: responseBody?.replayStored ?? null,
      schemaValidated: responseBody?.schemaValidated ?? null
    }
  };
};

const runItsmPreflight = async () => {
  const baseUrl = itsmUrl.replace(/\/$/, "");
  const response = await fetch(`${baseUrl}/tickets/${encodeURIComponent(ticketRef)}`, {
    headers: { Accept: "application/json", "User-Agent": "SentinelVault-Connector-Preflight/1.0" },
    signal: AbortSignal.timeout(timeoutMs)
  });
  const ticket = await parseJson(response);
  const state = String(ticket?.state || ticket?.status || "").toLowerCase();
  const active = ticket?.active === true || ["open", "active", "approved", "in_progress", "scheduled"].includes(state);
  return {
    endpointHost: new URL(baseUrl).host,
    ticketRef,
    status: response.status,
    ok: response.ok,
    active,
    state: ticket?.state || ticket?.status || null,
    requesterHash: ticket?.requester ? sha256(String(ticket.requester)) : null,
    assignmentGroupHash: ticket?.assignmentGroup ? sha256(String(ticket.assignmentGroup)) : null
  };
};

const connectors = {};
if (siemUrl) connectors.siem = await runSiemPreflight();
if (itsmUrl) connectors.itsm = await runItsmPreflight();

const checks = {
  siemDeliveryAccepted: connectors.siem ? connectors.siem.ok && connectors.siem.receiver.accepted === true : true,
  siemReplayEvidencePresent: connectors.siem ? connectors.siem.receiver.replayStored !== false : true,
  itsmTicketLookupPassed: connectors.itsm ? connectors.itsm.ok === true : true,
  itsmTicketActive: connectors.itsm ? connectors.itsm.active === true : true,
  redactedOutput: JSON.stringify(connectors).includes(siemSecret) === false
};

const evidence = {
  format: "sentinel-enterprise-connector-live-preflight-v1",
  checkedAt: new Date().toISOString(),
  connectors,
  checks
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

const failed = Object.entries(checks).filter(([, passed]) => !passed);
if (failed.length) {
  console.error(JSON.stringify(evidence, null, 2));
  throw new Error(`Enterprise connector preflight failed: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(`Enterprise connector live preflight evidence written: ${outputPath}`);
