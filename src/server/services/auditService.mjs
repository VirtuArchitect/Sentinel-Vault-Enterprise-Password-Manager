import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";
import { enqueueIntegrationEvent } from "./integrationService.mjs";

const auditLedgerPath = () => path.join(config.dataDir, "audit-ledger.jsonl");
const signingKey = () => crypto.createHash("sha256").update(`${config.vaultRootKey}:audit-ledger`, "utf8").digest();

const canonicalAudit = (event) => JSON.stringify({
  id: event.id,
  ts: event.ts,
  actor: event.actor,
  action: event.action,
  target: event.target,
  detail: event.detail,
  source: event.source,
  outcome: event.outcome,
  previousHash: event.previousHash || null
});

export const auditHash = (event) => crypto.createHash("sha256").update(canonicalAudit(event), "utf8").digest("base64url");
export const auditSignature = (event) => crypto.createHmac("sha256", signingKey()).update(event.hash || auditHash(event), "utf8").digest("base64url");

const publicLedgerEvent = (event) => ({
  ...event,
  hash: event.hash || auditHash(event),
  signature: event.signature || auditSignature(event),
  signatureAlgorithm: "HMAC-SHA256"
});

const appendAuditLedger = (event) => {
  if (config.isTest) return;
  fs.mkdirSync(config.dataDir, { recursive: true });
  fs.appendFileSync(auditLedgerPath(), `${JSON.stringify(publicLedgerEvent(event))}\n`, "utf8");
};

export const verifyAuditChain = (events = store.state.audit) => {
  const newestFirst = events.filter((event) => event.hash || event.previousHash);
  if (!newestFirst.length) return { verified: true, checked: 0, brokenAt: null };

  for (let index = 0; index < newestFirst.length; index += 1) {
    const event = newestFirst[index];
    if (event.hash !== auditHash(event)) {
      return { verified: false, checked: index + 1, brokenAt: event.id, reason: "hash_mismatch" };
    }
    const nextOlder = newestFirst[index + 1];
    if (nextOlder && event.previousHash !== nextOlder.hash) {
      return { verified: false, checked: index + 1, brokenAt: event.id, reason: "chain_break" };
    }
  }
  return { verified: true, checked: newestFirst.length, brokenAt: null };
};

export const exportSignedAuditLedger = (events = store.state.audit) => {
  const ledger = events.slice().reverse().map(publicLedgerEvent);
  const payload = JSON.stringify(ledger);
  const manifest = {
    exportedAt: new Date().toISOString(),
    count: ledger.length,
    hashAlgorithm: "SHA-256",
    signatureAlgorithm: "HMAC-SHA256",
    payloadHash: crypto.createHash("sha256").update(payload, "utf8").digest("base64url"),
    ledgerPath: config.isTest ? null : auditLedgerPath()
  };
  manifest.signature = crypto.createHmac("sha256", signingKey()).update(manifest.payloadHash, "utf8").digest("base64url");
  return { manifest, events: ledger };
};

export const verifySignedAuditLedger = (ledger = exportSignedAuditLedger()) => {
  const payload = JSON.stringify(ledger.events || []);
  const payloadHash = crypto.createHash("sha256").update(payload, "utf8").digest("base64url");
  if (payloadHash !== ledger.manifest?.payloadHash) {
    return { verified: false, checked: 0, reason: "payload_hash_mismatch" };
  }
  const manifestSignature = crypto.createHmac("sha256", signingKey()).update(payloadHash, "utf8").digest("base64url");
  if (manifestSignature !== ledger.manifest?.signature) {
    return { verified: false, checked: 0, reason: "manifest_signature_mismatch" };
  }
  for (const [index, event] of (ledger.events || []).entries()) {
    if (event.hash !== auditHash(event)) {
      return { verified: false, checked: index + 1, reason: "event_hash_mismatch", brokenAt: event.id };
    }
    if (event.signature !== auditSignature(event)) {
      return { verified: false, checked: index + 1, reason: "event_signature_mismatch", brokenAt: event.id };
    }
  }
  return { verified: true, checked: ledger.events?.length || 0, reason: null };
};

export const audit = (actorId, action, target, detail = "", source = "127.0.0.1") => {
  const actor = store.findUserById(actorId);
  const previousHash = store.state.audit.find((event) => event.hash)?.hash || null;
  const event = {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    actor: actor?.name || "System",
    action,
    target,
    detail,
    source,
    outcome: "allowed",
    previousHash
  };
  event.hash = auditHash(event);
  event.signature = auditSignature(event);
  event.signatureAlgorithm = "HMAC-SHA256";
  store.state.audit.unshift(event);
  appendAuditLedger(event);
  enqueueIntegrationEvent(event);
  store.save();
};
