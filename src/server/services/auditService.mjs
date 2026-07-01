import crypto from "node:crypto";
import { store } from "../data/store.mjs";
import { enqueueIntegrationEvent } from "./integrationService.mjs";

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
  store.state.audit.unshift(event);
  enqueueIntegrationEvent(event);
  store.save();
};
