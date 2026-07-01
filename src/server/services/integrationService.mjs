import crypto from "node:crypto";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";
import { logger } from "../logging/logger.mjs";

const replayWindowSeconds = 300;
const signPayload = (payload, secret) => crypto.createHmac("sha256", secret).update(payload, "utf8").digest("hex");
const signDelivery = ({ timestamp, nonce, payload }, secret) => signPayload(`${timestamp}.${nonce}.${payload}`, secret);
const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const getIntegrationStatus = () => ({
  siem: {
    configured: Boolean(config.integrations.siemWebhookUrl),
    mode: config.integrations.siemWebhookUrl ? "webhook" : "outbox",
    webhookUrl: config.integrations.siemWebhookUrl,
    signing: Boolean(config.integrations.siemWebhookSecret),
    signingKeyId: config.integrations.siemWebhookKeyId,
    previousSigningKeyConfigured: Boolean(config.integrations.siemWebhookPreviousSecret && config.integrations.siemWebhookPreviousKeyId),
    previousSigningKeyId: config.integrations.siemWebhookPreviousKeyId,
    replayWindowSeconds,
    pending: store.state.integrationOutbox?.filter((item) => item.target === "siem-webhook" && ["queued", "retrying"].includes(item.status)).length || 0,
    failed: store.state.integrationOutbox?.filter((item) => item.target === "siem-webhook" && item.status === "failed").length || 0
  },
  itsm: {
    configured: Boolean(config.integrations.itsmBaseUrl),
    mode: config.integrations.itsmBaseUrl ? "live-ticket-validation-work-notes" : "manual",
    baseUrl: config.integrations.itsmBaseUrl,
    ticketPrefixes: config.integrations.itsmTicketPrefixes
  },
  devopsApi: {
    enabled: config.integrations.devopsApiEnabled,
    mode: config.integrations.devopsApiEnabled ? "managed-scoped-tokens" : "disabled",
    tokenCount: store.state.serviceTokens?.filter((token) => !token.revokedAt).length || 0
  },
  outboxDepth: store.state.integrationOutbox?.length || 0
});

const validateTicketWithItsm = async (ticketRef, fetchImpl = globalThis.fetch) => {
  if (!config.integrations.itsmBaseUrl) return { valid: true, checked: false };
  const url = `${config.integrations.itsmBaseUrl.replace(/\/$/, "")}/tickets/${encodeURIComponent(ticketRef)}`;
  try {
    const response = await fetchImpl(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "SentinelVault-ITSM/1.0"
      }
    });
    if (response.status === 404) return { valid: false, checked: true, message: "Ticket reference was not found in ITSM" };
    if (!response.ok) return { valid: false, checked: true, message: `ITSM ticket validation returned HTTP ${response.status}` };
    const ticket = await response.json();
    const state = String(ticket.state || ticket.status || "").toLowerCase();
    const active = ticket.active === true || ["open", "active", "approved", "in_progress", "scheduled"].includes(state);
    if (!active) {
      return { valid: false, checked: true, message: `Ticket ${ticketRef} is not active` };
    }
    return {
      valid: true,
      checked: true,
      state: ticket.state || ticket.status || "active",
      assignmentGroup: ticket.assignmentGroup || null,
      requester: ticket.requester || null
    };
  } catch (err) {
    return {
      valid: false,
      checked: true,
      message: err instanceof Error ? `ITSM ticket validation failed: ${err.message}` : "ITSM ticket validation failed"
    };
  }
};

export const validateTicketReference = async (ticketRef, options = {}) => {
  if (!config.integrations.itsmBaseUrl) return { valid: true, required: false };
  const text = String(ticketRef || "").trim().toUpperCase();
  const prefixes = config.integrations.itsmTicketPrefixes;
  const valid = prefixes.some((prefix) => new RegExp(`^${escapeRegex(prefix)}-\\d{3,}$`).test(text));
  if (!valid) {
    return {
      valid: false,
      required: true,
      prefixes,
      message: `Ticket reference must start with ${prefixes.join(", ")} and include a numeric identifier`
    };
  }
  const live = await validateTicketWithItsm(text, options.fetchImpl || globalThis.fetch);
  return {
    ...live,
    required: true,
    prefixes,
    message: live.valid ? "" : live.message
  };
};

const publicWorkNotePayload = ({ action, request, actor, secret }) => ({
  source: "Sentinel Vault",
  action,
  requestId: request.id,
  requestStatus: request.status,
  requestedAt: request.requestedAt,
  decidedAt: request.decidedAt || null,
  expiresAt: request.expiresAt || null,
  requestedMinutes: request.requestedMinutes || null,
  actor: {
    id: actor.id,
    name: actor.name,
    role: actor.role
  },
  secret: {
    id: secret.id,
    name: secret.name,
    vaultId: secret.vaultId
  },
  redaction: {
    secretValueIncluded: false,
    freeFormReasonIncluded: false
  },
  note: `Sentinel Vault ${action} access request ${request.id} for ${secret.name}. Status: ${request.status}.`
});

export const postItsmWorkNote = async ({ ticketRef, action, request, actor, secret, fetchImpl = globalThis.fetch }) => {
  if (!config.integrations.itsmBaseUrl || !ticketRef) {
    return { attempted: false, delivered: false, reason: "not_configured" };
  }
  const normalizedTicketRef = String(ticketRef || "").trim().toUpperCase();
  const url = `${config.integrations.itsmBaseUrl.replace(/\/$/, "")}/tickets/${encodeURIComponent(normalizedTicketRef)}/work-notes`;
  const payload = publicWorkNotePayload({ action, request, actor, secret });
  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "SentinelVault-ITSM/1.0"
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    return {
      attempted: true,
      delivered: false,
      status: response.status,
      message: `ITSM work-note update returned HTTP ${response.status}`
    };
  }
  return {
    attempted: true,
    delivered: true,
    status: response.status,
    ticketRef: normalizedTicketRef
  };
};

export const updateIntegrationConfig = (patch = {}) => {
  if (patch.siemWebhookUrl !== undefined) config.integrations.siemWebhookUrl = String(patch.siemWebhookUrl || "").trim();
  if (patch.siemWebhookSecret !== undefined && String(patch.siemWebhookSecret || "").trim()) {
    config.integrations.siemWebhookSecret = String(patch.siemWebhookSecret).trim();
  }
  if (patch.siemWebhookKeyId !== undefined) config.integrations.siemWebhookKeyId = String(patch.siemWebhookKeyId || "").trim();
  if (patch.siemWebhookPreviousSecret !== undefined && String(patch.siemWebhookPreviousSecret || "").trim()) {
    config.integrations.siemWebhookPreviousSecret = String(patch.siemWebhookPreviousSecret).trim();
  }
  if (patch.siemWebhookPreviousKeyId !== undefined) config.integrations.siemWebhookPreviousKeyId = String(patch.siemWebhookPreviousKeyId || "").trim();
  if (patch.siemMaxAttempts !== undefined) config.integrations.siemMaxAttempts = Number(patch.siemMaxAttempts);
  if (patch.siemRetrySeconds !== undefined) config.integrations.siemRetrySeconds = Number(patch.siemRetrySeconds);
  if (patch.itsmBaseUrl !== undefined) config.integrations.itsmBaseUrl = String(patch.itsmBaseUrl || "").trim();
  if (patch.itsmTicketPrefixes !== undefined) {
    config.integrations.itsmTicketPrefixes = String(patch.itsmTicketPrefixes || "")
      .split(",")
      .map((prefix) => prefix.trim().toUpperCase())
      .filter(Boolean);
  }
  if (patch.devopsApiEnabled !== undefined) config.integrations.devopsApiEnabled = Boolean(patch.devopsApiEnabled);

  return getIntegrationStatus();
};

export const enqueueIntegrationEvent = (event) => {
  store.state.integrationOutbox = store.state.integrationOutbox || [];
  store.state.integrationOutbox.unshift({
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    kind: "audit",
    status: "queued",
    target: config.integrations.siemWebhookUrl ? "siem-webhook" : "local-outbox",
    attempts: 0,
    nextAttemptAt: new Date().toISOString(),
    lastError: null,
    event
  });
  store.state.integrationOutbox = store.state.integrationOutbox.slice(0, config.integrations.outboxLimit);
};

export const deliverQueuedIntegrationEvents = async ({ fetchImpl = globalThis.fetch, now = new Date() } = {}) => {
  if (!config.integrations.siemWebhookUrl || typeof fetchImpl !== "function") {
    return { attempted: 0, delivered: 0, failed: 0 };
  }

  const dueAt = now instanceof Date ? now : new Date(now);
  let attempted = 0;
  let delivered = 0;
  let failed = 0;

  for (const item of store.state.integrationOutbox || []) {
    if (item.target !== "siem-webhook") continue;
    if (!["queued", "retrying"].includes(item.status)) continue;
    if (item.nextAttemptAt && Date.parse(item.nextAttemptAt) > dueAt.getTime()) continue;

    attempted += 1;
    item.attempts = Number(item.attempts || 0) + 1;
    const deliveryId = crypto.randomUUID();
    const deliveryTs = new Date().toISOString();
    const deliveryNonce = crypto.randomBytes(16).toString("base64url");
    const payload = JSON.stringify({
      id: item.id,
      ts: item.ts,
      delivery: {
        id: deliveryId,
        ts: deliveryTs,
        replayWindowSeconds
      },
      kind: item.kind,
      event: item.event
    });
    const headers = {
      "Content-Type": "application/json",
      "User-Agent": "SentinelVault-SIEM/1.0",
      "X-Sentinel-Delivery-Id": deliveryId,
      "X-Sentinel-Timestamp": deliveryTs,
      "X-Sentinel-Nonce": deliveryNonce,
      "X-Sentinel-Replay-Window": String(replayWindowSeconds)
    };
    if (config.integrations.siemWebhookSecret) {
      headers["X-Sentinel-Signature"] = `sha256=${signDelivery({ timestamp: deliveryTs, nonce: deliveryNonce, payload }, config.integrations.siemWebhookSecret)}`;
      if (config.integrations.siemWebhookKeyId) headers["X-Sentinel-Key-Id"] = config.integrations.siemWebhookKeyId;
      if (config.integrations.siemWebhookPreviousSecret && config.integrations.siemWebhookPreviousKeyId) {
        headers["X-Sentinel-Previous-Key-Id"] = config.integrations.siemWebhookPreviousKeyId;
      }
    }
    item.lastDeliveryId = deliveryId;
    item.lastDeliveryAt = deliveryTs;

    try {
      const response = await fetchImpl(config.integrations.siemWebhookUrl, {
        method: "POST",
        headers,
        body: payload
      });
      if (!response.ok) {
        throw new Error(`SIEM webhook returned HTTP ${response.status}`);
      }
      item.status = "delivered";
      item.deliveredAt = new Date().toISOString();
      item.lastError = null;
      delivered += 1;
    } catch (err) {
      const maxAttempts = config.integrations.siemMaxAttempts;
      item.lastError = err instanceof Error ? err.message : "SIEM webhook delivery failed";
      if (item.attempts >= maxAttempts) {
        item.status = "failed";
        failed += 1;
      } else {
        item.status = "retrying";
        const retryDelay = config.integrations.siemRetrySeconds * 1000 * item.attempts;
        item.nextAttemptAt = new Date(Date.now() + retryDelay).toISOString();
      }
    }
  }

  if (attempted) store.save();
  return { attempted, delivered, failed };
};

export const startIntegrationDeliveryWorker = () => {
  if (!config.integrations.siemWebhookUrl || config.isTest) return null;
  const interval = setInterval(() => {
    deliverQueuedIntegrationEvents().catch((err) => {
      logger.error("siem.delivery_worker_failed", { err });
    });
  }, Math.max(5, config.integrations.siemRetrySeconds) * 1000);
  interval.unref?.();
  return interval;
};
