import crypto from "node:crypto";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";

const signPayload = (payload, secret) => crypto.createHmac("sha256", secret).update(payload, "utf8").digest("hex");

export const getIntegrationStatus = () => ({
  siem: {
    configured: Boolean(config.integrations.siemWebhookUrl),
    mode: config.integrations.siemWebhookUrl ? "webhook" : "outbox",
    signing: Boolean(config.integrations.siemWebhookSecret),
    pending: store.state.integrationOutbox?.filter((item) => item.target === "siem-webhook" && ["queued", "retrying"].includes(item.status)).length || 0,
    failed: store.state.integrationOutbox?.filter((item) => item.target === "siem-webhook" && item.status === "failed").length || 0
  },
  itsm: {
    configured: Boolean(config.integrations.itsmBaseUrl),
    mode: config.integrations.itsmBaseUrl ? "ticket-reference" : "manual"
  },
  devopsApi: {
    enabled: config.integrations.devopsApiEnabled,
    mode: config.integrations.devopsApiEnabled ? "managed-scoped-tokens" : "disabled",
    tokenCount: store.state.serviceTokens?.filter((token) => !token.revokedAt).length || 0
  },
  outboxDepth: store.state.integrationOutbox?.length || 0
});

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
    const payload = JSON.stringify({
      id: item.id,
      ts: item.ts,
      kind: item.kind,
      event: item.event
    });
    const headers = {
      "Content-Type": "application/json",
      "User-Agent": "SentinelVault-SIEM/1.0"
    };
    if (config.integrations.siemWebhookSecret) {
      headers["X-Sentinel-Signature"] = `sha256=${signPayload(payload, config.integrations.siemWebhookSecret)}`;
    }

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
      console.error("Sentinel Vault SIEM delivery worker failed", err);
    });
  }, Math.max(5, config.integrations.siemRetrySeconds) * 1000);
  interval.unref?.();
  return interval;
};
