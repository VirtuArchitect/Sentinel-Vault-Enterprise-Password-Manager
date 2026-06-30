import crypto from "node:crypto";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";

export const getIntegrationStatus = () => ({
  siem: {
    configured: Boolean(config.integrations.siemWebhookUrl),
    mode: config.integrations.siemWebhookUrl ? "webhook" : "outbox"
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
    event
  });
  store.state.integrationOutbox = store.state.integrationOutbox.slice(0, config.integrations.outboxLimit);
};
