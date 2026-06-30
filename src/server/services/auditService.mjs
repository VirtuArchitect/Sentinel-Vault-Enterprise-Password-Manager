import crypto from "node:crypto";
import { store } from "../data/store.mjs";
import { enqueueIntegrationEvent } from "./integrationService.mjs";

export const audit = (actorId, action, target, detail = "", source = "127.0.0.1") => {
  const actor = store.findUserById(actorId);
  const event = {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    actor: actor?.name || "System",
    action,
    target,
    detail,
    source,
    outcome: "allowed"
  };
  store.state.audit.unshift(event);
  enqueueIntegrationEvent(event);
  store.save();
};
