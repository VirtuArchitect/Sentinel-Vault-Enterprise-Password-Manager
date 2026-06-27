import crypto from "node:crypto";
import { store } from "../data/store.mjs";

export const audit = (actorId, action, target, detail = "", source = "127.0.0.1") => {
  const actor = store.findUserById(actorId);
  store.state.audit.unshift({
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    actor: actor?.name || "System",
    action,
    target,
    detail,
    source,
    outcome: "allowed"
  });
};
