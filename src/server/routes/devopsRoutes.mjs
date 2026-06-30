import express from "express";
import { config } from "../config.mjs";
import { decryptSecret } from "../crypto/vaultCrypto.mjs";
import { store } from "../data/store.mjs";
import { audit } from "../services/auditService.mjs";

export const devopsRoutes = express.Router();

const requireServiceToken = (req, res, next) => {
  if (!config.integrations.devopsApiEnabled) {
    return res.status(404).json({ error: "DevOps API is disabled" });
  }
  const token = req.headers["x-sentinel-service-token"];
  if (!config.integrations.devopsServiceToken || token !== config.integrations.devopsServiceToken) {
    return res.status(401).json({ error: "Service token required" });
  }
  next();
};

devopsRoutes.get("/devops/secrets/:id", requireServiceToken, (req, res) => {
  const secret = store.findSecretById(req.params.id);
  if (!secret || secret.deletedAt) return res.status(404).json({ error: "Secret not found" });
  audit(null, "DEVOPS_SECRET_RETRIEVAL", secret.name, "Secret retrieved through service-token API", req.ip);
  res.json({
    id: secret.id,
    name: secret.name,
    type: secret.type,
    username: secret.username,
    value: decryptSecret(secret.encrypted)
  });
});
