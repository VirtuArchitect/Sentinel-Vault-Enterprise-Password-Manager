import express from "express";
import { config } from "../config.mjs";
import { decryptSecret } from "../crypto/vaultCrypto.mjs";
import { store } from "../data/store.mjs";
import { audit } from "../services/auditService.mjs";
import { resolveServiceToken } from "../services/serviceTokenService.mjs";

export const devopsRoutes = express.Router();

const requireDevopsEnabled = (_req, res, next) => {
  if (!config.integrations.devopsApiEnabled) {
    return res.status(404).json({ error: "DevOps API is disabled" });
  }
  next();
};

devopsRoutes.get("/devops/secrets/:id", requireDevopsEnabled, (req, res) => {
  const secret = store.findSecretById(req.params.id);
  if (!secret || secret.deletedAt) return res.status(404).json({ error: "Secret not found" });
  const serviceToken = resolveServiceToken(req.headers["x-sentinel-service-token"], secret);
  if (!serviceToken) return res.status(401).json({ error: "Scoped service token required" });
  audit(null, "DEVOPS_SECRET_RETRIEVAL", secret.name, `Secret retrieved through service token ${serviceToken.name}`, req.ip);
  res.json({
    id: secret.id,
    name: secret.name,
    type: secret.type,
    username: secret.username,
    value: decryptSecret(secret.encrypted)
  });
});
