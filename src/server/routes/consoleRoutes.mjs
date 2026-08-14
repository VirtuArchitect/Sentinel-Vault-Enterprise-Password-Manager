import express from "express";
import { auth } from "../middleware/auth.mjs";
import { can } from "../middleware/permissions.mjs";
import { store } from "../data/store.mjs";
import { getComplianceEvidencePack, getComplianceReport } from "../services/complianceService.mjs";
import { getIntegrationStatus, updateIntegrationConfig } from "../services/integrationService.mjs";
import { audit, exportSignedAuditLedger, verifySignedAuditLedger } from "../services/auditService.mjs";
import { createTenant, createVault, exportAdminMetadata, importAdminMetadata, updateTenant, updateUser, updateVault } from "../services/adminService.mjs";
import { createOfflineCache, rehydrateOfflineCacheSecret, verifyOfflineCache } from "../services/offlineCacheService.mjs";
import { approveSecretImport, createSecretImport, denySecretImport, listSecretImports } from "../services/secretImportService.mjs";
import { createServiceToken, listServiceTokens, revokeServiceToken, rotateServiceToken } from "../services/serviceTokenService.mjs";
import { listDevices, listSessions, revokeSessionById } from "../services/sessionService.mjs";
import {
  approveAccessRequest,
  createSecret,
  deleteSecret,
  denyAccessRequest,
  getConsolePayload,
  getSecretHealthReport,
  requestSecretAccess,
  revealSecret,
  restoreDeletedSecret,
  restoreSecretVersion,
  revokeAccessRequest,
  rotateSecret,
  shareSecret,
  updateSecret,
  updatePolicies
} from "../services/vaultService.mjs";

export const consoleRoutes = express.Router();

consoleRoutes.get("/console", auth, (req, res) => {
  res.json(getConsolePayload(req.user));
});

consoleRoutes.get("/reports/secret-health", auth, can("audit:read"), (_req, res) => {
  res.json({ secrets: getSecretHealthReport() });
});

consoleRoutes.get("/integrations/status", auth, can("audit:read"), (_req, res) => {
  res.json({ integrations: getIntegrationStatus() });
});

consoleRoutes.patch("/integrations/config", auth, can("policy:write"), (req, res, next) => {
  try {
    const integrations = updateIntegrationConfig(req.body);
    audit(req.user.id, "INTEGRATION_CONFIG_UPDATE", "Enterprise integrations", "Updated SIEM, ITSM, or DevOps integration configuration", req.ip);
    res.json({ integrations });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.get("/service-tokens", auth, can("policy:write"), (_req, res) => {
  res.json({ tokens: listServiceTokens() });
});

consoleRoutes.get("/storage/status", auth, can("policy:write"), (_req, res) => {
  res.json({ storage: store.getStorageStatus() });
});

consoleRoutes.post("/storage/backup", auth, can("policy:write"), (_req, res) => {
  res.json({ backup: store.createBackup() });
});

consoleRoutes.post("/storage/backup/encrypted", auth, can("policy:write"), (_req, res) => {
  res.json({ backup: store.createEncryptedBackup() });
});

consoleRoutes.get("/storage/backups/verify", auth, can("policy:write"), (_req, res) => {
  res.json({ backups: store.validateBackups() });
});

consoleRoutes.get("/storage/backups/restore-validate", auth, can("policy:write"), (_req, res) => {
  res.json({ backups: store.validateEncryptedBackups() });
});

consoleRoutes.get("/sessions", auth, can("policy:write"), (_req, res) => {
  res.json({ sessions: listSessions(), devices: listDevices() });
});

consoleRoutes.post("/vaults", auth, can("policy:write"), (req, res, next) => {
  try {
    res.status(201).json({ vault: createVault(req.user, req.body) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/tenants", auth, can("policy:write"), (req, res, next) => {
  try {
    res.status(201).json({ tenant: createTenant(req.user, req.body) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.patch("/tenants/:id", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ tenant: updateTenant(req.user, req.params.id, req.body) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.get("/admin/export", auth, can("policy:write"), (req, res) => {
  res.setHeader("Content-Disposition", "attachment; filename=sentinel-admin-metadata.json");
  res.json({ metadata: exportAdminMetadata(req.user) });
});

consoleRoutes.post("/admin/import", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ result: importAdminMetadata(req.user, req.body) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.patch("/vaults/:id", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ vault: updateVault(req.user, req.params.id, req.body) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.patch("/users/:id", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ user: updateUser(req.user, req.params.id, req.body) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.get("/secret-imports", auth, can("policy:write"), (_req, res) => {
  res.json({ imports: listSecretImports() });
});

consoleRoutes.post("/secret-imports", auth, can("policy:write"), (req, res, next) => {
  try {
    res.status(201).json({ importBatch: createSecretImport(req.user, req.body) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secret-imports/:id/approve", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ importBatch: approveSecretImport(req.user, req.params.id) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secret-imports/:id/deny", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ importBatch: denySecretImport(req.user, req.params.id, req.body.reason) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/sessions/:id/revoke", auth, can("policy:write"), (req, res) => {
  const revoked = revokeSessionById(req.params.id);
  if (revoked) audit(req.user.id, "SESSION_REVOKE", req.params.id, "Administrator revoked an active session", req.ip);
  res.status(revoked ? 200 : 404).json(revoked ? { ok: true } : { error: "Session not found" });
});

consoleRoutes.post("/service-tokens", auth, can("policy:write"), (req, res, next) => {
  try {
    res.status(201).json(createServiceToken(req.user, req.body));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/service-tokens/:id/revoke", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json(revokeServiceToken(req.user, req.params.id));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/service-tokens/:id/rotate", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json(rotateServiceToken(req.user, req.params.id));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.get("/reports/compliance", auth, can("audit:read"), (_req, res) => {
  res.json({ report: getComplianceReport() });
});

consoleRoutes.get("/reports/compliance/export", auth, can("audit:read"), (_req, res) => {
  res.setHeader("Content-Disposition", "attachment; filename=sentinel-compliance-evidence.json");
  res.json({ report: getComplianceEvidencePack() });
});

consoleRoutes.get("/reports/audit-ledger/export", auth, can("audit:read"), (_req, res) => {
  res.setHeader("Content-Disposition", "attachment; filename=sentinel-audit-ledger.json");
  res.json({ ledger: exportSignedAuditLedger() });
});

consoleRoutes.get("/reports/audit-ledger/verify", auth, can("audit:read"), (_req, res) => {
  res.json({ verification: verifySignedAuditLedger(exportSignedAuditLedger()) });
});

consoleRoutes.post("/offline-cache/export", auth, can("vault:read"), (req, res) => {
  res.setHeader("Content-Disposition", "attachment; filename=sentinel-offline-cache.json");
  res.json({ cache: createOfflineCache(req.user) });
});

consoleRoutes.post("/offline-cache/verify", auth, can("vault:read"), (req, res, next) => {
  try {
    res.json({ verification: verifyOfflineCache(req.user, req.body.cache) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/offline-cache/rehydrate", auth, can("secret:reveal"), (req, res, next) => {
  try {
    res.json(rehydrateOfflineCacheSecret(req.user, req.body.cache, req.body.secretId));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secrets", auth, can("vault:write"), (req, res, next) => {
  try {
    createSecret(req.user, req.body);
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.patch("/secrets/:id", auth, can("vault:write"), (req, res, next) => {
  try {
    res.json(updateSecret(req.user, req.params.id, req.body));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.delete("/secrets/:id", auth, can("vault:write"), (req, res, next) => {
  try {
    res.json(deleteSecret(req.user, req.params.id));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secrets/:id/restore", auth, can("vault:write"), (req, res, next) => {
  try {
    res.json(restoreDeletedSecret(req.user, req.params.id));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secrets/:id/versions/:index/restore", auth, can("vault:write"), (req, res, next) => {
  try {
    res.json(restoreSecretVersion(req.user, req.params.id, req.params.index));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secrets/:id/reveal", auth, can("secret:reveal"), (req, res, next) => {
  try {
    res.json(revealSecret(req.user, req.params.id));
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secrets/:id/rotate", auth, can("vault:write"), (req, res, next) => {
  try {
    res.json({ ok: true, password: rotateSecret(req.user, req.params.id) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secrets/:id/share", auth, can("vault:share"), (req, res, next) => {
  try {
    shareSecret(req.user, req.params.id, req.body.userId);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/access-requests", auth, async (req, res, next) => {
  try {
    res.status(201).json({
      request: await requestSecretAccess(req.user, req.body.secretId, req.body.reason, {
        minutes: req.body.minutes,
        ticketRef: req.body.ticketRef
      })
    });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/access-requests/:id/approve", auth, can("vault:share"), (req, res, next) => {
  try {
    res.json({ request: approveAccessRequest(req.user, req.params.id, req.body.minutes) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/access-requests/:id/deny", auth, can("vault:share"), (req, res, next) => {
  try {
    res.json({ request: denyAccessRequest(req.user, req.params.id) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/access-requests/:id/revoke", auth, can("vault:share"), (req, res, next) => {
  try {
    res.json({ request: revokeAccessRequest(req.user, req.params.id) });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.patch("/policies", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ policies: updatePolicies(req.user, req.body) });
  } catch (err) {
    next(err);
  }
});
