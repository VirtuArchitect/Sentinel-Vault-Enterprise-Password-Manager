import express from "express";
import { auth } from "../middleware/auth.mjs";
import { can } from "../middleware/permissions.mjs";
import { getComplianceReport } from "../services/complianceService.mjs";
import { getIntegrationStatus } from "../services/integrationService.mjs";
import {
  approveAccessRequest,
  createSecret,
  denyAccessRequest,
  getConsolePayload,
  getSecretHealthReport,
  requestSecretAccess,
  revealSecret,
  rotateSecret,
  shareSecret,
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

consoleRoutes.get("/reports/compliance", auth, can("audit:read"), (_req, res) => {
  res.json({ report: getComplianceReport() });
});

consoleRoutes.post("/secrets", auth, can("vault:write"), (req, res, next) => {
  try {
    createSecret(req.user, req.body);
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

consoleRoutes.post("/secrets/:id/reveal", auth, can("vault:read"), (req, res, next) => {
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

consoleRoutes.post("/access-requests", auth, (req, res, next) => {
  try {
    res.status(201).json({
      request: requestSecretAccess(req.user, req.body.secretId, req.body.reason, {
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

consoleRoutes.patch("/policies", auth, can("policy:write"), (req, res, next) => {
  try {
    res.json({ policies: updatePolicies(req.user, req.body) });
  } catch (err) {
    next(err);
  }
});
