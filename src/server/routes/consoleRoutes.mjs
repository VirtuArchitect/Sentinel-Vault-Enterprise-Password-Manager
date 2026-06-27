import express from "express";
import { auth } from "../middleware/auth.mjs";
import { can } from "../middleware/permissions.mjs";
import { createSecret, getConsolePayload, revealSecret, rotateSecret, shareSecret, updatePolicies } from "../services/vaultService.mjs";

export const consoleRoutes = express.Router();

consoleRoutes.get("/console", auth, (req, res) => {
  res.json(getConsolePayload(req.user));
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

consoleRoutes.patch("/policies", auth, can("policy:write"), (req, res) => {
  res.json({ policies: updatePolicies(req.user, req.body) });
});
