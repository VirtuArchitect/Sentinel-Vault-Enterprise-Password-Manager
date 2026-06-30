import express from "express";
import { store } from "../data/store.mjs";
import { verifyPassword } from "../crypto/passwords.mjs";
import { publicUser } from "../rbac/roles.mjs";
import { createSession } from "../services/sessionService.mjs";
import { audit } from "../services/auditService.mjs";
import { rateLimit } from "../middleware/rateLimit.mjs";

export const authRoutes = express.Router();

authRoutes.post("/login", rateLimit({ windowMs: 60000, max: 10 }), (req, res) => {
  const { email, password } = req.body;
  const user = store.findUserByEmail(email);
  if (!user || !verifyPassword(password, user)) return res.status(401).json({ error: "Invalid credentials" });
  const token = createSession(user.id);
  audit(user.id, "LOGIN", "Sentinel Vault Console", "MFA assertion accepted", req.ip);
  res.json({ token, user: publicUser(user) });
});
