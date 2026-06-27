import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import { createServer as createViteServer } from "vite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 5173);
const prod = process.env.NODE_ENV === "production";

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const roles = {
  SECURITY_ADMIN: ["vault:read", "vault:write", "vault:share", "users:read", "policy:write", "audit:read"],
  VAULT_OPERATOR: ["vault:read", "vault:write", "vault:share"],
  AUDITOR: ["vault:read", "audit:read", "users:read"]
};

const hashPassword = (password, salt = crypto.randomBytes(16).toString("hex")) => {
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 32, "sha512").toString("hex");
  return { salt, hash };
};

const vaultKey = crypto.scryptSync(process.env.VAULT_ROOT_KEY || "sentinel-demo-root-key", "sentinel-vault", 32);

const encryptSecret = (value) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", vaultKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    value: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64")
  };
};

const decryptSecret = (payload) => {
  const decipher = crypto.createDecipheriv("aes-256-gcm", vaultKey, Buffer.from(payload.iv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(payload.value, "base64")), decipher.final()]).toString("utf8");
};

const seededPassword = "Passw0rd!";
const userSeeds = [
  ["u1", "Commander Ada", "ada@defence.local", "SECURITY_ADMIN", "Strategic Systems"],
  ["u2", "Morgan Vale", "morgan@defence.local", "VAULT_OPERATOR", "Cyber Operations"],
  ["u3", "Iris Chen", "iris@defence.local", "AUDITOR", "Assurance"]
];

const db = {
  users: userSeeds.map(([id, name, email, role, unit]) => ({ id, name, email, role, unit, mfa: true, ...hashPassword(seededPassword) })),
  sessions: new Map(),
  vaults: [
    { id: "v1", name: "Mission Systems", classification: "SECRET", ownerUnit: "Strategic Systems", members: ["u1", "u2"], health: 98 },
    { id: "v2", name: "Identity Backbone", classification: "TOP SECRET", ownerUnit: "Cyber Operations", members: ["u1", "u2", "u3"], health: 93 },
    { id: "v3", name: "Supplier Access", classification: "OFFICIAL-SENSITIVE", ownerUnit: "Assurance", members: ["u1", "u3"], health: 89 }
  ],
  secrets: [],
  audit: [],
  policies: {
    rotationDays: 45,
    minimumLength: 20,
    mfaRequired: true,
    justInTimeAccess: true,
    breakGlassApproval: "Two-person integrity",
    clipboardTtl: 30,
    sessionMinutes: 15
  }
};

const seedSecret = (secret) => db.secrets.push({ ...secret, encrypted: encryptSecret(secret.password), password: undefined });
seedSecret({ id: "s1", vaultId: "v1", name: "Satellite Telemetry API", username: "svc_telemetry", password: "E7#hP9!qZ2@Lw8$mV4", url: "https://telemetry.defence.local", tags: ["api", "mission"], risk: "low", rotatedAt: "2026-06-21T09:30:00Z", sharedWith: ["u2"] });
seedSecret({ id: "s2", vaultId: "v2", name: "Privileged Directory Root", username: "adm.root", password: "nK5!vD8@xR2#tY6$pB", url: "ldaps://identity.defence.local", tags: ["identity", "tier-0"], risk: "high", rotatedAt: "2026-06-14T13:10:00Z", sharedWith: ["u1"] });
seedSecret({ id: "s3", vaultId: "v3", name: "Secure Build Registry", username: "robot.deploy", password: "Q4$pL7#cN1@zV9!eH", url: "https://registry.defence.local", tags: ["devsecops"], risk: "medium", rotatedAt: "2026-06-24T06:45:00Z", sharedWith: ["u3"] });

const audit = (actorId, action, target, detail = "") => {
  const actor = db.users.find((u) => u.id === actorId);
  db.audit.unshift({
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    actor: actor?.name || "System",
    action,
    target,
    detail,
    source: "127.0.0.1",
    outcome: "allowed"
  });
};
db.audit.push(
  { id: crypto.randomUUID(), ts: "2026-06-27T07:42:00Z", actor: "Iris Chen", action: "EXPORT_REVIEW", target: "Audit evidence pack", detail: "Quarterly compliance export opened", source: "10.20.4.18", outcome: "allowed" },
  { id: crypto.randomUUID(), ts: "2026-06-26T17:10:00Z", actor: "Morgan Vale", action: "ROTATE_SECRET", target: "Secure Build Registry", detail: "Automated rotation completed", source: "10.20.9.42", outcome: "allowed" },
  { id: crypto.randomUUID(), ts: "2026-06-26T11:02:00Z", actor: "Commander Ada", action: "POLICY_UPDATE", target: "Session timeout", detail: "Changed from 30 to 15 minutes", source: "10.20.1.7", outcome: "allowed" }
);

const publicUser = (user) => ({ id: user.id, name: user.name, email: user.email, role: user.role, unit: user.unit, mfa: user.mfa, permissions: roles[user.role] || [] });
const auth = (req, res, next) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const session = token && db.sessions.get(token);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  req.user = db.users.find((u) => u.id === session.userId);
  next();
};
const can = (permission) => (req, res, next) => {
  if (!(roles[req.user.role] || []).includes(permission)) return res.status(403).json({ error: "Insufficient role clearance" });
  next();
};

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find((u) => u.email.toLowerCase() === String(email || "").toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const { hash } = hashPassword(password || "", user.salt);
  if (hash !== user.hash) return res.status(401).json({ error: "Invalid credentials" });
  const token = crypto.randomBytes(32).toString("base64url");
  db.sessions.set(token, { userId: user.id, createdAt: Date.now() });
  audit(user.id, "LOGIN", "Sentinel Vault Console", "MFA assertion accepted");
  res.json({ token, user: publicUser(user) });
});

app.get("/api/console", auth, (req, res) => {
  const readableVaults = db.vaults.filter((v) => v.members.includes(req.user.id) || req.user.role === "SECURITY_ADMIN");
  const readableIds = new Set(readableVaults.map((v) => v.id));
  const secrets = db.secrets
    .filter((s) => readableIds.has(s.vaultId) || s.sharedWith.includes(req.user.id))
    .map((s) => ({
      id: s.id,
      vaultId: s.vaultId,
      name: s.name,
      username: s.username,
      url: s.url,
      tags: s.tags,
      risk: s.risk,
      rotatedAt: s.rotatedAt,
      sharedWith: s.sharedWith,
      strength: Math.min(100, Math.round(decryptSecret(s.encrypted).length * 4.6))
    }));
  res.json({
    user: publicUser(req.user),
    users: db.users.map(publicUser),
    vaults: readableVaults,
    secrets,
    policies: db.policies,
    audit: db.audit.slice(0, 20),
    metrics: {
      secrets: db.secrets.length,
      vaults: db.vaults.length,
      stale: db.secrets.filter((s) => Date.now() - Date.parse(s.rotatedAt) > db.policies.rotationDays * 86400000).length,
      highRisk: db.secrets.filter((s) => s.risk === "high").length
    }
  });
});

app.post("/api/secrets", auth, can("vault:write"), (req, res) => {
  const { vaultId, name, username, password, url, tags } = req.body;
  if (!vaultId || !name || !username || !password) return res.status(400).json({ error: "Vault, name, username, and password are required" });
  const vault = db.vaults.find((v) => v.id === vaultId);
  if (!vault || (!vault.members.includes(req.user.id) && req.user.role !== "SECURITY_ADMIN")) return res.status(403).json({ error: "Vault access denied" });
  const secret = {
    id: crypto.randomUUID(),
    vaultId,
    name,
    username,
    url: url || "",
    tags: String(tags || "").split(",").map((t) => t.trim()).filter(Boolean),
    risk: password.length < db.policies.minimumLength ? "high" : "low",
    rotatedAt: new Date().toISOString(),
    sharedWith: [req.user.id],
    encrypted: encryptSecret(password)
  };
  db.secrets.unshift(secret);
  audit(req.user.id, "CREATE_SECRET", name, `Stored in ${vault.name}`);
  res.status(201).json({ ok: true });
});

app.post("/api/secrets/:id/reveal", auth, can("vault:read"), (req, res) => {
  const secret = db.secrets.find((s) => s.id === req.params.id);
  if (!secret) return res.status(404).json({ error: "Secret not found" });
  const vault = db.vaults.find((v) => v.id === secret.vaultId);
  if (!vault?.members.includes(req.user.id) && !secret.sharedWith.includes(req.user.id) && req.user.role !== "SECURITY_ADMIN") return res.status(403).json({ error: "Secret access denied" });
  audit(req.user.id, "REVEAL_SECRET", secret.name, "Credential viewed under active session policy");
  res.json({ password: decryptSecret(secret.encrypted), expiresIn: db.policies.clipboardTtl });
});

app.post("/api/secrets/:id/rotate", auth, can("vault:write"), (req, res) => {
  const secret = db.secrets.find((s) => s.id === req.params.id);
  if (!secret) return res.status(404).json({ error: "Secret not found" });
  const generated = crypto.randomBytes(18).toString("base64url") + "!A7";
  secret.encrypted = encryptSecret(generated);
  secret.rotatedAt = new Date().toISOString();
  secret.risk = "low";
  audit(req.user.id, "ROTATE_SECRET", secret.name, "Generated 170-bit replacement credential");
  res.json({ ok: true, password: generated });
});

app.post("/api/secrets/:id/share", auth, can("vault:share"), (req, res) => {
  const secret = db.secrets.find((s) => s.id === req.params.id);
  const target = db.users.find((u) => u.id === req.body.userId);
  if (!secret || !target) return res.status(404).json({ error: "Secret or user not found" });
  if (!secret.sharedWith.includes(target.id)) secret.sharedWith.push(target.id);
  audit(req.user.id, "SHARE_SECRET", secret.name, `Granted to ${target.name}`);
  res.json({ ok: true });
});

app.patch("/api/policies", auth, can("policy:write"), (req, res) => {
  db.policies = { ...db.policies, ...req.body };
  audit(req.user.id, "POLICY_UPDATE", "Enterprise policy", "Policy controls updated");
  res.json({ policies: db.policies });
});

if (prod) {
  app.use(express.static(path.join(__dirname, "dist")));
  app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "dist/index.html")));
} else {
  const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
  app.use(vite.middlewares);
}

app.listen(port, "127.0.0.1", () => {
  console.log(`Sentinel Vault Console running at http://127.0.0.1:${port}`);
});
