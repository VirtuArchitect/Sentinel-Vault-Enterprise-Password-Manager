import crypto from "node:crypto";
import { hashPassword } from "../crypto/passwords.mjs";
import { encryptSecret } from "../crypto/vaultCrypto.mjs";

const seededPassword = "Passw0rd!";

const userSeeds = [
  ["u1", "Commander Ada", "ada@defence.local", "SECURITY_ADMIN", "Strategic Systems"],
  ["u2", "Morgan Vale", "morgan@defence.local", "VAULT_OPERATOR", "Cyber Operations"],
  ["u3", "Iris Chen", "iris@defence.local", "AUDITOR", "Assurance"]
];

const seedSecret = (secret) => ({ ...secret, encrypted: encryptSecret(secret.password), password: undefined });

export const createSeedState = () => ({
  users: userSeeds.map(([id, name, email, role, unit]) => ({ id, name, email, role, unit, mfa: true, ...hashPassword(seededPassword) })),
  sessions: new Map(),
  vaults: [
    { id: "v1", name: "Mission Systems", classification: "SECRET", ownerUnit: "Strategic Systems", members: ["u1", "u2"], health: 98 },
    { id: "v2", name: "Identity Backbone", classification: "TOP SECRET", ownerUnit: "Cyber Operations", members: ["u1", "u2", "u3"], health: 93 },
    { id: "v3", name: "Supplier Access", classification: "OFFICIAL-SENSITIVE", ownerUnit: "Assurance", members: ["u1", "u3"], health: 89 }
  ],
  secrets: [
    seedSecret({ id: "s1", vaultId: "v1", name: "Satellite Telemetry API", username: "svc_telemetry", password: "E7#hP9!qZ2@Lw8$mV4", url: "https://telemetry.defence.local", tags: ["api", "mission"], risk: "low", rotatedAt: "2026-06-21T09:30:00Z", sharedWith: ["u2"] }),
    seedSecret({ id: "s2", vaultId: "v2", name: "Privileged Directory Root", username: "adm.root", password: "nK5!vD8@xR2#tY6$pB", url: "ldaps://identity.defence.local", tags: ["identity", "tier-0"], risk: "high", rotatedAt: "2026-06-14T13:10:00Z", sharedWith: ["u1"] }),
    seedSecret({ id: "s3", vaultId: "v3", name: "Secure Build Registry", username: "robot.deploy", password: "Q4$pL7#cN1@zV9!eH", url: "https://registry.defence.local", tags: ["devsecops"], risk: "medium", rotatedAt: "2026-06-24T06:45:00Z", sharedWith: ["u3"] })
  ],
  audit: [
    { id: crypto.randomUUID(), ts: "2026-06-27T07:42:00Z", actor: "Iris Chen", action: "EXPORT_REVIEW", target: "Audit evidence pack", detail: "Quarterly compliance export opened", source: "10.20.4.18", outcome: "allowed" },
    { id: crypto.randomUUID(), ts: "2026-06-26T17:10:00Z", actor: "Morgan Vale", action: "ROTATE_SECRET", target: "Secure Build Registry", detail: "Automated rotation completed", source: "10.20.9.42", outcome: "allowed" },
    { id: crypto.randomUUID(), ts: "2026-06-26T11:02:00Z", actor: "Commander Ada", action: "POLICY_UPDATE", target: "Session timeout", detail: "Changed from 30 to 15 minutes", source: "10.20.1.7", outcome: "allowed" }
  ],
  policies: {
    rotationDays: 45,
    minimumLength: 20,
    mfaRequired: true,
    justInTimeAccess: true,
    breakGlassApproval: "Two-person integrity",
    clipboardTtl: 30,
    sessionMinutes: 15
  }
});
