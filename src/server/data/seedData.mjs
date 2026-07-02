import crypto from "node:crypto";
import { hashPassword } from "../crypto/passwords.mjs";
import { encryptSecret, fingerprintSecret } from "../crypto/vaultCrypto.mjs";

const seededPassword = "Passw0rd!";

const userSeeds = [
  { id: "u1", name: "Avery Stone", email: "avery.stone@enterprise.example", role: "SECURITY_ADMIN", unit: "Platform Security" },
  { id: "u2", name: "Morgan Vale", email: "morgan.vale@enterprise.example", role: "VAULT_OPERATOR", unit: "Cloud Operations" },
  { id: "u3", name: "Iris Chen", email: "iris.chen@enterprise.example", role: "AUDITOR", unit: "Risk and Compliance" }
];

const seedSecret = (secret) => ({
  type: "password",
  notes: "",
  history: [],
  approvalsRequired: secret.risk === "high",
  ...secret,
  encrypted: encryptSecret(secret.password),
  fingerprint: fingerprintSecret(secret.password),
  password: undefined
});

export const createSeedState = () => ({
  users: userSeeds.map((user) => ({ ...user, mfa: true, ...hashPassword(seededPassword) })),
  sessions: new Map(),
  refreshTokens: [],
  deviceInventory: [],
  loginFailures: new Map(),
  tenants: [
    { id: "t1", name: "Enterprise Group", parentId: null, classification: "CONFIDENTIAL", ownerUnit: "Platform Security" },
    { id: "t2", name: "Cloud Operations", parentId: "t1", classification: "RESTRICTED", ownerUnit: "Cloud Operations" },
    { id: "t3", name: "Risk and Compliance", parentId: "t1", classification: "INTERNAL", ownerUnit: "Risk and Compliance" }
  ],
  vaults: [
    { id: "v1", tenantId: "t1", name: "Production Platforms", classification: "CONFIDENTIAL", ownerUnit: "Platform Security", members: ["u1", "u2"], health: 98 },
    { id: "v2", tenantId: "t2", name: "Identity and Access", classification: "RESTRICTED", ownerUnit: "Cloud Operations", members: ["u1", "u2", "u3"], health: 93 },
    { id: "v3", tenantId: "t3", name: "Supplier Access", classification: "INTERNAL", ownerUnit: "Risk and Compliance", members: ["u1", "u3"], health: 89 }
  ],
  secrets: [
    seedSecret({ id: "s1", vaultId: "v1", type: "api_key", name: "Customer Analytics API", username: "svc_analytics", password: "E7#hP9!qZ2@Lw8$mV4", url: "https://analytics.enterprise.example", tags: ["api", "customer-platform"], risk: "low", rotatedAt: "2026-06-21T09:30:00Z", sharedWith: ["u2"], notes: "Runtime API credential for analytics ingestion." }),
    seedSecret({ id: "s2", vaultId: "v2", type: "directory_account", name: "Privileged Identity Admin", username: "adm.identity", password: "nK5!vD8@xR2#tY6$pB", url: "ldaps://identity.enterprise.example", tags: ["identity", "tier-0"], risk: "high", rotatedAt: "2026-06-14T13:10:00Z", sharedWith: ["u1"], notes: "Tier-0 identity administration credential.", approvalsRequired: true }),
    seedSecret({ id: "s3", vaultId: "v3", type: "registry_token", name: "Secure Build Registry", username: "robot.deploy", password: "Q4$pL7#cN1@zV9!eH", url: "https://registry.enterprise.example", tags: ["devsecops"], risk: "medium", rotatedAt: "2026-06-24T06:45:00Z", sharedWith: ["u3"], notes: "CI/CD deployment token." })
  ],
  serviceTokens: [],
  secretImports: [],
  accessRequests: [
    {
      id: "ar1",
      secretId: "s2",
      requesterId: "u2",
      reason: "Emergency identity backbone maintenance window",
      status: "pending",
      requestedAt: "2026-06-27T08:15:00Z",
      expiresAt: null,
      approvedBy: null,
      decidedAt: null,
      ticketRef: "INC-2026-0627",
      requestedMinutes: 30,
      approvals: [],
      requiredApprovals: 2
    }
  ],
  integrationOutbox: [],
  audit: [
    { id: crypto.randomUUID(), ts: "2026-06-27T07:42:00Z", actor: "Iris Chen", action: "EXPORT_REVIEW", target: "Audit evidence pack", detail: "Quarterly compliance export opened", source: "10.20.4.18", outcome: "allowed" },
    { id: crypto.randomUUID(), ts: "2026-06-26T17:10:00Z", actor: "Morgan Vale", action: "ROTATE_SECRET", target: "Secure Build Registry", detail: "Automated rotation completed", source: "10.20.9.42", outcome: "allowed" },
    { id: crypto.randomUUID(), ts: "2026-06-26T11:02:00Z", actor: "Avery Stone", action: "POLICY_UPDATE", target: "Session timeout", detail: "Changed from 30 to 15 minutes", source: "10.20.1.7", outcome: "allowed" }
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
