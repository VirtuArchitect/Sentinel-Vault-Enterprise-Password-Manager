export type Role = "SECURITY_ADMIN" | "VAULT_OPERATOR" | "AUDITOR";

export type UserRecord = {
  id: string;
  name: string;
  email: string;
  role: Role;
  unit: string;
  mfa: boolean;
  enabled: boolean;
  permissions: string[];
};

export type VaultRecord = {
  id: string;
  name: string;
  classification: string;
  ownerUnit: string;
  members: string[];
  health: number;
};

export type Secret = {
  id: string;
  vaultId: string;
  type: string;
  name: string;
  username: string;
  url: string;
  tags: string[];
  risk: string;
  rotatedAt: string;
  sharedWith: string[];
  approvalsRequired: boolean;
  notes: string;
  strength: number;
  deletedAt: string | null;
  history: SecretVersion[];
};

export type SecretVersion = {
  index: number;
  rotatedAt: string;
  rotatedBy: string;
  rotatedByName: string;
};

export type AuditEvent = {
  id: string;
  ts: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
  source: string;
  outcome: string;
};

export type Policies = {
  rotationDays: number;
  minimumLength: number;
  mfaRequired: boolean;
  justInTimeAccess: boolean;
  breakGlassApproval: string;
  clipboardTtl: number;
  sessionMinutes: number;
};

export type ConsoleData = {
  user: UserRecord;
  users: UserRecord[];
  vaults: VaultRecord[];
  secrets: Secret[];
  deletedSecrets: Secret[];
  policies: Policies;
  identity: IdentityStatus;
  session: SessionStatus;
  crypto: CryptoStatus;
  integrations: IntegrationStatus;
  storage: StorageStatus;
  auditIntegrity: AuditIntegrity;
  audit: AuditEvent[];
  accessRequests: AccessRequest[];
  metrics: {
    secrets: number;
    vaults: number;
    stale: number;
    highRisk: number;
    reused: number;
    deleted: number;
    pendingRequests: number;
  };
};

export type StorageStatus = {
  mode: string;
  statePath: string;
  stateVersion: number;
  exists: boolean;
  backups: Array<{ file: string; size: number; createdAt: string; verified?: boolean; verificationReason?: string | null; sha256?: string | null }>;
};

export type AuditIntegrity = {
  verified: boolean;
  checked: number;
  brokenAt: string | null;
  reason?: string;
};

export type SessionStatus = {
  activeSessions: number;
  ttlMinutes: number;
  reviewable: number;
};

export type IntegrationStatus = {
  siem: { configured: boolean; mode: string; webhookUrl: string; signing: boolean; pending: number; failed: number };
  itsm: { configured: boolean; mode: string; baseUrl: string; ticketPrefixes: string[] };
  devopsApi: { enabled: boolean; mode: string; tokenCount: number };
  outboxDepth: number;
};

export type CryptoStatus = {
  algorithm: string;
  keyDerivation: string;
  keyVersion: string;
  saltConfigured: boolean;
  kmsMode: string;
};

export type IdentityStatus = {
  mode: string;
  name: string;
  configured: boolean;
  issuer: string;
  clientId: string;
  tenantId: string;
  groupClaim: string;
  mfaSource: string;
  roleMapping: Record<Role, string>;
};

export type AddSecret = {
  vaultId: string;
  type: string;
  name: string;
  username: string;
  password: string;
  repeat: string;
  url: string;
  tags: string;
  notes: string;
};

export type PasswordGeneratorOptions = {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  noAmbiguous: boolean;
};

export type AccessRequest = {
  id: string;
  secretId: string;
  secretName: string;
  requesterId: string;
  requesterName: string;
  reason: string;
  status: "pending" | "approved" | "denied" | "revoked";
  requestedAt: string;
  expiresAt: string | null;
  approvedBy: string | null;
  approvedByName: string | null;
  decidedAt: string | null;
  ticketRef: string;
  requestedMinutes: number;
  approvals: string[];
  approvalCount: number;
  requiredApprovals: number;
};
