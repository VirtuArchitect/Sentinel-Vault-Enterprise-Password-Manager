export type Role = "SECURITY_ADMIN" | "VAULT_OPERATOR" | "AUDITOR";

export type UserRecord = {
  id: string;
  name: string;
  email: string;
  role: Role;
  unit: string;
  mfa: boolean;
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
  policies: Policies;
  identity: IdentityStatus;
  crypto: CryptoStatus;
  integrations: IntegrationStatus;
  audit: AuditEvent[];
  accessRequests: AccessRequest[];
  metrics: {
    secrets: number;
    vaults: number;
    stale: number;
    highRisk: number;
    reused: number;
    pendingRequests: number;
  };
};

export type IntegrationStatus = {
  siem: { configured: boolean; mode: string };
  itsm: { configured: boolean; mode: string };
  devopsApi: { enabled: boolean; mode: string };
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
  status: "pending" | "approved" | "denied";
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
