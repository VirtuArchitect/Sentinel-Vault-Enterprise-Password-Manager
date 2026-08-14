export const roles = {
  SECURITY_ADMIN: ["vault:read", "secret:reveal", "vault:write", "vault:share", "users:read", "policy:write", "audit:read"],
  VAULT_OPERATOR: ["vault:read", "secret:reveal", "vault:write", "vault:share"],
  AUDITOR: ["vault:read", "audit:read", "users:read"]
};

export const hasPermission = (role, permission) => Boolean(roles[role]?.includes(permission));

export const publicUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  role: user.role,
  unit: user.unit,
  mfa: user.mfa,
  enabled: user.enabled !== false,
  permissions: roles[user.role] || []
});
