import { store } from "../data/store.mjs";
import { getCryptoStatus } from "../crypto/vaultCrypto.mjs";
import { getIdentityStatus } from "./identityService.mjs";
import { getIntegrationStatus } from "./integrationService.mjs";
import { getSecretHealthReport } from "./vaultService.mjs";

const evidence = (control, status, detail) => ({ control, status, detail });

export const getComplianceReport = () => {
  const crypto = getCryptoStatus();
  const identity = getIdentityStatus();
  const integrations = getIntegrationStatus();
  const health = getSecretHealthReport();
  const stale = health.filter((secret) => secret.stale).length;
  const reused = health.filter((secret) => secret.reused).length;
  const auditEvents = store.state.audit.length;

  const controls = [
    evidence("encryption_at_rest", "implemented", `${crypto.algorithm} with ${crypto.keyDerivation} and key version ${crypto.keyVersion}`),
    evidence("identity_provider", identity.configured ? "implemented" : "partial", `${identity.name} mode`),
    evidence("mfa_policy", store.state.policies.mfaRequired ? "implemented" : "partial", "MFA policy flag is enabled"),
    evidence("least_privilege", "implemented", "RBAC and object-level vault checks are enforced in service methods"),
    evidence("jit_access", store.state.policies.justInTimeAccess ? "implemented" : "partial", `${store.state.accessRequests.length} access request records`),
    evidence("audit_logging", auditEvents > 0 ? "implemented" : "partial", `${auditEvents} audit events retained`),
    evidence("secret_rotation", stale === 0 ? "implemented" : "attention", `${stale} stale secrets against ${store.state.policies.rotationDays} day policy`),
    evidence("reuse_prevention", reused === 0 ? "implemented" : "attention", `${reused} reused secrets detected`),
    evidence("siem_export", integrations.siem.configured ? "implemented" : "partial", `SIEM mode: ${integrations.siem.mode}`)
  ];

  return {
    generatedAt: new Date().toISOString(),
    standards: ["ISO/IEC 27001", "NIS2", "SOC 2", "PCI DSS"],
    summary: {
      implemented: controls.filter((control) => control.status === "implemented").length,
      partial: controls.filter((control) => control.status === "partial").length,
      attention: controls.filter((control) => control.status === "attention").length
    },
    controls
  };
};

export const getComplianceEvidencePack = () => {
  const report = getComplianceReport();
  return {
    ...report,
    evidence: {
      auditSample: store.state.audit.slice(0, 25),
      policySnapshot: store.state.policies,
      accessRequests: store.state.accessRequests.slice(0, 25),
      generatedBy: "Sentinel Vault compliance reporter"
    }
  };
};
