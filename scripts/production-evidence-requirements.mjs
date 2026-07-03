export const productionEvidenceRequirements = Object.freeze({
  connector: "certified",
  itsmWorkNotes: "production",
  siemReceiverRotation: "certified",
  windowsSigning: "signed",
  browserIdentity: "production",
  browserRollout: "production",
  nativeCompanion: "production",
  credentialProviderApproval: "approved",
  kmsHsm: "active",
  kmsHsmSdkApproval: "approved",
  sourceMigration: "production",
  tenantIsolation: "production",
  postgresHa: "approved"
});

export const productionEvidenceRequirementEntries = Object.freeze(Object.entries(productionEvidenceRequirements));

