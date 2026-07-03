import test from "node:test";
import assert from "node:assert/strict";
import { productionEvidenceRequirements } from "../scripts/production-evidence-requirements.mjs";

test("production evidence requirements cover final release evidence statuses", () => {
  assert.deepEqual(productionEvidenceRequirements, {
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
});
