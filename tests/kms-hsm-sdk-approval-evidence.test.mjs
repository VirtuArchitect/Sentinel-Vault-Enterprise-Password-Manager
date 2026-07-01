import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-kms-hsm-sdk-approval-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-kms-hsm-sdk-approval-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("kms hsm sdk approval template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "kms-hsm-sdk-approval-evidence.json")), /validated/);
});

test("kms hsm sdk approval generator creates approved evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-kms-sdk-approval-"));
  try {
    const packagePath = path.join(dir, "provider-sdk.tgz");
    const preflightPath = path.join(dir, "kms-hsm-gateway-preflight.json");
    const providerEvidencePath = path.join(dir, "kms-hsm-provider-evidence.json");
    const reportPath = path.join(dir, "sdk-approval-report.json");
    const evidencePath = path.join(dir, "kms-hsm-sdk-approval-evidence.json");
    writeFileSync(packagePath, "provider sdk package fixture");
    writeFileSync(preflightPath, JSON.stringify({
      format: "sentinel-kms-hsm-gateway-preflight-v1",
      provider: "external-kms",
      keyId: "sentinel-key-2026-07",
      checks: {
        keyExportDisabled: true,
        auditLoggingEnabled: true
      }
    }, null, 2));
    writeFileSync(providerEvidencePath, JSON.stringify({
      format: "sentinel-kms-hsm-provider-evidence-v1",
      provider: "external-kms",
      keyId: "sentinel-key-2026-07",
      region: "eu-west-1",
      serviceIdentity: "sentinel-vault-prod",
      keyExportDisabled: true,
      auditLoggingEnabled: true
    }, null, 2));
    writeFileSync(reportPath, JSON.stringify({
      provider: "external-kms",
      environment: "pilot",
      sdk: {
        packageName: "@example/kms-sdk",
        packageVersion: "3.2.1",
        license: "MIT",
        registry: "npmjs",
        packagePath,
        maintenanceStatus: "passed",
        supplyChainReview: "passed",
        securityReview: "passed",
        approvalReference: "SEC-2001"
      },
      targetEnvironment: {
        providerTenant: "example-prod-tenant",
        networkIsolation: "passed",
        auditSinkConfigured: "passed",
        breakGlassProcedure: "passed"
      },
      operationProof: {
        signOrUnwrapOperation: "passed",
        rollbackTested: "passed"
      },
      approvals: {
        securityArchitectureOwner: "Security Architect",
        platformOwner: "Platform Owner",
        releaseOwner: "Release Owner",
        changeTicket: "CHG-2001"
      }
    }, null, 2));

    assert.match(runGenerator([
      "--status", "approved",
      "--report", reportPath,
      "--preflight", preflightPath,
      "--provider-evidence", providerEvidencePath,
      "--out", evidencePath
    ]), /written/);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.sdk.packageSha256, hash("provider sdk package fixture"));
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("kms hsm sdk approval validator rejects provider token leakage", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-kms-sdk-approval-fail-"));
  try {
    const preflightPath = path.join(dir, "preflight.json");
    const providerEvidencePath = path.join(dir, "provider.json");
    const evidencePath = path.join(dir, "approval.json");
    writeFileSync(preflightPath, "{}");
    writeFileSync(providerEvidencePath, "{}");
    writeFileSync(evidencePath, JSON.stringify({
      format: "sentinel-kms-hsm-sdk-approval-evidence-v1",
      status: "approved",
      environment: "pilot",
      provider: "external-kms",
      sdk: {
        packageName: "@example/kms-sdk",
        packageVersion: "3.2.1",
        license: "MIT",
        registry: "npmjs",
        packageSha256: hash("provider sdk package fixture"),
        maintenanceStatus: "passed",
        supplyChainReview: "passed",
        securityReview: "passed",
        approvalReference: "SEC-2001"
      },
      targetEnvironment: {
        providerTenant: "example-prod-tenant",
        region: "eu-west-1",
        keyId: "sentinel-key-2026-07",
        serviceIdentity: "sentinel-vault-prod",
        networkIsolation: "passed",
        auditSinkConfigured: "passed",
        breakGlassProcedure: "passed"
      },
      operationProof: {
        preflightPath,
        providerEvidencePath,
        signOrUnwrapOperation: "passed",
        keyExportBlocked: "passed",
        auditEventCaptured: "passed",
        rollbackTested: "passed"
      },
      approvals: {
        securityArchitectureOwner: "Security Architect",
        platformOwner: "Platform Owner",
        releaseOwner: "Release Owner",
        changeTicket: "CHG-2001"
      },
      redaction: {
        containsCredentials: false,
        containsKeyMaterial: false,
        containsProviderTokens: true,
        containsConnectionStrings: false
      }
    }, null, 2));

    assert.throws(() => runValidator(evidencePath), /provider tokens/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
