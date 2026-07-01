import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-tenant-isolation-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "tenant-isolation-evidence.json"), "utf8"));

const productionEvidence = () => {
  const evidence = template();
  evidence.status = "production";
  evidence.environment = "prod";
  evidence.testedAt = "2026-07-01T10:00:00Z";
  evidence.scope = {
    tenantCount: 3,
    vaultCount: 8,
    userCount: 24,
    sampledTenantPairs: 4,
    testCadence: "per-release"
  };
  evidence.controls = {
    serviceLayerObjectChecks: "passed",
    routeRbacChecks: "passed",
    consolePayloadFiltering: "passed",
    offlineCacheScoping: "passed",
    adminMetadataExportRestricted: "passed",
    jitGrantTenantBoundary: "passed"
  };
  evidence.negativeTests = {
    reveal: "passed",
    update: "passed",
    delete: "passed",
    restore: "passed",
    versionRestore: "passed",
    rotate: "passed",
    share: "passed",
    approveAccess: "passed",
    denyAccess: "passed",
    revokeAccess: "passed",
    consoleVaultEnumeration: "passed",
    offlineCacheEnumeration: "passed"
  };
  evidence.redaction = {
    secretValuesFound: false,
    sessionTokensFound: false,
    tenantIdentifiersScoped: "passed"
  };
  evidence.approvals = {
    securityReviewer: "Security Reviewer",
    operationsOwner: "Operations Owner",
    changeTicket: "CHG-90002"
  };
  return evidence;
};

test("tenant isolation evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "tenant-isolation-evidence.json")), /validated/);
});

test("production tenant isolation evidence validates controls and negative tests", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tenant-isolation-"));
  try {
    const evidencePath = path.join(dir, "tenant-isolation.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production tenant isolation evidence rejects failed negative tests", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tenant-isolation-failed-"));
  try {
    const evidence = productionEvidence();
    evidence.negativeTests.share = "failed";
    const evidencePath = path.join(dir, "tenant-isolation.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /share negative test/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production tenant isolation evidence rejects leaked secret values", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tenant-isolation-leak-"));
  try {
    const evidence = productionEvidence();
    evidence.redaction.secretValuesFound = true;
    const evidencePath = path.join(dir, "tenant-isolation.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /secret values/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
