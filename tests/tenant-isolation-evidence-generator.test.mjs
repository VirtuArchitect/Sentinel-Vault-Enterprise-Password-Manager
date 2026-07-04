import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-tenant-isolation-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-tenant-isolation-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const negativeTestNames = [
  "reveal",
  "update",
  "delete",
  "restore",
  "versionRestore",
  "rotate",
  "share",
  "approveAccess",
  "denyAccess",
  "revokeAccess",
  "consoleVaultEnumeration",
  "offlineCacheEnumeration"
];

const writeReport = (filePath, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    testedAt: "2026-07-01T10:00:00Z",
    scope: {
      tenantCount: 3,
      vaultCount: 6,
      userCount: 12,
      sampledTenantPairs: 4,
      testCadence: "per-release"
    },
    negativeTests: negativeTestNames.map((name) => ({ name, outcome: "blocked" })),
    ...extra
  }, null, 2));
};

test("tenant isolation generator summarizes planned negative-test evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tenant-isolation-generator-"));
  try {
    const reportPath = path.join(dir, "tenant-isolation-tests.json");
    const evidencePath = path.join(dir, "tenant-isolation.json");
    writeReport(reportPath);

    assert.match(runGenerator([
      "--report", reportPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /Tenant isolation evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.testedAt, "2026-07-01T10:00:00Z");
    assert.equal(evidence.scope.tenantCount, 3);
    assert.equal(evidence.scope.sampledTenantPairs, 4);
    assert.equal(evidence.testReport.validated, true);
    assert.deepEqual(evidence.testReport.scope, evidence.scope);
    assert.equal(evidence.testReport.negativeTests.share, "passed");
    assert.equal(evidence.negativeTests.reveal, "passed");
    assert.equal(evidence.negativeTests.offlineCacheEnumeration, "passed");
    assert.equal(evidence.redaction.secretValuesFound, false);
    assert.equal(evidence.redaction.sessionTokensFound, false);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tenant isolation validator rejects production evidence with mismatched test report scope", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tenant-isolation-scope-drift-"));
  try {
    const reportPath = path.join(dir, "tenant-isolation-tests.json");
    const evidencePath = path.join(dir, "tenant-isolation.json");
    writeReport(reportPath);

    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--report", reportPath,
      "--service-layer-object-checks", "passed",
      "--route-rbac-checks", "passed",
      "--console-payload-filtering", "passed",
      "--offline-cache-scoping", "passed",
      "--admin-metadata-export-restricted", "passed",
      "--jit-grant-tenant-boundary", "passed",
      "--tenant-identifiers-scoped", "passed",
      "--security-reviewer", "Security Reviewer",
      "--operations-owner", "Operations Owner",
      "--change-ticket", "CHG-93001",
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    evidence.testReport.scope.tenantCount = 2;
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /testReport\.scope\.tenantCount must match/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tenant isolation generator flags leaked secrets and session tokens", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tenant-isolation-leak-generator-"));
  try {
    const reportPath = path.join(dir, "tenant-isolation-tests.json");
    const samplesPath = path.join(dir, "samples.log");
    const evidencePath = path.join(dir, "tenant-isolation.json");
    writeReport(reportPath);
    writeFileSync(samplesPath, [
      "secretValue=",
      "sampleSecretValue123",
      "\nsession_token=",
      "sampleSessionValue456"
    ].join(""));

    runGenerator([
      "--report", reportPath,
      "--samples", samplesPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.secretValuesFound, true);
    assert.equal(evidence.redaction.sessionTokensFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tenant isolation generator creates production evidence from supplied controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tenant-isolation-production-generator-"));
  try {
    const reportPath = path.join(dir, "tenant-isolation-tests.json");
    const evidencePath = path.join(dir, "tenant-isolation.json");
    writeReport(reportPath);

    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--report", reportPath,
      "--service-layer-object-checks", "passed",
      "--route-rbac-checks", "passed",
      "--console-payload-filtering", "passed",
      "--offline-cache-scoping", "passed",
      "--admin-metadata-export-restricted", "passed",
      "--jit-grant-tenant-boundary", "passed",
      "--tenant-identifiers-scoped", "passed",
      "--security-reviewer", "Security Reviewer",
      "--operations-owner", "Operations Owner",
      "--change-ticket", "CHG-93001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
