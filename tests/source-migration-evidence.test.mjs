import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const writeCompletedMigrationFixture = (dir) => {
  mkdirSync(dir, { recursive: true });
  const sourcePath = path.join(dir, "source.csv");
  const columnMapPath = path.join(dir, "column-map.json");
  const normalizedPath = path.join(dir, "normalized.csv");
  const adapterEvidencePath = path.join(dir, "adapter-evidence.json");
  const storageEvidencePath = path.join(dir, "storage-migration-evidence.json");
  const tenantEvidencePath = path.join(dir, "tenant-isolation-evidence.json");

  writeFileSync(sourcePath, [
    "Record Title,Login ID,Secret Value,Endpoint,Folder,Description",
    "Privileged Console,root,Map-Secret-Value,https://console.example.test,Privileged,Emergency admin"
  ].join("\n"));
  writeFileSync(columnMapPath, JSON.stringify({
    format: "sentinel-source-export-column-map-v1",
    sourceSystem: "Acme Proprietary Vault",
    fields: {
      type: { constant: "password" },
      name: { columns: ["Record Title"] },
      username: { columns: ["Login ID"] },
      password: { columns: ["Secret Value"] },
      url: { columns: ["Endpoint"] },
      tags: { columns: ["Folder"], constants: ["migrated"] },
      risk: { constant: "high" },
      notes: { columns: ["Description"] }
    },
    redaction: {
      evidenceIncludesPasswordValues: false,
      evidenceIncludesOtpValues: false
    }
  }, null, 2));
  runScript("scripts/convert-source-export.mjs", [
    "--source", sourcePath,
    "--format", "mapped-csv",
    "--mapping", columnMapPath,
    "--vault-id", "v-import",
    "--out", normalizedPath,
    "--evidence", adapterEvidencePath
  ]);

  copyFileSync(path.join(rootDir, "docs", "templates", "storage-migration-evidence.json"), storageEvidencePath);
  const storage = JSON.parse(readFileSync(storageEvidencePath, "utf8"));
  storage.inspectedAt = "2026-07-01T10:00:00Z";
  storage.stateFile = path.join(dir, "sentinel-state.json");
  storage.stateSha256 = "a".repeat(43);
  storage.counts.users = 2;
  storage.counts.tenants = 2;
  storage.counts.vaults = 2;
  storage.counts.secrets = 1;
  for (const key of Object.keys(storage.checks)) storage.checks[key] = true;
  for (const key of Object.keys(storage.findings)) storage.findings[key] = [];
  writeFileSync(storageEvidencePath, JSON.stringify(storage, null, 2));

  copyFileSync(path.join(rootDir, "docs", "templates", "tenant-isolation-evidence.json"), tenantEvidencePath);
  const tenant = JSON.parse(readFileSync(tenantEvidencePath, "utf8"));
  tenant.status = "pilot";
  tenant.environment = "pilot";
  tenant.testedAt = "2026-07-01T10:00:00Z";
  tenant.scope = {
    tenantCount: 2,
    vaultCount: 2,
    userCount: 2,
    sampledTenantPairs: 1,
    testCadence: "per-release"
  };
  for (const key of Object.keys(tenant.controls)) tenant.controls[key] = "passed";
  for (const key of Object.keys(tenant.negativeTests)) tenant.negativeTests[key] = "passed";
  tenant.redaction = {
    secretValuesFound: false,
    sessionTokensFound: false,
    tenantIdentifiersScoped: "passed"
  };
  tenant.approvals = {
    securityReviewer: "Security",
    operationsOwner: "Operations",
    changeTicket: "CHG-12345"
  };
  writeFileSync(tenantEvidencePath, JSON.stringify(tenant, null, 2));

  return { columnMapPath, normalizedPath, adapterEvidencePath, storageEvidencePath, tenantEvidencePath };
};

test("source migration evidence template validates in planned mode", () => {
  const output = runScript("scripts/validate-source-migration-evidence.mjs", [
    "docs/templates/source-migration-evidence.json"
  ]);

  assert.match(output, /Source migration evidence validated/);
});

test("source migration generator creates deployed evidence from migration artifacts", () => {
  const dir = path.join(tmpdir(), `sentinel-source-migration-${process.pid}-${Date.now()}`);
  try {
    const artifacts = writeCompletedMigrationFixture(dir);
    const evidencePath = path.join(dir, "source-migration-evidence.json");
    const result = JSON.parse(runScript("scripts/generate-source-migration-evidence.mjs", [
      "--status", "pilot",
      "--environment", "pilot",
      "--source-system", "Acme Proprietary Vault",
      "--column-map", artifacts.columnMapPath,
      "--source-adapter-evidence", artifacts.adapterEvidencePath,
      "--normalized-import", artifacts.normalizedPath,
      "--storage-migration-evidence", artifacts.storageEvidencePath,
      "--tenant-isolation-evidence", artifacts.tenantEvidencePath,
      "--migration-owner", "Migration",
      "--security-reviewer", "Security",
      "--operations-owner", "Operations",
      "--change-ticket", "CHG-12345",
      "--out", evidencePath
    ]));

    assert.equal(result.format, "sentinel-source-migration-evidence-result-v1");
    assert.equal(result.convertedRowCount, 1);

    const validation = runScript("scripts/validate-source-migration-evidence.mjs", [evidencePath]);
    assert.match(validation, /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("source migration validator rejects deployed evidence with secret redaction findings", () => {
  const dir = path.join(tmpdir(), `sentinel-source-migration-redaction-${process.pid}-${Date.now()}`);
  try {
    const artifacts = writeCompletedMigrationFixture(dir);
    const evidencePath = path.join(dir, "source-migration-evidence.json");
    runScript("scripts/generate-source-migration-evidence.mjs", [
      "--status", "pilot",
      "--environment", "pilot",
      "--source-system", "Acme Proprietary Vault",
      "--column-map", artifacts.columnMapPath,
      "--source-adapter-evidence", artifacts.adapterEvidencePath,
      "--normalized-import", artifacts.normalizedPath,
      "--storage-migration-evidence", artifacts.storageEvidencePath,
      "--tenant-isolation-evidence", artifacts.tenantEvidencePath,
      "--migration-owner", "Migration",
      "--security-reviewer", "Security",
      "--operations-owner", "Operations",
      "--change-ticket", "CHG-12345",
      "--contains-plaintext-secrets", "true",
      "--out", evidencePath
    ]);

    assert.throws(() => runScript("scripts/validate-source-migration-evidence.mjs", [
      evidencePath
    ]), /cannot contain plaintext secrets/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
