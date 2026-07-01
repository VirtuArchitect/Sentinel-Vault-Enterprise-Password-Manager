import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("postgres HA approval evidence template validates in planned mode", () => {
  const output = runScript("scripts/validate-postgres-ha-approval-evidence.mjs", [
    "docs/templates/postgres-ha-approval-evidence.json"
  ]);

  assert.match(output, /Postgres HA approval evidence validated/);
});

test("postgres HA generator creates approved evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-postgres-ha-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(dir, { recursive: true });
    const migrationPlanPath = path.join(dir, "postgres-migration-plan.json");
    const storageEvidencePath = path.join(dir, "storage-migration-evidence.json");
    const evidencePath = path.join(dir, "postgres-ha-approval-evidence.json");
    writeFileSync(migrationPlanPath, "{}\n");
    writeFileSync(storageEvidencePath, "{}\n");

    const result = JSON.parse(runScript("scripts/generate-postgres-ha-approval-evidence.mjs", [
      "--status", "approved",
      "--environment", "production",
      "--package-name", "pg",
      "--package-version", "8.13.1",
      "--license", "MIT",
      "--approval-reference", "CHG-12345",
      "--cluster-name", "sentinel-prod-ha",
      "--ha-mode", "multi-az",
      "--migration-plan", migrationPlanPath,
      "--storage-migration-evidence", storageEvidencePath,
      "--maintenance-window", "2026-08-01T22:00:00Z/2026-08-02T01:00:00Z",
      "--platform-data-owner", "Platform Data",
      "--security-reviewer", "Security Architecture",
      "--operations-owner", "Operations",
      "--out", evidencePath
    ]));

    assert.equal(result.format, "sentinel-postgres-ha-approval-evidence-result-v1");
    assert.equal(result.status, "approved");

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.format, "sentinel-postgres-ha-approval-evidence-v1");
    assert.equal(evidence.dependencyApproval.packageName, "pg");

    const validation = runScript("scripts/validate-postgres-ha-approval-evidence.mjs", [evidencePath]);
    assert.match(validation, /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("postgres HA validator rejects leaked connection details in completed evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-postgres-ha-leak-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(dir, { recursive: true });
    const migrationPlanPath = path.join(dir, "postgres-migration-plan.json");
    const storageEvidencePath = path.join(dir, "storage-migration-evidence.json");
    const evidencePath = path.join(dir, "postgres-ha-approval-evidence.json");
    writeFileSync(migrationPlanPath, "{}\n");
    writeFileSync(storageEvidencePath, "{}\n");
    runScript("scripts/generate-postgres-ha-approval-evidence.mjs", [
      "--status", "approved",
      "--environment", "production",
      "--package-name", "pg",
      "--package-version", "8.13.1",
      "--license", "MIT",
      "--approval-reference", "CHG-12345",
      "--cluster-name", "sentinel-prod-ha",
      "--ha-mode", "multi-az",
      "--migration-plan", migrationPlanPath,
      "--storage-migration-evidence", storageEvidencePath,
      "--maintenance-window", "2026-08-01T22:00:00Z/2026-08-02T01:00:00Z",
      "--platform-data-owner", "Platform Data",
      "--security-reviewer", "Security Architecture",
      "--operations-owner", "Operations",
      "--contains-connection-strings", "true",
      "--out", evidencePath
    ]);

    assert.throws(() => runScript("scripts/validate-postgres-ha-approval-evidence.mjs", [
      evidencePath
    ]), /cannot include connection strings/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
