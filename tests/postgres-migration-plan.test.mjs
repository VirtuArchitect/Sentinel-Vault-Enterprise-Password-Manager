import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createSeedState } from "../src/server/data/seedData.mjs";

const rootDir = path.resolve(import.meta.dirname, "..");

const persistedSeed = () => {
  const { sessions: _sessions, loginFailures: _loginFailures, ...state } = createSeedState();
  return { ...state, metadata: { version: 2, savedAt: new Date().toISOString() } };
};

const runPlan = (statePath, outputPath) => execFileSync(process.execPath, [
  "scripts/plan-postgres-migration.mjs",
  "--state", statePath,
  "--out", outputPath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("postgres migration planner validates source state and schema", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-postgres-plan-"));
  try {
    const statePath = path.join(dir, "state.json");
    const outputPath = path.join(dir, "postgres-plan.json");
    writeFileSync(statePath, JSON.stringify(persistedSeed(), null, 2));

    runPlan(statePath, outputPath);
    const plan = JSON.parse(readFileSync(outputPath, "utf8"));

    assert.equal(plan.format, "sentinel-postgres-migration-plan-v1");
    assert.equal(plan.checks.schemaTablesPresent, true);
    assert.equal(plan.checks.schemaIndexesPresent, true);
    assert.equal(plan.checks.driverDependencyDeferred, true);
    assert.equal(plan.migrationTables.includes("sentinel_state"), true);
    assert.equal(plan.counts.secrets, 3);
    assert.ok(plan.cutoverSteps.some((step) => step.includes("STORAGE_PROVIDER=postgres")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("postgres migration planner rejects plaintext source secrets", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-postgres-plan-fail-"));
  try {
    const state = persistedSeed();
    state.secrets[0].password = "plaintext";
    const statePath = path.join(dir, "state.json");
    const outputPath = path.join(dir, "postgres-plan.json");
    writeFileSync(statePath, JSON.stringify(state, null, 2));

    assert.throws(() => runPlan(statePath, outputPath), /plaintextSecretsAbsent/);
    const plan = JSON.parse(readFileSync(outputPath, "utf8"));
    assert.equal(plan.checks.plaintextSecretsAbsent, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
