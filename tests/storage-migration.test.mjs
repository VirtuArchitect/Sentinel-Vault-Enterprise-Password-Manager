import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createSeedState } from "../src/server/data/seedData.mjs";

const rootDir = path.resolve(import.meta.dirname, "..");
const require = createRequire(import.meta.url);

const hasNodeSqlite = () => {
  try {
    require("node:sqlite");
    return true;
  } catch {
    return false;
  }
};

const runNode = (args) => execFileSync(process.execPath, args, {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
  env: { ...process.env, NODE_ENV: "test", VAULT_ROOT_KEY: "storage-migration-test-root-key" }
});

const createPersistedSeedState = () => {
  const { sessions: _sessions, loginFailures: _loginFailures, ...state } = createSeedState();
  return state;
};

test("storage inspector fails incomplete state before migration", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-storage-inspect-"));
  try {
    const statePath = path.join(dir, "state.json");
    const evidencePath = path.join(dir, "evidence.json");
    const state = createPersistedSeedState();
    delete state.secretImports;
    writeFileSync(statePath, JSON.stringify(state, null, 2));

    assert.throws(
      () => runNode(["scripts/inspect-storage-state.mjs", "--state", statePath, "--out", evidencePath]),
      /requiredCollectionsPresent/
    );
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.checks.requiredCollectionsPresent, false);
    assert.deepEqual(evidence.findings.missingCollections, ["secretImports"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("json to sqlite migration writes readiness evidence and relational mirror tables", { skip: !hasNodeSqlite() && "node:sqlite is unavailable in this runtime" }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-storage-migrate-"));
  try {
    const statePath = path.join(dir, "state.json");
    const sqlitePath = path.join(dir, "sentinel.sqlite");
    const evidencePath = path.join(dir, "sqlite-evidence.json");
    writeFileSync(statePath, JSON.stringify(createPersistedSeedState(), null, 2));

    runNode([
      "scripts/migrate-json-to-sqlite.mjs",
      "--state", statePath,
      "--sqlite", sqlitePath,
      "--evidence", evidencePath
    ]);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.format, "sentinel-json-to-sqlite-migration-evidence-v1");
    assert.equal(evidence.checks.requiredCollectionsPresent, true);
    assert.equal(evidence.checks.transientCollectionsExcluded, true);
    assert.equal(evidence.counts.secrets, 3);

    const { DatabaseSync } = require("node:sqlite");
    const db = new DatabaseSync(sqlitePath);
    try {
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM sentinel_state").get().count, 1);
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM secrets").get().count, 3);
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM vaults WHERE tenant_id IS NOT NULL").get().count, 3);
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM policies WHERE id = 'main'").get().count, 1);
    } finally {
      db.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
