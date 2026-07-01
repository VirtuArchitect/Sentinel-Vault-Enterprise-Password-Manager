import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

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

const runStoreScript = (sqlitePath, script) => execFileSync(
  process.execPath,
  ["--input-type=module", "-e", script],
  {
    cwd: rootDir,
    env: {
      ...process.env,
      NODE_ENV: "development",
      STORAGE_PROVIDER: "sqlite",
      SQLITE_PATH: sqlitePath,
      VAULT_ROOT_KEY: "sqlite-test-root-key"
    },
    encoding: "utf8"
  }
);

test("sqlite store persists normalized state across processes", { skip: !hasNodeSqlite() && "node:sqlite is unavailable in this runtime" }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-sqlite-"));
  const sqlitePath = path.join(dir, "sentinel.sqlite");
  try {
    runStoreScript(sqlitePath, `
      const { store } = await import("./src/server/data/store.mjs");
      store.state.vaults.unshift({
        id: "v-sqlite",
        tenantId: "t1",
        name: "SQLite Persistence",
        classification: "SECRET",
        ownerUnit: "Storage",
        members: ["u1"],
        health: 100
      });
      store.save();
      console.log(JSON.stringify(store.getStorageStatus()));
    `);

    const output = runStoreScript(sqlitePath, `
      const { store } = await import("./src/server/data/store.mjs");
      console.log(JSON.stringify({
        mode: store.getStorageStatus().mode,
        exists: store.getStorageStatus().exists,
        vault: store.findVaultById("v-sqlite")
      }));
    `);

    const result = JSON.parse(output.trim());
    assert.equal(result.mode, "sqlite");
    assert.equal(result.exists, true);
    assert.equal(result.vault.name, "SQLite Persistence");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
