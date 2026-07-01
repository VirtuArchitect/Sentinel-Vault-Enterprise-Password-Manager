import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const require = createRequire(import.meta.url);

try {
  require("node:sqlite");
} catch {
  console.error("SQLite test mode requires a Node.js runtime with node:sqlite support. Use Node.js 24+.");
  process.exit(1);
}

const sqlitePath = process.env.SQLITE_PATH || path.join(tmpdir(), `sentinel-vault-test-${process.pid}.sqlite`);
const rootDir = path.resolve(import.meta.dirname, "..");
const testFiles = readdirSync(path.join(rootDir, "tests"))
  .filter((file) => file.endsWith(".test.mjs"))
  .sort()
  .map((file) => path.join("tests", file));

const result = spawnSync(process.execPath, ["--test", ...testFiles], {
  cwd: rootDir,
  env: {
    ...process.env,
    STORAGE_PROVIDER: "sqlite",
    SQLITE_PATH: sqlitePath
  },
  stdio: "inherit",
  windowsHide: true
});

rmSync(sqlitePath, { force: true });
rmSync(`${sqlitePath}-wal`, { force: true });
rmSync(`${sqlitePath}-shm`, { force: true });

process.exit(result.status ?? 1);
