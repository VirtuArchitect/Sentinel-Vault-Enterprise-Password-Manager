import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (args = []) => execFileSync(process.execPath, [
  "scripts/validate-postgres-schema.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("postgres schema validator records schema shape evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-postgres-schema-"));
  try {
    const reportPath = path.join(dir, "postgres-schema-validation.json");
    const output = runValidator(["--out", reportPath]);
    const result = JSON.parse(output);
    const saved = JSON.parse(readFileSync(reportPath, "utf8"));

    assert.equal(result.format, "sentinel-postgres-schema-validation-v1");
    assert.equal(result.validated, true);
    assert.equal(result.requiredTableCount, 13);
    assert.equal(result.requiredIndexCount, 9);
    assert.equal(result.checks.transactionWrapped, true);
    assert.equal(result.checks.schemaMigrationRecorded, true);
    assert.equal(result.checks.noDatabaseUrlPlaceholders, true);
    assert.match(result.schemaSha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(saved, result);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("postgres schema validator rejects missing required schema objects", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-postgres-schema-fail-"));
  try {
    const schemaPath = path.join(dir, "postgres-schema.sql");
    copyFileSync(path.join(rootDir, "docs", "architecture", "postgres-schema.sql"), schemaPath);
    const schema = readFileSync(schemaPath, "utf8").replace(/CREATE TABLE IF NOT EXISTS audit_events[\s\S]*?CREATE TABLE IF NOT EXISTS policies/i, "CREATE TABLE IF NOT EXISTS policies");
    writeFileSync(schemaPath, schema);

    assert.throws(() => runValidator(["--schema", schemaPath]), /jsonbMirrorTablesPresent/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
