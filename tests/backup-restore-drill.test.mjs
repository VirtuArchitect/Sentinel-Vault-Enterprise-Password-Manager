import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createSeedState } from "../src/server/data/seedData.mjs";

const rootDir = path.resolve(import.meta.dirname, "..");
const rootKey = "restore-drill-test-root-key";
const backupKey = () => crypto.createHash("sha256").update(rootKey, "utf8").digest();
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("base64url");

const persistedSeed = () => {
  const { sessions: _sessions, loginFailures: _loginFailures, ...state } = createSeedState();
  return { ...state, metadata: { version: 3, savedAt: new Date().toISOString() } };
};

const writeEncryptedBackup = (dir, state = persistedSeed()) => {
  const backupPath = path.join(dir, "sentinel-state-test.json.enc");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", backupKey(), iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(state), "utf8")), cipher.final()]);
  writeFileSync(backupPath, encrypted);
  const manifest = {
    file: path.basename(backupPath),
    sha256: sha256(encrypted),
    createdAt: new Date().toISOString(),
    algorithm: "AES-256-GCM",
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url")
  };
  writeFileSync(`${backupPath}.sha256.json`, JSON.stringify(manifest, null, 2));
  return backupPath;
};

const runRestoreDrill = (backupPath, evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-encrypted-backup-restore.mjs",
  "--backup", backupPath,
  "--out", evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
  env: { ...process.env, VAULT_ROOT_KEY: rootKey }
});

test("encrypted backup restore drill validates checksum, decrypts, and writes evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-restore-drill-"));
  try {
    const backupPath = writeEncryptedBackup(dir);
    const evidencePath = path.join(dir, "evidence.json");
    runRestoreDrill(backupPath, evidencePath);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.format, "sentinel-encrypted-backup-restore-drill-v1");
    assert.equal(evidence.restoreMode, "dry-run");
    assert.equal(evidence.checks.checksumVerified, true);
    assert.equal(evidence.checks.decryptedAndParsed, true);
    assert.equal(evidence.checks.requiredCollectionsPresent, true);
    assert.equal(evidence.counts.secrets, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("encrypted backup restore drill rejects tampered encrypted backup", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-restore-drill-fail-"));
  try {
    const backupPath = writeEncryptedBackup(dir);
    const encrypted = readFileSync(backupPath);
    encrypted[0] = encrypted[0] ^ 0xff;
    writeFileSync(backupPath, encrypted);
    const evidencePath = path.join(dir, "evidence.json");

    assert.throws(() => runRestoreDrill(backupPath, evidencePath), /restore drill failed/);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.checks.checksumVerified, false);
    assert.equal(evidence.checks.decryptedAndParsed, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
