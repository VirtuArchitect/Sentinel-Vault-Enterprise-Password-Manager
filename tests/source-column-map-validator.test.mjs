import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-source-column-map.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const writeMapping = (mappingPath, overrides = {}) => {
  writeFileSync(mappingPath, JSON.stringify({
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
    ignoredColumns: ["Internal OTP"],
    redaction: {
      evidenceIncludesPasswordValues: false,
      evidenceIncludesOtpValues: false
    },
    ...overrides
  }, null, 2));
};

test("source column map validator records complete proprietary mapping evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-source-map-"));
  try {
    const sourcePath = path.join(dir, "source.csv");
    const mappingPath = path.join(dir, "source-map.json");
    const reportPath = path.join(dir, "source-map-validation.json");
    writeFileSync(sourcePath, [
      "Record Title,Login ID,Secret Value,Endpoint,Folder,Description,Internal OTP",
      "Privileged Console,root,secret,https://console.example.test,Privileged,Emergency admin,otp"
    ].join("\n"));
    writeMapping(mappingPath);

    const result = JSON.parse(runValidator([
      "--mapping", mappingPath,
      "--source", sourcePath,
      "--out", reportPath
    ]));
    const saved = JSON.parse(readFileSync(reportPath, "utf8"));

    assert.equal(result.format, "sentinel-source-column-map-validation-v1");
    assert.equal(result.validated, true);
    assert.equal(result.sourceSystem, "Acme Proprietary Vault");
    assert.equal(result.checks.requiredFieldsPresent, true);
    assert.equal(result.checks.redactionFlagsSafe, true);
    assert.equal(result.checks.allSourceColumnsMappedOrIgnored, true);
    assert.deepEqual(result.findings.unmappedSourceColumns, []);
    assert.ok(result.mappedColumns.includes("Secret Value"));
    assert.ok(result.ignoredColumns.includes("Internal OTP"));
    assert.match(result.mappingSha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(saved, result);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("source column map validator rejects unmapped source columns", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-source-map-fail-"));
  try {
    const sourcePath = path.join(dir, "source.csv");
    const mappingPath = path.join(dir, "source-map.json");
    writeFileSync(sourcePath, "Record Title,Login ID,Secret Value,Endpoint,Folder,Description,Internal OTP,Customer Only\n");
    writeMapping(mappingPath);

    assert.throws(() => runValidator([
      "--mapping", mappingPath,
      "--source", sourcePath
    ]), /source CSV columns must be mapped or explicitly ignored/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("source column map validator rejects unsafe redaction settings", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-source-map-redaction-"));
  try {
    const mappingPath = path.join(dir, "source-map.json");
    writeMapping(mappingPath, {
      redaction: {
        evidenceIncludesPasswordValues: true,
        evidenceIncludesOtpValues: false
      }
    });

    assert.throws(() => runValidator([
      "--mapping", mappingPath
    ]), /evidenceIncludesPasswordValues must be false/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
