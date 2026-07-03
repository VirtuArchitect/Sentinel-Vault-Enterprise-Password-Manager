import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [
  script,
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const writeMapping = (mappingPath) => {
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
    redaction: {
      evidenceIncludesPasswordValues: false,
      evidenceIncludesOtpValues: false
    }
  }, null, 2));
};

test("normalized import validator accepts converted Sentinel CSV and adapter evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-normalized-import-"));
  try {
    const sourcePath = path.join(dir, "source.csv");
    const mappingPath = path.join(dir, "column-map.json");
    const normalizedPath = path.join(dir, "normalized.csv");
    const adapterEvidencePath = path.join(dir, "adapter-evidence.json");
    const reportPath = path.join(dir, "normalized-import-validation.json");
    writeFileSync(sourcePath, [
      "Record Title,Login ID,Secret Value,Endpoint,Folder,Description",
      "Privileged Console,root,Map-Secret-Value,https://console.example.test,Privileged,Emergency admin"
    ].join("\n"));
    writeMapping(mappingPath);

    runScript("scripts/convert-source-export.mjs", [
      "--source", sourcePath,
      "--format", "mapped-csv",
      "--mapping", mappingPath,
      "--vault-id", "v-import",
      "--out", normalizedPath,
      "--evidence", adapterEvidencePath
    ]);

    const result = JSON.parse(runScript("scripts/validate-normalized-import.mjs", [
      "--csv", normalizedPath,
      "--adapter-evidence", adapterEvidencePath,
      "--expected-rows", "1",
      "--out", reportPath
    ]));
    const saved = JSON.parse(readFileSync(reportPath, "utf8"));

    assert.equal(result.format, "sentinel-normalized-import-validation-v1");
    assert.equal(result.validated, true);
    assert.equal(result.rowCount, 1);
    assert.deepEqual(result.vaultIds, ["v-import"]);
    assert.equal(result.passwordValuesIncluded, false);
    assert.ok(result.redactedEntries[0].passwordFingerprint);
    assert.equal(saved.csvSha256, result.csvSha256);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("normalized import validator rejects malformed rows", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-normalized-import-fail-"));
  try {
    const normalizedPath = path.join(dir, "normalized.csv");
    writeFileSync(normalizedPath, [
      "vaultId,type,name,username,password,url,tags,risk,notes",
      "v1,password,Missing Password,svc_missing,,https://example.test,import,medium,empty secret"
    ].join("\n"));

    assert.throws(() => runScript("scripts/validate-normalized-import.mjs", [
      "--csv", normalizedPath
    ]), /missing password/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
