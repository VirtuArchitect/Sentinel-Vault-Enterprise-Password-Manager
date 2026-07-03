import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
const positionals = [];
for (let index = 0; index < cliArgs.length; index += 1) {
  const arg = cliArgs[index];
  if (arg.startsWith("--")) {
    const next = cliArgs[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(arg, true);
    } else {
      args.set(arg, next);
      index += 1;
    }
  } else {
    positionals.push(arg);
  }
}

const csvPath = path.resolve(args.get("--csv") || positionals[0] || "artifacts/import/source-export-normalized.csv");
const evidencePath = args.get("--adapter-evidence") ? path.resolve(args.get("--adapter-evidence")) : null;
const outputPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const expectedRows = args.get("--expected-rows") ? Number(args.get("--expected-rows")) : null;
const requiredHeaders = ["vaultId", "type", "name", "username", "password", "url", "tags", "risk", "notes"];
const allowedTypes = new Set(["password", "api_key", "ssh_key", "certificate", "token", "connection_string", "directory_account", "registry_token"]);
const allowedRisks = new Set(["low", "medium", "high"]);

const parseCsvRows = (text) => {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];
    if (quoted && char === "\"" && next === "\"") {
      value += "\"";
      index += 1;
    } else if (char === "\"") {
      quoted = !quoted;
    } else if (!quoted && char === ",") {
      row.push(value);
      value = "";
    } else if (!quoted && (char === "\n" || char === "\r")) {
      if (char === "\r" && next === "\n") index += 1;
      row.push(value);
      if (row.some((cell) => cell.trim())) rows.push(row);
      row = [];
      value = "";
    } else {
      value += char;
    }
  }
  row.push(value);
  if (row.some((cell) => cell.trim())) rows.push(row);
  return rows;
};

const sha256 = (value) => crypto.createHash("sha256").update(value, "utf8").digest("hex");
const fingerprint = (value) => crypto.createHash("sha256").update(value, "utf8").digest("base64url");

assert.ok(existsSync(csvPath), `normalized import CSV not found: ${csvPath}`);
const raw = readFileSync(csvPath, "utf8").replace(/^\uFEFF/, "");
const rows = parseCsvRows(raw);
assert.ok(rows.length >= 2, "normalized import CSV must include headers and at least one entry");
const headers = rows[0].map((header) => header.trim());
assert.deepEqual(headers, requiredHeaders, "normalized import CSV headers must match Sentinel import format");

const entries = rows.slice(1).map((cells, index) => {
  assert.equal(cells.length, headers.length, `row ${index + 1} column count must match headers`);
  const entry = Object.fromEntries(headers.map((header, headerIndex) => [header, cells[headerIndex] || ""]));
  assert.ok(entry.vaultId.trim(), `row ${index + 1} is missing vaultId`);
  assert.ok(allowedTypes.has(entry.type), `row ${index + 1} has unsupported type: ${entry.type}`);
  assert.ok(entry.name.trim(), `row ${index + 1} is missing name`);
  assert.ok(entry.username.trim(), `row ${index + 1} is missing username`);
  assert.ok(entry.password, `row ${index + 1} is missing password`);
  assert.ok(allowedRisks.has(entry.risk || "medium"), `row ${index + 1} has unsupported risk: ${entry.risk}`);
  return entry;
});

if (expectedRows !== null) {
  assert.equal(entries.length, expectedRows, "normalized import row count does not match --expected-rows");
}

let adapterEvidence = null;
if (evidencePath) {
  assert.ok(existsSync(evidencePath), `source adapter evidence not found: ${evidencePath}`);
  adapterEvidence = JSON.parse(readFileSync(evidencePath, "utf8"));
  assert.equal(adapterEvidence.format, "sentinel-source-export-adapter-evidence-v1");
  assert.equal(path.resolve(adapterEvidence.outputCsv), csvPath, "adapter evidence outputCsv must match normalized import CSV");
  assert.equal(adapterEvidence.passwordValuesIncluded, false, "adapter evidence cannot include password values");
  assert.equal(adapterEvidence.convertedCount, entries.length, "adapter evidence convertedCount must match normalized CSV rows");
}

const vaultIds = [...new Set(entries.map((entry) => entry.vaultId))].sort();
const report = {
  format: "sentinel-normalized-import-validation-v1",
  csvPath,
  adapterEvidencePath: evidencePath,
  csvSha256: sha256(raw),
  rowCount: entries.length,
  vaultIds,
  uniqueVaultCount: vaultIds.length,
  adapterEvidenceMatched: Boolean(adapterEvidence),
  redactedEntries: entries.map((entry) => ({
    vaultId: entry.vaultId,
    type: entry.type,
    name: entry.name,
    username: entry.username,
    url: entry.url,
    risk: entry.risk,
    tags: entry.tags ? entry.tags.split(";").map((tag) => tag.trim()).filter(Boolean) : [],
    passwordFingerprint: fingerprint(entry.password)
  })),
  passwordValuesIncluded: false,
  validated: true
};

if (outputPath) {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(report, null, 2));
}

console.log(JSON.stringify(report, null, 2));
