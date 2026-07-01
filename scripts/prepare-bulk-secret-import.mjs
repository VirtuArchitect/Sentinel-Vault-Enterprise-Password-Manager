import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const csvPath = args.get("--csv");
const mappingPath = args.get("--mapping");
const outputPath = args.get("--out") || "artifacts/import/bulk-secret-import-payload.json";
const evidencePath = args.get("--evidence") || "artifacts/import/bulk-secret-import-evidence.json";

assert.ok(csvPath, "Usage: node scripts/prepare-bulk-secret-import.mjs --csv <file> --mapping <file> [--out <file>] [--evidence <file>]");
assert.ok(mappingPath, "Missing --mapping <file>");

const parseCsv = (text) => {
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
  if (!rows.length) return [];
  const headers = rows[0].map((header) => header.trim());
  return rows.slice(1).map((cells) => Object.fromEntries(headers.map((header, index) => [header, cells[index] || ""])));
};

const sha256 = (value) => crypto.createHash("sha256").update(value, "utf8").digest("base64url");
const mapping = JSON.parse(readFileSync(mappingPath, "utf8"));
const csvRaw = readFileSync(csvPath, "utf8");
const rows = parseCsv(csvRaw);
const field = (row, target) => row[mapping.fieldMap[target]] || "";
const tagSeparator = mapping.tagSeparator || ";";

const entries = rows.map((row) => ({
  vaultId: field(row, "vaultId") || mapping.defaultVaultId,
  type: field(row, "type") || "password",
  name: field(row, "name"),
  username: field(row, "username"),
  password: field(row, "password"),
  url: field(row, "url"),
  tags: String(field(row, "tags") || "").split(tagSeparator).map((tag) => tag.trim()).filter(Boolean),
  risk: mapping.riskMapping?.[String(field(row, "risk") || "").toLowerCase()] || field(row, "risk") || "medium",
  notes: field(row, "notes")
}));

for (const [index, entry] of entries.entries()) {
  assert.ok(entry.vaultId, `Row ${index + 1} is missing vaultId`);
  assert.ok(entry.name, `Row ${index + 1} is missing name`);
  assert.ok(entry.username, `Row ${index + 1} is missing username`);
  assert.ok(entry.password, `Row ${index + 1} is missing password`);
}

const vaultIds = [...new Set(entries.map((entry) => entry.vaultId))];
assert.equal(vaultIds.length, 1, "Bulk import payload must target exactly one vaultId");

const payload = {
  vaultId: vaultIds[0],
  reason: mapping.approval?.requestReason || "Bulk secret import",
  entries: entries.map(({ vaultId: _vaultId, ...entry }) => entry)
};

const evidence = {
  format: "sentinel-bulk-secret-import-evidence-v1",
  sourceSystem: mapping.sourceSystem,
  rowCount: rows.length,
  entryCount: entries.length,
  targetVaultId: payload.vaultId,
  csvSha256: sha256(csvRaw),
  mappingSha256: sha256(JSON.stringify(mapping)),
  generatedAt: new Date().toISOString(),
  passwordValuesIncluded: false,
  entries: entries.map((entry) => ({
    name: entry.name,
    username: entry.username,
    url: entry.url,
    risk: entry.risk,
    tags: entry.tags,
    passwordFingerprint: sha256(entry.password)
  }))
};

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(evidencePath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(payload, null, 2));
writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

console.log(`Import payload written: ${outputPath}`);
console.log(`Redacted import evidence written: ${evidencePath}`);
