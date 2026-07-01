import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const sourcePath = args.get("--source");
const format = String(args.get("--format") || "").toLowerCase();
const vaultId = args.get("--vault-id");
const outputPath = args.get("--out") || "artifacts/import/source-export-normalized.csv";
const evidencePath = args.get("--evidence") || "artifacts/import/source-export-adapter-evidence.json";
const allowedFormats = new Set(["bitwarden-csv", "onepassword-csv", "sentinel-csv"]);

assert.ok(sourcePath, "Usage: node scripts/convert-source-export.mjs --source <file> --format <bitwarden-csv|onepassword-csv|sentinel-csv> --vault-id <vault-id>");
assert.ok(allowedFormats.has(format), "Unsupported --format");
assert.ok(vaultId, "--vault-id is required");

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

const csvEscape = (value) => {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll("\"", "\"\"")}"` : text;
};
const sha256 = (value) => crypto.createHash("sha256").update(value, "utf8").digest("base64url");
const normalizeTags = (...values) => values
  .flatMap((value) => String(value || "").split(/[;,]/))
  .map((tag) => tag.trim())
  .filter(Boolean);

const first = (row, names) => {
  for (const name of names) {
    if (row[name] !== undefined && String(row[name]).trim()) return String(row[name]).trim();
  }
  return "";
};

const adapters = {
  "sentinel-csv": (row) => ({
    type: first(row, ["type"]) || "password",
    name: first(row, ["name"]),
    username: first(row, ["username"]),
    password: first(row, ["password"]),
    url: first(row, ["url"]),
    tags: normalizeTags(first(row, ["tags"])),
    risk: first(row, ["risk"]) || "medium",
    notes: first(row, ["notes"])
  }),
  "bitwarden-csv": (row) => ({
    type: first(row, ["type"]) || "password",
    name: first(row, ["name", "login_name", "folder"]),
    username: first(row, ["login_username", "username"]),
    password: first(row, ["login_password", "password"]),
    url: first(row, ["login_uri", "url"]),
    tags: normalizeTags(first(row, ["folder"]), first(row, ["favorite"]) === "1" ? "favorite" : ""),
    risk: first(row, ["risk"]) || "medium",
    notes: first(row, ["notes"])
  }),
  "onepassword-csv": (row) => ({
    type: first(row, ["type", "category"]) || "password",
    name: first(row, ["title", "name"]),
    username: first(row, ["username", "login_username"]),
    password: first(row, ["password", "login_password"]),
    url: first(row, ["website", "url", "login_uri"]),
    tags: normalizeTags(first(row, ["tags"]), first(row, ["vault"])),
    risk: first(row, ["risk"]) || "medium",
    notes: first(row, ["notes", "note"])
  })
};

const raw = readFileSync(sourcePath, "utf8");
const rows = parseCsv(raw);
const normalized = rows.map(adapters[format]).filter((entry) => entry.name || entry.username || entry.password);

for (const [index, entry] of normalized.entries()) {
  assert.ok(entry.name, `Row ${index + 1} is missing name after ${format} conversion`);
  assert.ok(entry.username, `Row ${index + 1} is missing username after ${format} conversion`);
  assert.ok(entry.password, `Row ${index + 1} is missing password after ${format} conversion`);
}

const headers = ["vaultId", "type", "name", "username", "password", "url", "tags", "risk", "notes"];
const csv = [
  headers.join(","),
  ...normalized.map((entry) => headers.map((header) => csvEscape(header === "vaultId" ? vaultId : header === "tags" ? entry.tags.join(";") : entry[header])).join(","))
].join("\n");

const evidence = {
  format: "sentinel-source-export-adapter-evidence-v1",
  sourceFormat: format,
  sourceFile: path.resolve(sourcePath),
  sourceSha256: sha256(raw),
  generatedAt: new Date().toISOString(),
  rowCount: rows.length,
  convertedCount: normalized.length,
  targetVaultId: vaultId,
  passwordValuesIncluded: false,
  outputCsv: path.resolve(outputPath),
  entries: normalized.map((entry) => ({
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
writeFileSync(outputPath, `${csv}\n`);
writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

console.log(`Normalized Sentinel import CSV written: ${outputPath}`);
console.log(`Source adapter evidence written: ${evidencePath}`);
