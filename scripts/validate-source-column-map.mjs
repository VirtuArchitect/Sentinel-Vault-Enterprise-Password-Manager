import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
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
  }
}

const mappingPath = path.resolve(args.get("--mapping") || args.get("--map") || "docs/templates/source-export-column-map.json");
const sourcePath = args.get("--source") ? path.resolve(args.get("--source")) : null;
const outPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const placeholder = /replace-with/i;
const requiredFields = ["name", "username", "password"];

const parseCsvLine = (line) => {
  const values = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];
    if (char === "\"" && quoted && next === "\"") {
      value += "\"";
      index += 1;
    } else if (char === "\"") {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      values.push(value.trim());
      value = "";
    } else {
      value += char;
    }
  }
  values.push(value.trim());
  return values;
};

const collectColumns = (spec) => {
  if (!spec) return [];
  if (typeof spec === "string") return [spec];
  if (Array.isArray(spec)) return spec;
  return Array.isArray(spec.columns) ? spec.columns : [];
};

assert.ok(existsSync(mappingPath), `Source export column map not found: ${mappingPath}`);
const rawMapping = readFileSync(mappingPath, "utf8").replace(/^\uFEFF/, "");
const mapping = JSON.parse(rawMapping);

assert.equal(mapping.format, "sentinel-source-export-column-map-v1");
assert.ok(mapping.sourceSystem, "mapping.sourceSystem is required");
assert.ok(mapping.fields && typeof mapping.fields === "object", "mapping.fields is required");
for (const field of requiredFields) {
  assert.ok(mapping.fields[field], `mapping.fields.${field} is required`);
}
assert.equal(mapping.redaction?.evidenceIncludesPasswordValues, false, "mapping.redaction.evidenceIncludesPasswordValues must be false");
assert.equal(mapping.redaction?.evidenceIncludesOtpValues, false, "mapping.redaction.evidenceIncludesOtpValues must be false");

const mappedColumns = [...new Set(Object.values(mapping.fields).flatMap(collectColumns).filter(Boolean))].sort();
const ignoredColumns = [...new Set(mapping.ignoredColumns || [])].sort();
const duplicateMappedColumns = mappedColumns.filter((column, index) => mappedColumns.indexOf(column) !== index);
assert.deepEqual(duplicateMappedColumns, [], "mapped columns must be unique after normalization");

let sourceHeaders = [];
let unmappedSourceColumns = [];
let missingMappedColumns = [];
if (sourcePath) {
  assert.ok(existsSync(sourcePath), `Source export CSV not found: ${sourcePath}`);
  const firstLine = readFileSync(sourcePath, "utf8").replace(/^\uFEFF/, "").split(/\r?\n/).find((line) => line.trim());
  assert.ok(firstLine, "Source export CSV must include a header row");
  sourceHeaders = parseCsvLine(firstLine);
  const sourceHeaderSet = new Set(sourceHeaders);
  const coveredColumns = new Set([...mappedColumns, ...ignoredColumns]);
  unmappedSourceColumns = sourceHeaders.filter((column) => !coveredColumns.has(column));
  missingMappedColumns = mappedColumns.filter((column) => !sourceHeaderSet.has(column));
  assert.deepEqual(missingMappedColumns, [], "mapped columns must exist in the source CSV header");
  assert.deepEqual(unmappedSourceColumns, [], "source CSV columns must be mapped or explicitly ignored");
}

const result = {
  format: "sentinel-source-column-map-validation-v1",
  mappingPath,
  sourcePath,
  mappingSha256: crypto.createHash("sha256").update(rawMapping).digest("hex"),
  sourceSystem: mapping.sourceSystem,
  sourceSystemPlaceholder: placeholder.test(mapping.sourceSystem),
  requiredFields,
  mappedColumns,
  ignoredColumns,
  sourceHeaders,
  findings: {
    missingMappedColumns,
    unmappedSourceColumns
  },
  checks: {
    requiredFieldsPresent: requiredFields.every((field) => Boolean(mapping.fields[field])),
    redactionFlagsSafe: mapping.redaction?.evidenceIncludesPasswordValues === false && mapping.redaction?.evidenceIncludesOtpValues === false,
    mappedColumnsExistInSource: missingMappedColumns.length === 0,
    allSourceColumnsMappedOrIgnored: unmappedSourceColumns.length === 0
  },
  validated: true
};

const json = JSON.stringify(result, null, 2);
if (outPath) {
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, json, { encoding: "utf8" });
}
console.log(json);
