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

const schemaPath = path.resolve(args.get("--schema") || "docs/architecture/postgres-schema.sql");
const outPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
assert.ok(existsSync(schemaPath), `Postgres schema file not found: ${schemaPath}`);

const schema = readFileSync(schemaPath, "utf8");
const requiredTables = [
  "schema_migrations",
  "sentinel_state",
  "users",
  "device_inventory",
  "tenants",
  "vaults",
  "secrets",
  "service_tokens",
  "secret_imports",
  "access_requests",
  "integration_outbox",
  "audit_events",
  "policies"
];
const requiredIndexes = [
  "idx_users_email",
  "idx_vaults_tenant_id",
  "idx_secrets_vault_id",
  "idx_secrets_active",
  "idx_access_requests_secret_status",
  "idx_access_requests_requester_status",
  "idx_integration_outbox_target_status",
  "idx_audit_events_ts",
  "idx_audit_events_action"
];
const requiredGeneratedColumns = [
  "email TEXT GENERATED ALWAYS",
  "role TEXT GENERATED ALWAYS",
  "enabled BOOLEAN GENERATED ALWAYS",
  "last_seen_at TIMESTAMPTZ GENERATED ALWAYS",
  "parent_id TEXT GENERATED ALWAYS",
  "classification TEXT GENERATED ALWAYS",
  "fingerprint TEXT GENERATED ALWAYS",
  "expires_at TIMESTAMPTZ GENERATED ALWAYS",
  "next_attempt_at TIMESTAMPTZ GENERATED ALWAYS",
  "hash TEXT GENERATED ALWAYS",
  "previous_hash TEXT GENERATED ALWAYS"
];

const hasStatement = (pattern) => new RegExp(pattern, "i").test(schema);
const missingTables = requiredTables.filter((table) => !hasStatement(`CREATE\\s+TABLE\\s+IF\\s+NOT\\s+EXISTS\\s+${table}\\b`));
const missingIndexes = requiredIndexes.filter((index) => !hasStatement(`CREATE\\s+INDEX\\s+IF\\s+NOT\\s+EXISTS\\s+${index}\\b`));
const missingGeneratedColumns = requiredGeneratedColumns.filter((fragment) => !schema.includes(fragment));
const beginIndex = schema.search(/\bBEGIN\s*;/i);
const commitIndex = schema.search(/\bCOMMIT\s*;/i);

const checks = {
  transactionWrapped: beginIndex >= 0 && commitIndex > beginIndex,
  schemaMigrationRecorded: schema.includes("INSERT INTO schema_migrations"),
  jsonbMirrorTablesPresent: missingTables.length === 0,
  requiredIndexesPresent: missingIndexes.length === 0,
  generatedColumnsPresent: missingGeneratedColumns.length === 0,
  noDatabaseUrlPlaceholders: !/DATABASE_URL|postgres:\/\/|password=/i.test(schema)
};

const result = {
  format: "sentinel-postgres-schema-validation-v1",
  schemaPath,
  schemaSha256: crypto.createHash("sha256").update(schema).digest("hex"),
  requiredTableCount: requiredTables.length,
  requiredIndexCount: requiredIndexes.length,
  requiredGeneratedColumnCount: requiredGeneratedColumns.length,
  checks,
  findings: {
    missingTables,
    missingIndexes,
    missingGeneratedColumns
  },
  validated: Object.values(checks).every(Boolean)
};

const json = JSON.stringify(result, null, 2);
if (outPath) {
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, json, { encoding: "utf8" });
}
console.log(json);

const failed = Object.entries(checks).filter(([, passed]) => !passed);
if (failed.length) {
  throw new Error(`Postgres schema validation failed: ${failed.map(([name]) => name).join(", ")}`);
}
