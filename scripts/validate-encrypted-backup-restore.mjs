import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const dataDir = args.get("--data-dir") || process.env.DATA_DIR || "data";
const backupDir = args.get("--backup-dir") || path.join(dataDir, "backups");
const outputPath = args.get("--out") || "artifacts/storage/encrypted-backup-restore-evidence.json";
const rootKey = process.env.VAULT_ROOT_KEY || "dev-root-key-change-me";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("base64url");
const backupKey = () => crypto.createHash("sha256").update(rootKey, "utf8").digest();
const hasEncryptedPayload = (secret) => secret.encrypted?.iv && secret.encrypted?.tag && (secret.encrypted?.ciphertext || secret.encrypted?.value);

const latestEncryptedBackup = () => {
  if (!existsSync(backupDir)) return null;
  return readdirSync(backupDir)
    .filter((file) => file.endsWith(".json.enc"))
    .sort()
    .reverse()
    .map((file) => path.join(backupDir, file))[0] || null;
};

const backupPath = args.get("--backup") || latestEncryptedBackup();
assert.ok(backupPath, `No encrypted backup was found in ${backupDir}`);
assert.ok(existsSync(backupPath), `Encrypted backup not found: ${backupPath}`);

const manifestPath = args.get("--manifest") || `${backupPath}.sha256.json`;
assert.ok(existsSync(manifestPath), `Encrypted backup manifest not found: ${manifestPath}`);

const encrypted = readFileSync(backupPath);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const checksum = sha256(encrypted);
const checksumVerified = checksum === manifest.sha256;

let parsed = null;
let decryptError = null;
try {
  const decipher = crypto.createDecipheriv("aes-256-gcm", backupKey(), Buffer.from(manifest.iv || "", "base64url"));
  decipher.setAuthTag(Buffer.from(manifest.tag || "", "base64url"));
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  parsed = JSON.parse(decrypted.toString("utf8"));
} catch (err) {
  decryptError = err instanceof Error ? err.message : "decrypt_or_parse_failed";
}

const requiredCollections = [
  "users",
  "deviceInventory",
  "tenants",
  "vaults",
  "secrets",
  "serviceTokens",
  "secretImports",
  "accessRequests",
  "integrationOutbox",
  "audit"
];
const missingCollections = parsed ? requiredCollections.filter((collection) => !Array.isArray(parsed[collection])) : requiredCollections;
const transientCollectionsPresent = parsed ? ["sessions", "loginFailures"].filter((collection) => Object.hasOwn(parsed, collection)) : [];
const unencryptedSecretIds = parsed ? (parsed.secrets || []).filter((secret) => !hasEncryptedPayload(secret)).map((secret) => secret.id) : [];
const vaultIds = new Set(parsed?.vaults?.map((vault) => vault.id) || []);
const orphanSecrets = parsed ? (parsed.secrets || []).filter((secret) => !vaultIds.has(secret.vaultId)).map((secret) => secret.id) : [];
const userIds = new Set(parsed?.users?.map((user) => user.id) || []);
const orphanVaultMembers = parsed ? (parsed.vaults || []).flatMap((vault) => (
  (vault.members || []).filter((member) => !userIds.has(member)).map((member) => ({ vaultId: vault.id, member }))
)) : [];

const checks = {
  manifestPresent: true,
  checksumVerified,
  algorithmSupported: manifest.algorithm === "AES-256-GCM",
  decryptedAndParsed: Boolean(parsed),
  requiredCollectionsPresent: missingCollections.length === 0,
  transientCollectionsExcluded: transientCollectionsPresent.length === 0,
  encryptedSecretPayloadsPresent: unencryptedSecretIds.length === 0,
  orphanSecretsAbsent: orphanSecrets.length === 0,
  orphanVaultMembersAbsent: orphanVaultMembers.length === 0
};

const evidence = {
  format: "sentinel-encrypted-backup-restore-drill-v1",
  checkedAt: new Date().toISOString(),
  restoreMode: "dry-run",
  backupFile: path.resolve(backupPath),
  manifestFile: path.resolve(manifestPath),
  backupSha256: checksum,
  manifestSha256: manifest.sha256 || null,
  stateVersion: parsed?.metadata?.version || null,
  counts: Object.fromEntries(requiredCollections.map((collection) => [collection, parsed?.[collection]?.length || 0])),
  checks,
  findings: {
    decryptError,
    missingCollections,
    transientCollectionsPresent,
    unencryptedSecretIds,
    orphanSecrets,
    orphanVaultMembers
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

const failed = Object.entries(checks).filter(([, passed]) => !passed);
if (failed.length) {
  console.error(JSON.stringify(evidence, null, 2));
  throw new Error(`Encrypted backup restore drill failed: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(`Encrypted backup restore drill evidence written: ${outputPath}`);
