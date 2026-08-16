import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(rootDir, relativePath), "utf8");
const packageJson = JSON.parse(read("package.json"));
const version = packageJson.version;
const demoUrl = "http://127.0.0.1:5173";
const requiredRunbooks = [
  "docs/operations/bulk-secret-import-runbook.md",
  "docs/operations/kms-hsm-key-ceremony.md",
  "docs/operations/release-governance-runbook.md"
];

assert.match(version, /^\d+\.\d+\.\d+$/, "package.json version must be semantic x.y.z");

const versionSource = read("src/version.ts");
assert.match(
  versionSource,
  new RegExp(`APP_VERSION\\s*=\\s*["']${version.replaceAll(".", "\\.")}["']`),
  "src/version.ts APP_VERSION must match package.json"
);

const readme = read("README.md");
assert.ok(readme.includes(`**Current version:** \`v${version}\``), "README must show the current version");
assert.ok(readme.includes(demoUrl), "README must include the canonical local demo URL");
assert.ok(readme.includes("[CHANGELOG.md](CHANGELOG.md)"), "README must link to CHANGELOG.md");

const changelog = read("CHANGELOG.md");
assert.ok(changelog.includes(`## [${version}] - `), "CHANGELOG.md must include the current version entry");

const smokeTests = read("docs/testing/smoke-tests.md");
assert.ok(smokeTests.includes(demoUrl), "Smoke tests must include the canonical local demo URL");

const releaseRunbook = read("docs/operations/release-governance-runbook.md");
for (const phrase of [
  "Every future update must review",
  "CHANGELOG.md",
  demoUrl,
  "pnpm validate:release-integrity",
  "Open a PR, wait for CI, merge through GitHub"
]) {
  assert.ok(releaseRunbook.includes(phrase), `release governance runbook must include: ${phrase}`);
}

for (const runbook of requiredRunbooks) {
  assert.ok(existsSync(path.join(rootDir, runbook)), `${runbook} must exist`);
  assert.ok(readme.includes(runbook), `README must link to ${runbook}`);
}

const agents = read("AGENTS.md");
for (const phrase of [
  "Release integrity: pnpm validate:release-integrity",
  "Full local verify: pnpm verify",
  "Future Update Requirements",
  "docs/operations/release-governance-runbook.md"
]) {
  assert.ok(agents.includes(phrase), `AGENTS.md must include: ${phrase}`);
}
assert.equal(agents.includes("Replace these placeholders"), false, "AGENTS.md must not contain placeholder command text");

console.log(`Release integrity validated for v${version}.`);
