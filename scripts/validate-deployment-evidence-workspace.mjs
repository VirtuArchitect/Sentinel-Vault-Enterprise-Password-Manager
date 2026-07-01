import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
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

const manifestPath = path.resolve(args.get("--manifest") || "artifacts/deployment/pilot/deployment-evidence-workspace-manifest.json");
const expectedBundlePath = args.get("--bundle") ? path.resolve(args.get("--bundle")) : null;
const templatePath = path.resolve(args.get("--template") || "docs/templates/deployment-evidence-bundle.json");

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

const validateArtifact = (workspaceDir, name, artifact) => {
  assert.ok(artifact, `missing manifest artifact: ${name}`);
  assert.ok(artifact.path && typeof artifact.path === "string", `${name}.path is required`);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/, `${name}.sha256 must be a SHA-256 hex digest`);
  assert.ok(Number.isInteger(artifact.bytes) && artifact.bytes > 0, `${name}.bytes must be a positive integer`);
  const artifactPath = path.resolve(workspaceDir, artifact.path);
  assert.ok(existsSync(artifactPath), `${name} file not found: ${artifactPath}`);
  const actual = hashFile(artifactPath);
  assert.equal(actual.bytes, artifact.bytes, `${name} byte length changed`);
  assert.equal(actual.sha256, artifact.sha256, `${name} SHA-256 changed`);
  return artifactPath;
};

assert.ok(existsSync(manifestPath), `Deployment evidence workspace manifest not found: ${manifestPath}`);
assert.ok(existsSync(templatePath), `Deployment evidence bundle template not found: ${templatePath}`);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const template = JSON.parse(readFileSync(templatePath, "utf8"));

assert.equal(manifest.format, "sentinel-deployment-evidence-workspace-manifest-v1");
assert.equal(template.format, "sentinel-deployment-evidence-bundle-v1");
assert.ok(!Number.isNaN(Date.parse(manifest.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(manifest.environment && typeof manifest.environment === "string", "environment is required");
assert.ok(manifest.status && typeof manifest.status === "string", "status is required");
assert.ok(manifest.owner && typeof manifest.owner === "string", "owner is required");
assert.ok(manifest.outputDir && typeof manifest.outputDir === "string", "outputDir is required");
assert.ok(manifest.evidence && typeof manifest.evidence === "object", "evidence manifest map is required");

const workspaceDir = path.resolve(manifest.outputDir);
assert.ok(existsSync(workspaceDir), `workspace outputDir does not exist: ${workspaceDir}`);
const bundlePath = validateArtifact(workspaceDir, "bundle", manifest.bundle);
validateArtifact(workspaceDir, "readme", manifest.readme);

if (expectedBundlePath) {
  assert.equal(bundlePath, expectedBundlePath, "manifest bundle path does not match expected bundle");
}

const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
assert.equal(bundle.format, "sentinel-deployment-evidence-bundle-v1");
assert.equal(bundle.environment, manifest.environment, "bundle environment does not match manifest");
assert.equal(bundle.status, manifest.status, "bundle status does not match manifest");
assert.equal(bundle.owner, manifest.owner, "bundle owner does not match manifest");

const evidenceNames = Object.keys(bundle.evidence || {});
const templateEvidenceNames = Object.keys(template.evidence || {});
assert.deepEqual(evidenceNames.sort(), templateEvidenceNames.sort(), "workspace evidence names do not match current deployment evidence template");
assert.deepEqual(Object.keys(manifest.evidence).sort(), evidenceNames.sort(), "manifest evidence names do not match bundle");
for (const name of evidenceNames) {
  const evidencePath = validateArtifact(workspaceDir, `evidence.${name}`, manifest.evidence[name]);
  assert.equal(evidencePath, path.resolve(workspaceDir, bundle.evidence[name]), `manifest evidence path does not match bundle for ${name}`);
}

console.log(JSON.stringify({
  format: "sentinel-deployment-evidence-workspace-validation-v1",
  manifestPath,
  environment: manifest.environment,
  status: manifest.status,
  evidenceCount: evidenceNames.length,
  validated: true
}, null, 2));
