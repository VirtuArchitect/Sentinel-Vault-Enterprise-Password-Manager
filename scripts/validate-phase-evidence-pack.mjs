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

const manifestPath = path.resolve(args.get("--manifest") || "artifacts/deployment/pilot/phase-evidence-pack-manifest.json");
const requiredArtifactNames = [
  "deploymentBundle",
  "deploymentStatus",
  "externalRequests",
  "externalRequestsMarkdown",
  "phaseReadiness",
  "phaseReadinessMarkdown",
  "phaseHandoffChecklist"
];

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

assert.ok(existsSync(manifestPath), `Phase evidence pack manifest not found: ${manifestPath}`);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

assert.equal(manifest.format, "sentinel-phase-evidence-pack-manifest-v1");
assert.ok(!Number.isNaN(Date.parse(manifest.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(manifest.artifacts && typeof manifest.artifacts === "object", "artifacts map is required");

for (const artifactName of requiredArtifactNames) {
  const artifact = manifest.artifacts[artifactName];
  assert.ok(artifact, `missing artifact entry: ${artifactName}`);
  assert.ok(artifact.path && typeof artifact.path === "string", `${artifactName}.path is required`);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/, `${artifactName}.sha256 must be a SHA-256 hex digest`);
  assert.ok(Number.isInteger(artifact.bytes) && artifact.bytes > 0, `${artifactName}.bytes must be a positive integer`);
  assert.ok(existsSync(artifact.path), `artifact file not found: ${artifactName}: ${artifact.path}`);

  const actual = hashFile(artifact.path);
  assert.equal(actual.bytes, artifact.bytes, `${artifactName} byte length changed`);
  assert.equal(actual.sha256, artifact.sha256, `${artifactName} SHA-256 changed`);
}

const readiness = JSON.parse(readFileSync(manifest.artifacts.phaseReadiness.path, "utf8"));
const externalRequests = JSON.parse(readFileSync(manifest.artifacts.externalRequests.path, "utf8"));
const deploymentStatus = JSON.parse(readFileSync(manifest.artifacts.deploymentStatus.path, "utf8"));

assert.equal(readiness.format, "sentinel-phase-readiness-report-v1");
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(deploymentStatus.format, "sentinel-deployment-evidence-status-v1");
assert.equal(manifest.environment, readiness.bundle.environment, "manifest environment does not match readiness report");
assert.equal(manifest.target, readiness.target, "manifest target does not match readiness report");
assert.equal(manifest.bundleStatus, readiness.bundle.status, "manifest bundle status does not match readiness report");
assert.equal(manifest.ready, readiness.ready, "manifest ready flag does not match readiness report");
assert.equal(manifest.blockerCount, readiness.blockers?.length || 0, "manifest blocker count does not match readiness report");
assert.equal(manifest.warningCount, readiness.warnings?.length || 0, "manifest warning count does not match readiness report");
assert.equal(manifest.requestCount, externalRequests.requests?.length || 0, "manifest request count does not match external requests");
assert.deepEqual(manifest.deploymentEvidenceSummary, deploymentStatus.summary, "manifest deployment evidence summary does not match status report");

console.log(JSON.stringify({
  format: "sentinel-phase-evidence-pack-validation-v1",
  manifestPath,
  artifactCount: requiredArtifactNames.length,
  ready: manifest.ready,
  blockerCount: manifest.blockerCount,
  validated: true
}, null, 2));
