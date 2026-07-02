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
  "deploymentWorkspaceManifest",
  "deploymentBundle",
  "deploymentStatus",
  "deploymentRedaction",
  "deploymentRedactionMarkdown",
  "externalRequests",
  "externalRequestsMarkdown",
  "phaseCompletionAudit",
  "phaseCompletionAuditMarkdown",
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
const workspaceManifest = JSON.parse(readFileSync(manifest.artifacts.deploymentWorkspaceManifest.path, "utf8"));
const deploymentStatus = JSON.parse(readFileSync(manifest.artifacts.deploymentStatus.path, "utf8"));
const deploymentRedaction = JSON.parse(readFileSync(manifest.artifacts.deploymentRedaction.path, "utf8"));
const phaseCompletion = JSON.parse(readFileSync(manifest.artifacts.phaseCompletionAudit.path, "utf8"));

assert.equal(readiness.format, "sentinel-phase-readiness-report-v1");
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(workspaceManifest.format, "sentinel-deployment-evidence-workspace-manifest-v1");
assert.equal(deploymentStatus.format, "sentinel-deployment-evidence-status-v1");
assert.equal(deploymentRedaction.format, "sentinel-deployment-redaction-report-v1");
assert.equal(phaseCompletion.format, "sentinel-phase-completion-audit-v1");
assert.equal(workspaceManifest.environment, readiness.bundle.environment, "workspace manifest environment does not match readiness report");
assert.equal(workspaceManifest.status, readiness.bundle.status, "workspace manifest status does not match readiness report");
assert.equal(path.resolve(workspaceManifest.outputDir, workspaceManifest.bundle.path), manifest.artifacts.deploymentBundle.path, "workspace manifest bundle path does not match phase evidence bundle");
assert.equal(path.resolve(deploymentRedaction.bundle), manifest.artifacts.deploymentBundle.path, "deployment redaction bundle path does not match phase evidence bundle");
assert.equal(manifest.environment, readiness.bundle.environment, "manifest environment does not match readiness report");
assert.equal(manifest.target, readiness.target, "manifest target does not match readiness report");
assert.equal(manifest.bundleStatus, readiness.bundle.status, "manifest bundle status does not match readiness report");
assert.equal(manifest.ready, readiness.ready, "manifest ready flag does not match readiness report");
assert.equal(manifest.blockerCount, readiness.blockers?.length || 0, "manifest blocker count does not match readiness report");
assert.equal(manifest.warningCount, readiness.warnings?.length || 0, "manifest warning count does not match readiness report");
assert.equal(manifest.requestCount, externalRequests.requests?.length || 0, "manifest request count does not match external requests");
assert.deepEqual(manifest.externalRequestSummary, {
  evidenceKeyCount: readiness.externalRequests?.evidenceKeyCount || 0,
  commandScriptCount: readiness.externalRequests?.commandScriptCount || 0,
  validatorCommandCount: readiness.externalRequests?.validatorCommandCount || 0,
  commandScripts: externalRequests.summary?.commandScripts || []
}, "manifest external request summary does not match readiness and request pack");
assert.equal(manifest.remainingPhaseCount, phaseCompletion.remainingPhaseCount, "manifest remaining phase count does not match completion audit");
assert.equal(manifest.remainingItemCount, phaseCompletion.remainingItemCount, "manifest remaining item count does not match completion audit");
assert.equal(manifest.remainingExternallyCovered, phaseCompletion.externallyCovered, "manifest external coverage flag does not match completion audit");
assert.deepEqual(manifest.deploymentEvidenceSummary, deploymentStatus.summary, "manifest deployment evidence summary does not match status report");
assert.deepEqual(manifest.deploymentRedactionSummary, deploymentRedaction.summary, "manifest deployment redaction summary does not match redaction report");

console.log(JSON.stringify({
  format: "sentinel-phase-evidence-pack-validation-v1",
  manifestPath,
  artifactCount: requiredArtifactNames.length,
  ready: manifest.ready,
  blockerCount: manifest.blockerCount,
  evidenceKeyCount: manifest.externalRequestSummary.evidenceKeyCount,
  commandScriptCount: manifest.externalRequestSummary.commandScriptCount,
  validated: true
}, null, 2));
