import assert from "node:assert/strict";
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

const matrixPath = path.resolve(args.get("--matrix") || "artifacts/deployment/pilot/phase-gap-matrix.json");
const bundlePath = args.get("--bundle") ? path.resolve(args.get("--bundle")) : null;
const requestsPath = args.get("--external-requests") ? path.resolve(args.get("--external-requests")) : null;

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const normalize = (filePath) => filePath.replaceAll("\\", "/");
const basename = (filePath) => path.basename(normalize(filePath));

assert.ok(existsSync(matrixPath), `Phase gap matrix not found: ${matrixPath}`);
const matrix = readJson(matrixPath);

assert.equal(matrix.format, "sentinel-phase-gap-matrix-v1");
assert.ok(!Number.isNaN(Date.parse(matrix.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(matrix.environment, "environment is required");
assert.ok(matrix.owner, "owner is required");
assert.ok(matrix.status, "status is required");
assert.ok(Array.isArray(matrix.phases), "phases must be an array");
assert.equal(matrix.summary.phaseCount, matrix.phases.length, "summary phase count mismatch");
assert.equal(matrix.summary.evidenceKeyCount, new Set(matrix.phases.flatMap((phase) => phase.evidenceKeys || [])).size, "summary evidence key count mismatch");
assert.equal(matrix.summary.missingArtifactCount, matrix.phases.reduce((total, phase) => total + phase.missingArtifactCount, 0), "summary missing artifact count mismatch");
assert.equal(matrix.summary.supportingArtifactCount, matrix.phases.reduce((total, phase) => total + phase.supportingArtifactCount, 0), "summary supporting artifact count mismatch");
assert.equal(matrix.summary.deploymentBundleCoveredPhaseCount, matrix.phases.filter((phase) => phase.coveredByDeploymentBundle).length, "summary deployment bundle coverage count mismatch");

const externalRequests = requestsPath ? readJson(requestsPath) : readJson(matrix.externalRequestsPath);
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(matrix.phases.length, externalRequests.requests.length, "phase gap matrix request count mismatch");

const bundle = bundlePath ? readJson(bundlePath) : readJson(matrix.bundlePath);
assert.equal(bundle.format, "sentinel-deployment-evidence-bundle-v1");
const bundleEvidence = Object.entries(bundle.evidence || {}).map(([name, evidencePath]) => ({
  name,
  path: normalize(evidencePath),
  basename: basename(evidencePath)
}));

matrix.phases.forEach((phase, index) => {
  const request = externalRequests.requests[index];
  assert.equal(phase.id, `GAP-${String(index + 1).padStart(2, "0")}`, `phase ${index + 1} id mismatch`);
  assert.equal(phase.phase, request.phase, `phase ${index + 1} phase mismatch`);
  assert.equal(phase.title, request.title, `phase ${index + 1} title mismatch`);
  assert.equal(phase.blockerType, request.blockerType, `phase ${index + 1} blocker type mismatch`);
  assert.equal(phase.ownerRole, request.ownerRole, `phase ${index + 1} owner role mismatch`);
  assert.deepEqual(phase.evidenceKeys, request.evidenceKeys || [], `phase ${index + 1} evidence key mismatch`);
  assert.equal(phase.requiredInputCount, request.requiredInputs.length, `phase ${index + 1} required input count mismatch`);
  assert.equal(phase.commandCount, request.commands.length, `phase ${index + 1} command count mismatch`);
  assert.equal(phase.acceptanceCriteriaCount, request.acceptanceCriteria.length, `phase ${index + 1} acceptance criteria count mismatch`);
  assert.equal(phase.templateMappings.length, request.evidenceTemplates.length, `phase ${index + 1} template mapping count mismatch`);
  assert.equal(phase.missingArtifactCount, phase.templateMappings.filter((mapping) => !mapping.exists).length, `phase ${index + 1} missing artifact count mismatch`);
  assert.equal(phase.supportingArtifactCount, phase.templateMappings.filter((mapping) => mapping.coverage === "supporting-artifact").length, `phase ${index + 1} supporting artifact count mismatch`);
  assert.equal(phase.coveredByDeploymentBundle, phase.templateMappings.some((mapping) => mapping.coverage === "deployment-bundle"), `phase ${index + 1} deployment coverage mismatch`);
  assert.equal(phase.coveredByDeploymentBundle, true, `phase ${index + 1} must map to at least one deployment-bundle evidence artifact`);

  phase.templateMappings.forEach((mapping, mappingIndex) => {
    const templatePath = request.evidenceTemplates[mappingIndex];
    assert.equal(mapping.templatePath, normalize(templatePath), `phase ${index + 1} template ${mappingIndex + 1} path mismatch`);
    assert.ok(["deployment-bundle", "supporting-artifact"].includes(mapping.coverage), `phase ${index + 1} template ${mappingIndex + 1} coverage invalid`);
    assert.ok(mapping.resolvedPath && typeof mapping.resolvedPath === "string", `phase ${index + 1} template ${mappingIndex + 1} resolved path required`);
    assert.equal(mapping.exists, existsSync(mapping.resolvedPath), `phase ${index + 1} template ${mappingIndex + 1} existence is stale`);

    if (mapping.coverage === "deployment-bundle") {
      const matchingArtifact = bundleEvidence.find((artifact) => (
        artifact.name === mapping.bundleEvidenceName
        && (artifact.path === normalize(templatePath) || artifact.basename === basename(templatePath))
      ));
      assert.ok(matchingArtifact, `phase ${index + 1} template ${mappingIndex + 1} deployment evidence mapping mismatch`);
      assert.equal(mapping.evidenceKey, matchingArtifact.name, `phase ${index + 1} template ${mappingIndex + 1} evidence key mismatch`);
    } else {
      assert.equal(mapping.bundleEvidenceName, null, `phase ${index + 1} template ${mappingIndex + 1} supporting artifact cannot name bundle evidence`);
      assert.equal(mapping.evidenceKey, null, `phase ${index + 1} template ${mappingIndex + 1} supporting artifact cannot name evidence key`);
    }
  });
});

console.log(JSON.stringify({
  format: "sentinel-phase-gap-matrix-validation-v1",
  matrixPath,
  phaseCount: matrix.phases.length,
  evidenceKeyCount: matrix.summary.evidenceKeyCount,
  deploymentBundleCoveredPhaseCount: matrix.summary.deploymentBundleCoveredPhaseCount,
  missingArtifactCount: matrix.summary.missingArtifactCount,
  validated: true
}, null, 2));
