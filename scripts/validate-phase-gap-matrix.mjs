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
const markdownPath = args.get("--markdown") ? path.resolve(args.get("--markdown")) : null;
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
assert.equal(matrix.summary.commandScriptCount, matrix.summary.commandScripts?.length || 0, "summary command script count mismatch");
assert.equal(matrix.summary.missingArtifactCount, matrix.phases.reduce((total, phase) => total + phase.missingArtifactCount, 0), "summary missing artifact count mismatch");
assert.equal(matrix.summary.supportingArtifactCount, matrix.phases.reduce((total, phase) => total + phase.supportingArtifactCount, 0), "summary supporting artifact count mismatch");
assert.equal(matrix.summary.deploymentBundleCoveredPhaseCount, matrix.phases.filter((phase) => phase.coveredByDeploymentBundle).length, "summary deployment bundle coverage count mismatch");

const externalRequests = requestsPath ? readJson(requestsPath) : readJson(matrix.externalRequestsPath);
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(matrix.phases.length, externalRequests.requests.length, "phase gap matrix request count mismatch");
const requiredValidatorCommands = [
  "pnpm plan:postgres",
  "pnpm validate:storage-migration",
  "pnpm validate:tenant-isolation",
  "pnpm validate:connector-evidence",
  "pnpm validate:siem-rotation",
  "pnpm validate:windows-package",
  "pnpm validate:windows-release",
  "pnpm validate:windows-signing",
  "pnpm validate:kms-hsm-sdk-approval",
  "pnpm validate:kms-hsm-evidence",
  "pnpm validate:browser-identity",
  "pnpm validate:browser-rollout",
  "pnpm validate:credential-provider-approval",
  "pnpm validate:native-companion"
];
const allCommands = externalRequests.requests.flatMap((request) => request.commands);
const validatorCommandCount = requiredValidatorCommands.filter((command) => (
  allCommands.some((candidate) => candidate.startsWith(command))
)).length;
assert.equal(matrix.summary.commandScriptCount, externalRequests.summary?.commandScriptCount || 0, "summary request command script count mismatch");
assert.equal(matrix.summary.validatorCommandCount, validatorCommandCount, "summary validator command count mismatch");
assert.deepEqual(matrix.summary.commandScripts, externalRequests.summary?.commandScripts || [], "summary command scripts mismatch");

if (markdownPath) {
  assert.ok(existsSync(markdownPath), `Phase gap matrix markdown not found: ${markdownPath}`);
  const markdown = readFileSync(markdownPath, "utf8");
  assert.ok(markdown.includes("## Command Coverage Summary"), "markdown must include command coverage summary");
  assert.ok(markdown.includes(`- Command scripts: ${matrix.summary.commandScriptCount}`), "markdown command script count mismatch");
  assert.ok(markdown.includes(`- Validator commands: ${matrix.summary.validatorCommandCount}`), "markdown validator command count mismatch");
  for (const script of matrix.summary.commandScripts) {
    assert.ok(markdown.includes(`- \`pnpm ${script}\``), `markdown missing command script coverage: ${script}`);
  }
}

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
  assert.deepEqual(phase.commandScripts, request.commands.map((command) => command.match(/^pnpm\s+([^\s]+)/)?.[1]).filter(Boolean), `phase ${index + 1} command scripts mismatch`);
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
  commandScriptCount: matrix.summary.commandScriptCount,
  validatorCommandCount: matrix.summary.validatorCommandCount,
  deploymentBundleCoveredPhaseCount: matrix.summary.deploymentBundleCoveredPhaseCount,
  missingArtifactCount: matrix.summary.missingArtifactCount,
  validated: true
}, null, 2));
