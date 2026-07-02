import assert from "node:assert/strict";
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

const rootDir = path.resolve(import.meta.dirname, "..");
const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const bundlePath = path.resolve(args.get("--bundle") || path.join(evidenceDir, "deployment-evidence-bundle.json"));
const requestsPath = path.resolve(args.get("--external-requests") || path.join(evidenceDir, "external-evidence-requests.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-gap-matrix.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join(evidenceDir, "phase-gap-matrix.md"));

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const normalize = (filePath) => filePath.replaceAll("\\", "/");
const basename = (filePath) => path.basename(normalize(filePath));
const resolveBundlePath = (candidate) => {
  const bundleRelative = path.resolve(path.dirname(bundlePath), candidate);
  if (existsSync(bundleRelative)) return bundleRelative;
  return path.resolve(rootDir, candidate);
};

assert.ok(existsSync(bundlePath), `Deployment evidence bundle not found: ${bundlePath}`);
assert.ok(existsSync(requestsPath), `External evidence requests not found: ${requestsPath}`);

const bundle = readJson(bundlePath);
const requests = readJson(requestsPath);

assert.equal(bundle.format, "sentinel-deployment-evidence-bundle-v1");
assert.equal(requests.format, "sentinel-external-evidence-requests-v1");

const bundleEvidence = Object.entries(bundle.evidence || {}).map(([name, evidencePath]) => ({
  name,
  templatePath: normalize(evidencePath),
  basename: basename(evidencePath),
  resolvedPath: resolveBundlePath(evidencePath)
}));

const findEvidence = (templatePath) => bundleEvidence.find((artifact) => (
  artifact.templatePath === normalize(templatePath) || artifact.basename === basename(templatePath)
));

const phases = requests.requests.map((request, index) => {
  const templateMappings = request.evidenceTemplates.map((templatePath) => {
    const bundleArtifact = findEvidence(templatePath);
    const resolvedPath = bundleArtifact ? bundleArtifact.resolvedPath : path.resolve(rootDir, templatePath);
    const exists = existsSync(resolvedPath);
    return {
      templatePath: normalize(templatePath),
      coverage: bundleArtifact ? "deployment-bundle" : "supporting-artifact",
      evidenceKey: bundleArtifact?.name || null,
      bundleEvidenceName: bundleArtifact?.name || null,
      resolvedPath,
      exists
    };
  });

  return {
    id: `GAP-${String(index + 1).padStart(2, "0")}`,
    phase: request.phase,
    title: request.title,
    blockerType: request.blockerType,
    ownerRole: request.ownerRole,
    evidenceKeys: request.evidenceKeys || [],
    requiredInputCount: request.requiredInputs.length,
    commandCount: request.commands.length,
    acceptanceCriteriaCount: request.acceptanceCriteria.length,
    templateMappings,
    coveredByDeploymentBundle: templateMappings.some((mapping) => mapping.coverage === "deployment-bundle"),
    supportingArtifactCount: templateMappings.filter((mapping) => mapping.coverage === "supporting-artifact").length,
    missingArtifactCount: templateMappings.filter((mapping) => !mapping.exists).length
  };
});

const report = {
  format: "sentinel-phase-gap-matrix-v1",
  generatedAt: new Date().toISOString(),
  environment: bundle.environment,
  owner: bundle.owner,
  status: bundle.status,
  bundlePath,
  externalRequestsPath: requestsPath,
  summary: {
    phaseCount: phases.length,
    deploymentBundleEvidenceCount: bundleEvidence.length,
    evidenceKeyCount: new Set(phases.flatMap((phase) => phase.evidenceKeys)).size,
    deploymentBundleCoveredPhaseCount: phases.filter((phase) => phase.coveredByDeploymentBundle).length,
    missingArtifactCount: phases.reduce((total, phase) => total + phase.missingArtifactCount, 0),
    supportingArtifactCount: phases.reduce((total, phase) => total + phase.supportingArtifactCount, 0)
  },
  phases
};

const renderMarkdown = () => `# Sentinel Vault Phase Gap Matrix

Environment: ${report.environment}
Owner: ${report.owner}
Status: ${report.status}
Generated: ${report.generatedAt}

This matrix maps each remaining phase blocker to deployment-bundle evidence and supporting artifacts so release reviewers can see which files prove each phase.

${phases.map((phase) => `## ${phase.id}: ${phase.phase} - ${phase.title}

Owner role: ${phase.ownerRole}
Blocker type: ${phase.blockerType}
Deployment-bundle coverage: ${phase.coveredByDeploymentBundle ? "yes" : "no"}

Evidence mapping:
${phase.templateMappings.map((mapping) => `- ${mapping.coverage}: \`${mapping.templatePath}\`${mapping.evidenceKey ? ` -> \`${mapping.evidenceKey}\`` : ""}${mapping.exists ? "" : " (missing)"}`).join("\n")}

Operator workload:
- Required inputs: ${phase.requiredInputCount}
- Commands: ${phase.commandCount}
- Acceptance criteria: ${phase.acceptanceCriteriaCount}`).join("\n\n")}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(report, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-phase-gap-matrix-result-v1",
  outputPath,
  markdownPath,
  phaseCount: report.summary.phaseCount,
  deploymentBundleCoveredPhaseCount: report.summary.deploymentBundleCoveredPhaseCount,
  missingArtifactCount: report.summary.missingArtifactCount
}, null, 2));
