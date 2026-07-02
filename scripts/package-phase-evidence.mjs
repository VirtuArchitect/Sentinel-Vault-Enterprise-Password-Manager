import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-evidence-pack-manifest.json"));

const artifactMap = {
  deploymentWorkspaceManifest: args.get("--workspace-manifest") || path.join(evidenceDir, "deployment-evidence-workspace-manifest.json"),
  deploymentBundle: args.get("--bundle") || path.join(evidenceDir, "deployment-evidence-bundle.json"),
  deploymentStatus: args.get("--deployment-status") || path.join(evidenceDir, "deployment-evidence-status.json"),
  deploymentRedaction: args.get("--deployment-redaction") || path.join(evidenceDir, "deployment-redaction-report.json"),
  deploymentRedactionMarkdown: args.get("--deployment-redaction-markdown") || path.join(evidenceDir, "deployment-redaction-report.md"),
  externalRequests: args.get("--external-requests") || path.join(evidenceDir, "external-evidence-requests.json"),
  externalRequestsMarkdown: args.get("--external-requests-markdown") || path.join(evidenceDir, "external-evidence-requests.md"),
  phaseCompletionAudit: args.get("--phase-completion") || path.join(evidenceDir, "phase-completion-audit.json"),
  phaseCompletionAuditMarkdown: args.get("--phase-completion-markdown") || path.join(evidenceDir, "phase-completion-audit.md"),
  phaseReadiness: args.get("--readiness") || path.join(evidenceDir, "phase-readiness.json"),
  phaseReadinessMarkdown: args.get("--readiness-markdown") || path.join(evidenceDir, "phase-readiness.md"),
  phaseHandoffChecklist: args.get("--handoff") || path.join(evidenceDir, "phase-handoff-checklist.md")
};

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    path: path.resolve(filePath),
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

for (const [name, filePath] of Object.entries(artifactMap)) {
  assert.ok(existsSync(filePath), `Missing phase evidence artifact ${name}: ${filePath}`);
}

const readiness = JSON.parse(readFileSync(artifactMap.phaseReadiness, "utf8"));
const externalRequests = JSON.parse(readFileSync(artifactMap.externalRequests, "utf8"));
const workspaceManifest = JSON.parse(readFileSync(artifactMap.deploymentWorkspaceManifest, "utf8"));
const deploymentStatus = JSON.parse(readFileSync(artifactMap.deploymentStatus, "utf8"));
const deploymentRedaction = JSON.parse(readFileSync(artifactMap.deploymentRedaction, "utf8"));
const phaseCompletion = JSON.parse(readFileSync(artifactMap.phaseCompletionAudit, "utf8"));

assert.equal(readiness.format, "sentinel-phase-readiness-report-v1");
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(workspaceManifest.format, "sentinel-deployment-evidence-workspace-manifest-v1");
assert.equal(deploymentStatus.format, "sentinel-deployment-evidence-status-v1");
assert.equal(deploymentRedaction.format, "sentinel-deployment-redaction-report-v1");
assert.equal(phaseCompletion.format, "sentinel-phase-completion-audit-v1");
assert.equal(workspaceManifest.environment, readiness.bundle.environment, "workspace manifest environment does not match readiness report");
assert.equal(workspaceManifest.status, readiness.bundle.status, "workspace manifest status does not match readiness report");
assert.equal(path.resolve(deploymentRedaction.bundle), path.resolve(artifactMap.deploymentBundle), "deployment redaction bundle path does not match phase evidence bundle");

const artifacts = Object.fromEntries(Object.entries(artifactMap).map(([name, filePath]) => [name, hashFile(filePath)]));

const manifest = {
  format: "sentinel-phase-evidence-pack-manifest-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  environment: readiness.bundle.environment,
  target: readiness.target,
  bundleStatus: readiness.bundle.status,
  ready: readiness.ready,
  blockerCount: readiness.blockers?.length || 0,
  warningCount: readiness.warnings?.length || 0,
  requestCount: externalRequests.requests?.length || 0,
  remainingPhaseCount: phaseCompletion.remainingPhaseCount,
  remainingItemCount: phaseCompletion.remainingItemCount,
  remainingExternallyCovered: phaseCompletion.externallyCovered,
  deploymentEvidenceSummary: deploymentStatus.summary,
  deploymentRedactionSummary: deploymentRedaction.summary,
  artifacts
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(manifest, null, 2));

console.log(JSON.stringify({
  format: "sentinel-phase-evidence-pack-result-v1",
  outputPath,
  artifactCount: Object.keys(artifacts).length,
  ready: manifest.ready,
  blockerCount: manifest.blockerCount
}, null, 2));
