import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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

const rootDir = path.resolve(import.meta.dirname, "..");
const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const failOnBlockers = args.has("--fail-on-blockers");
const paths = {
  workspaceManifest: path.resolve(args.get("--workspace-manifest") || path.join(evidenceDir, "deployment-evidence-workspace-manifest.json")),
  bundle: path.resolve(args.get("--bundle") || path.join(evidenceDir, "deployment-evidence-bundle.json")),
  externalRequests: path.resolve(args.get("--external-requests") || path.join(evidenceDir, "external-evidence-requests.json")),
  completionAudit: path.resolve(args.get("--completion-audit") || path.join(evidenceDir, "phase-completion-audit.json")),
  readiness: path.resolve(args.get("--readiness") || path.join(evidenceDir, "phase-readiness.json")),
  handoff: path.resolve(args.get("--handoff") || path.join(evidenceDir, "phase-handoff-checklist.md")),
  phaseEvidenceManifest: path.resolve(args.get("--phase-evidence") || path.join(evidenceDir, "phase-evidence-pack-manifest.json"))
};

const requiredFiles = [
  "workspaceManifest",
  "bundle",
  "externalRequests",
  "completionAudit",
  "readiness",
  "handoff",
  "phaseEvidenceManifest"
];

for (const name of requiredFiles) {
  assert.ok(existsSync(paths[name]), `missing phase gate artifact ${name}: ${paths[name]}`);
}

const runJson = (script, scriptArgs) => {
  try {
    const output = execFileSync(process.execPath, [script, ...scriptArgs], {
      cwd: rootDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
    return { ok: true, result: JSON.parse(output), error: null };
  } catch (error) {
    const stderr = error.stderr?.toString().trim();
    const stdout = error.stdout?.toString().trim();
    return { ok: false, result: null, error: stderr || stdout || error.message };
  }
};

const checks = {
  workspace: runJson("scripts/validate-deployment-evidence-workspace.mjs", [
    "--manifest", paths.workspaceManifest,
    "--bundle", paths.bundle
  ]),
  externalRequests: runJson("scripts/validate-external-evidence-requests.mjs", [
    "--requests", paths.externalRequests,
    "--strict"
  ]),
  completionAudit: runJson("scripts/validate-phase-completion-audit.mjs", [
    "--audit", paths.completionAudit,
    "--external-requests", paths.externalRequests
  ]),
  phaseHandoff: runJson("scripts/validate-phase-handoff-checklist.mjs", [
    "--checklist", paths.handoff,
    "--readiness", paths.readiness,
    "--external-requests", paths.externalRequests
  ]),
  phaseEvidence: runJson("scripts/validate-phase-evidence-pack.mjs", [
    "--manifest", paths.phaseEvidenceManifest
  ])
};

const readiness = JSON.parse(readFileSync(paths.readiness, "utf8"));
const completionAudit = JSON.parse(readFileSync(paths.completionAudit, "utf8"));
const phaseEvidence = JSON.parse(readFileSync(paths.phaseEvidenceManifest, "utf8"));

assert.equal(readiness.format, "sentinel-phase-readiness-report-v1");
assert.equal(completionAudit.format, "sentinel-phase-completion-audit-v1");
assert.equal(phaseEvidence.format, "sentinel-phase-evidence-pack-manifest-v1");
assert.equal(phaseEvidence.artifacts.phaseReadiness.path, paths.readiness, "phase evidence pack must reference the selected readiness report");
assert.equal(phaseEvidence.artifacts.phaseCompletionAudit.path, paths.completionAudit, "phase evidence pack must reference the selected completion audit");
assert.equal(phaseEvidence.artifacts.externalRequests.path, paths.externalRequests, "phase evidence pack must reference the selected external request pack");
assert.equal(phaseEvidence.artifacts.phaseHandoffChecklist.path, paths.handoff, "phase evidence pack must reference the selected handoff checklist");
assert.equal(phaseEvidence.artifacts.deploymentWorkspaceManifest.path, paths.workspaceManifest, "phase evidence pack must reference the selected workspace manifest");

const failedChecks = Object.entries(checks)
  .filter(([, check]) => !check.ok)
  .map(([name, check]) => ({ name, error: check.error }));

const blockerCount = readiness.blockers?.length || 0;
const warningCount = readiness.warnings?.length || 0;
const report = {
  format: "sentinel-phase-gate-validation-v1",
  evidenceDir,
  generatedAt: new Date().toISOString(),
  failOnBlockers,
  paths,
  checks: Object.fromEntries(Object.entries(checks).map(([name, check]) => [name, { ok: check.ok, error: check.error }])),
  ready: failedChecks.length === 0 && readiness.ready && completionAudit.complete,
  blockerCount,
  warningCount,
  remainingPhaseCount: completionAudit.remainingPhaseCount,
  remainingItemCount: completionAudit.remainingItemCount,
  failedChecks,
  validated: failedChecks.length === 0
};

console.log(JSON.stringify(report, null, 2));

if (failedChecks.length > 0) {
  process.exitCode = 1;
} else if (failOnBlockers && !report.ready) {
  process.exitCode = 1;
}
