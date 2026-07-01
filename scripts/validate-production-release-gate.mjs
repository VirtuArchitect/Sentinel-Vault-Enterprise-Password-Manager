import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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
const target = args.get("--target") || "production";
const requireClean = args.get("--require-clean") === true || args.get("--require-clean") === "true";
const outputPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const allowedTargets = new Set(["pilot", "production"]);

const paths = {
  bundle: path.resolve(args.get("--bundle") || path.join(evidenceDir, "deployment-evidence-bundle.json")),
  workspaceManifest: path.resolve(args.get("--workspace-manifest") || path.join(evidenceDir, "deployment-evidence-workspace-manifest.json")),
  externalRequests: path.resolve(args.get("--external-requests") || path.join(evidenceDir, "external-evidence-requests.json")),
  phaseEvidence: path.resolve(args.get("--phase-evidence") || path.join(evidenceDir, "phase-evidence-pack-manifest.json")),
  phaseGate: path.resolve(args.get("--phase-gate") || path.join(evidenceDir, "phase-gate-validation.json")),
  phaseActions: path.resolve(args.get("--phase-actions") || path.join(evidenceDir, "phase-action-register.json")),
  phaseGaps: path.resolve(args.get("--phase-gaps") || path.join(evidenceDir, "phase-gap-matrix.json")),
  phaseDecision: path.resolve(args.get("--phase-decision") || path.join(evidenceDir, "phase-decision-record.json")),
  phaseSignoffs: path.resolve(args.get("--phase-signoffs") || path.join(evidenceDir, "phase-signoff-matrix.json")),
  phaseIntake: path.resolve(args.get("--phase-intake") || path.join(evidenceDir, "phase-evidence-intake.json")),
  phaseAttachments: path.resolve(args.get("--phase-attachments") || path.join(evidenceDir, "phase-attachment-inventory.json")),
  phaseWaivers: path.resolve(args.get("--phase-waivers") || path.join(evidenceDir, "phase-waiver-register.json")),
  phaseReview: path.resolve(args.get("--phase-review") || path.join(evidenceDir, "phase-review-bundle-manifest.json")),
  phaseClosure: path.resolve(args.get("--phase-closure") || path.join(evidenceDir, "phase-closure-archive-manifest.json"))
};

assert.ok(allowedTargets.has(target), "--target must be pilot or production");

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

const readJsonIfPresent = (filePath) => existsSync(filePath) ? JSON.parse(readFileSync(filePath, "utf8")) : null;
const blockers = [];
const warnings = [];

for (const [name, filePath] of Object.entries(paths)) {
  if (!existsSync(filePath)) {
    blockers.push({
      gate: `artifact.${name}`,
      severity: "blocking",
      message: `Required release artifact not found: ${filePath}`
    });
  }
}

const checks = {
  deploymentWorkspace: existsSync(paths.workspaceManifest) && existsSync(paths.bundle)
    ? runJson("scripts/validate-deployment-evidence-workspace.mjs", [
      "--manifest", paths.workspaceManifest,
      "--bundle", paths.bundle
    ])
    : { ok: false, result: null, error: "Deployment evidence workspace manifest or bundle is missing" },
  deploymentEvidence: existsSync(paths.bundle)
    ? runJson("scripts/validate-deployment-evidence-bundle.mjs", [paths.bundle])
    : { ok: false, result: null, error: `Deployment evidence bundle not found: ${paths.bundle}` },
  deploymentRedaction: existsSync(paths.bundle)
    ? runJson("scripts/report-deployment-redaction.mjs", [
      "--bundle", paths.bundle,
      "--fail-on-findings"
    ])
    : { ok: false, result: null, error: `Deployment evidence bundle not found: ${paths.bundle}` },
  externalEvidence: existsSync(paths.externalRequests)
    ? runJson("scripts/validate-external-evidence-requests.mjs", [
      "--requests", paths.externalRequests,
      "--strict"
    ])
    : { ok: false, result: null, error: `External evidence request pack not found: ${paths.externalRequests}` },
  phaseReadiness: existsSync(paths.bundle) && existsSync(paths.externalRequests)
    ? runJson("scripts/report-phase-readiness.mjs", [
      "--bundle", paths.bundle,
      "--external-requests", paths.externalRequests,
      "--target", target
    ])
    : { ok: false, result: null, error: "Deployment bundle or external evidence request pack is missing" },
  phaseEvidence: existsSync(paths.phaseEvidence)
    ? runJson("scripts/validate-phase-evidence-pack.mjs", [
      "--manifest", paths.phaseEvidence
    ])
    : { ok: false, result: null, error: `Phase evidence pack manifest not found: ${paths.phaseEvidence}` },
  phaseGate: existsSync(paths.phaseGate)
    ? runJson("scripts/validate-phase-gate.mjs", [
      "--dir", evidenceDir
    ])
    : { ok: false, result: null, error: `Phase gate validation report not found: ${paths.phaseGate}` },
  phaseActions: existsSync(paths.phaseActions) && existsSync(paths.phaseGate) && existsSync(paths.externalRequests)
    ? runJson("scripts/validate-phase-action-register.mjs", [
      "--register", paths.phaseActions,
      "--phase-gate", paths.phaseGate,
      "--external-requests", paths.externalRequests
    ])
    : { ok: false, result: null, error: "Phase action register, phase gate, or external evidence request pack is missing" },
  phaseGaps: existsSync(paths.phaseGaps) && existsSync(paths.bundle) && existsSync(paths.externalRequests)
    ? runJson("scripts/validate-phase-gap-matrix.mjs", [
      "--matrix", paths.phaseGaps,
      "--bundle", paths.bundle,
      "--external-requests", paths.externalRequests
    ])
    : { ok: false, result: null, error: "Phase gap matrix, deployment bundle, or external evidence request pack is missing" },
  phaseDecision: existsSync(paths.phaseDecision) && existsSync(paths.phaseGate) && existsSync(paths.phaseActions) && existsSync(paths.phaseGaps)
    ? runJson("scripts/validate-phase-decision-record.mjs", [
      "--record", paths.phaseDecision,
      "--phase-gate", paths.phaseGate,
      "--phase-actions", paths.phaseActions,
      "--phase-gaps", paths.phaseGaps
    ])
    : { ok: false, result: null, error: "Phase decision record, phase gate, action register, or gap matrix is missing" },
  phaseSignoffs: existsSync(paths.phaseSignoffs) && existsSync(paths.phaseDecision) && existsSync(paths.phaseActions)
    ? runJson("scripts/validate-phase-signoff-matrix.mjs", [
      "--matrix", paths.phaseSignoffs,
      "--phase-decision", paths.phaseDecision,
      "--phase-actions", paths.phaseActions
    ])
    : { ok: false, result: null, error: "Phase signoff matrix, decision record, or action register is missing" },
  phaseIntake: existsSync(paths.phaseIntake) && existsSync(paths.externalRequests) && existsSync(paths.phaseGaps) && existsSync(paths.phaseSignoffs)
    ? runJson("scripts/validate-phase-evidence-intake.mjs", [
      "--intake", paths.phaseIntake,
      "--external-requests", paths.externalRequests,
      "--phase-gaps", paths.phaseGaps,
      "--phase-signoffs", paths.phaseSignoffs
    ])
    : { ok: false, result: null, error: "Phase evidence intake, external requests, gap matrix, or signoff matrix is missing" },
  phaseAttachments: existsSync(paths.phaseAttachments) && existsSync(paths.phaseIntake)
    ? runJson("scripts/validate-phase-attachment-inventory.mjs", [
      "--inventory", paths.phaseAttachments,
      "--intake", paths.phaseIntake,
      "--require-redacted"
    ])
    : { ok: false, result: null, error: "Phase attachment inventory or evidence intake is missing" },
  phaseWaivers: existsSync(paths.phaseWaivers) && existsSync(paths.phaseAttachments) && existsSync(paths.phaseDecision)
    ? runJson("scripts/validate-phase-waiver-register.mjs", [
      "--register", paths.phaseWaivers,
      "--attachments", paths.phaseAttachments,
      "--phase-decision", paths.phaseDecision,
      "--require-approved"
    ])
    : { ok: false, result: null, error: "Phase waiver register, attachment inventory, or decision record is missing" },
  phaseReview: existsSync(paths.phaseReview)
    ? runJson("scripts/validate-phase-review-bundle.mjs", [
      "--manifest", paths.phaseReview,
      "--require-approved-waivers"
    ])
    : { ok: false, result: null, error: `Phase review bundle not found: ${paths.phaseReview}` },
  phaseClosure: existsSync(paths.phaseClosure) && existsSync(paths.phaseReview)
    ? runJson("scripts/validate-phase-closure-archive.mjs", [
      "--manifest", paths.phaseClosure,
      "--phase-review", paths.phaseReview,
      "--require-approved-waivers",
      ...(requireClean ? ["--require-clean"] : [])
    ])
    : { ok: false, result: null, error: "Phase closure archive or review bundle is missing" }
};

for (const [name, check] of Object.entries(checks)) {
  if (!check.ok) {
    blockers.push({
      gate: name,
      severity: "blocking",
      message: check.error
    });
  }
}

const bundle = readJsonIfPresent(paths.bundle);
const review = readJsonIfPresent(paths.phaseReview);
const closure = readJsonIfPresent(paths.phaseClosure);
const readiness = checks.phaseReadiness.result;

if (bundle) {
  if (bundle.status !== target) {
    blockers.push({
      gate: "deployment-target",
      severity: "blocking",
      message: `Bundle status is ${bundle.status}; release target is ${target}`
    });
  }
}

if (readiness) {
  if (!readiness.ready) {
    blockers.push({
      gate: "phase-readiness",
      severity: "blocking",
      message: "Phase readiness still reports blockers",
      blockerCount: readiness.blockers?.length || 0
    });
  }
}

if (checks.deploymentRedaction.result && !checks.deploymentRedaction.result.readyForRelease) {
  blockers.push({
    gate: "deployment-redaction",
    severity: "blocking",
    message: "Deployment evidence redaction report has findings",
    findingCount: checks.deploymentRedaction.result.summary?.findingCount || 0
  });
}

if (review) {
  assert.equal(review.format, "sentinel-phase-review-bundle-manifest-v1");
  if (!review.ready || review.blockerCount !== 0 || review.remainingPhaseCount !== 0 || review.remainingItemCount !== 0) {
    blockers.push({
      gate: "phase-review",
      severity: "blocking",
      message: "Phase review bundle is not closure-ready",
      ready: review.ready,
      blockerCount: review.blockerCount,
      remainingPhaseCount: review.remainingPhaseCount,
      remainingItemCount: review.remainingItemCount
    });
  }
  if (review.decision !== "approve-phase-closure") {
    blockers.push({
      gate: "phase-decision",
      severity: "blocking",
      message: `Phase decision is ${review.decision}; expected approve-phase-closure`
    });
  }
}

if (closure) {
  assert.equal(closure.format, "sentinel-phase-closure-archive-manifest-v1");
  if (closure.review?.target !== target) {
    blockers.push({
      gate: "closure-target",
      severity: "blocking",
      message: `Closure archive target is ${closure.review?.target}; release target is ${target}`
    });
  }
  if (requireClean && !closure.source?.cleanTree) {
    blockers.push({
      gate: "source-provenance",
      severity: "blocking",
      message: "Closure archive source tree is not clean"
    });
  } else if (!closure.source?.cleanTree) {
    warnings.push({
      gate: "source-provenance",
      severity: "warning",
      message: "Closure archive was generated from a dirty source tree"
    });
  }
}

const report = {
  format: "sentinel-production-release-gate-v1",
  generatedAt: new Date().toISOString(),
  target,
  requireClean,
  evidenceDir,
  paths,
  checks: Object.fromEntries(Object.entries(checks).map(([name, check]) => [name, {
    ok: check.ok,
    error: check.error
  }])),
  ready: blockers.length === 0,
  blockerCount: blockers.length,
  warningCount: warnings.length,
  blockers,
  warnings
};

const text = JSON.stringify(report, null, 2);
if (outputPath) {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, text);
}
console.log(text);

if (!report.ready) {
  process.exitCode = 1;
}
