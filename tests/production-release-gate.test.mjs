import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const createReleaseGateWorkspace = (dir) => {
  runScript("scripts/prepare-deployment-evidence-workspace.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out-dir", dir
  ]);
  runScript("scripts/validate-deployment-evidence-workspace.mjs", [
    "--manifest", path.join(dir, "deployment-evidence-workspace-manifest.json"),
    "--bundle", path.join(dir, "deployment-evidence-bundle.json")
  ]);
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", path.join(dir, "external-evidence-requests.json"),
    "--markdown-out", path.join(dir, "external-evidence-requests.md")
  ]);
  runScript("scripts/validate-external-evidence-requests.mjs", [
    "--requests", path.join(dir, "external-evidence-requests.json"),
    "--strict"
  ]);
  runScript("scripts/report-deployment-evidence-status.mjs", [
    "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
    "--out", path.join(dir, "deployment-evidence-status.json")
  ]);
  runScript("scripts/report-phase-completion-audit.mjs", [
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-completion-audit.json"),
    "--markdown-out", path.join(dir, "phase-completion-audit.md")
  ]);
  runScript("scripts/validate-phase-completion-audit.mjs", [
    "--audit", path.join(dir, "phase-completion-audit.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json")
  ]);
  runScript("scripts/report-phase-readiness.mjs", [
    "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-readiness.json"),
    "--markdown-out", path.join(dir, "phase-readiness.md")
  ]);
  runScript("scripts/prepare-phase-handoff-checklist.mjs", [
    "--readiness", path.join(dir, "phase-readiness.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-handoff-checklist.md")
  ]);
  runScript("scripts/validate-phase-handoff-checklist.mjs", [
    "--checklist", path.join(dir, "phase-handoff-checklist.md"),
    "--readiness", path.join(dir, "phase-readiness.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json")
  ]);
  runScript("scripts/package-phase-evidence.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-evidence-pack-manifest.json")
  ]);
  runScript("scripts/validate-phase-gate.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-gate-validation.json"),
    "--markdown-out", path.join(dir, "phase-gate-validation.md")
  ]);
  runScript("scripts/prepare-phase-action-register.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-action-register.json"),
    "--markdown-out", path.join(dir, "phase-action-register.md")
  ]);
  runScript("scripts/prepare-phase-gap-matrix.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-gap-matrix.json"),
    "--markdown-out", path.join(dir, "phase-gap-matrix.md")
  ]);
  runScript("scripts/prepare-phase-decision-record.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-decision-record.json"),
    "--markdown-out", path.join(dir, "phase-decision-record.md")
  ]);
  runScript("scripts/prepare-phase-signoff-matrix.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-signoff-matrix.json"),
    "--markdown-out", path.join(dir, "phase-signoff-matrix.md")
  ]);
  runScript("scripts/prepare-phase-evidence-intake.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-evidence-intake.json"),
    "--markdown-out", path.join(dir, "phase-evidence-intake.md")
  ]);
  runScript("scripts/prepare-phase-attachment-inventory.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-attachment-inventory.json"),
    "--markdown-out", path.join(dir, "phase-attachment-inventory.md")
  ]);
  runScript("scripts/prepare-phase-waiver-register.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-waiver-register.json"),
    "--markdown-out", path.join(dir, "phase-waiver-register.md")
  ]);
  runScript("scripts/package-phase-review-bundle.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-review-bundle-manifest.json")
  ]);
  runScript("scripts/package-phase-closure-archive.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-closure-archive-manifest.json")
  ]);
};

test("production release gate rejects missing release artifacts", () => {
  const dir = path.join(tmpdir(), `sentinel-release-gate-missing-${process.pid}-${Date.now()}`);
  try {
    const outputPath = path.join(dir, "release-gate.json");
    assert.throws(() => runScript("scripts/validate-production-release-gate.mjs", [
      "--dir", dir,
      "--out", outputPath
    ]), (error) => {
      assert.equal(error.status, 1);
      const report = JSON.parse(error.stdout.toString());
      assert.equal(report.format, "sentinel-production-release-gate-v1");
      assert.equal(report.ready, false);
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.bundle"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.workspaceManifest"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.externalRequests"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseEvidence"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseGate"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseActions"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseGaps"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseDecision"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseSignoffs"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseIntake"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseAttachments"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "artifact.phaseWaivers"));
      assert.ok(existsSync(outputPath));
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production release gate rejects placeholder phase workspaces", () => {
  const dir = path.join(tmpdir(), `sentinel-release-gate-placeholder-${process.pid}-${Date.now()}`);
  try {
    createReleaseGateWorkspace(dir);
    const outputPath = path.join(dir, "release-gate.json");

    assert.throws(() => runScript("scripts/validate-production-release-gate.mjs", [
      "--dir", dir,
      "--out", outputPath
    ]), (error) => {
      assert.equal(error.status, 1);
      const report = JSON.parse(error.stdout.toString());
      assert.equal(report.format, "sentinel-production-release-gate-v1");
      assert.equal(report.ready, false);
      assert.equal(report.checks.deploymentWorkspace.ok, true);
      assert.equal(report.checks.externalEvidence.ok, true);
      assert.equal(report.checks.phaseEvidence.ok, true);
      assert.equal(report.checks.phaseGate.ok, true);
      assert.equal(report.checks.phaseActions.ok, true);
      assert.equal(report.checks.phaseGaps.ok, true);
      assert.equal(report.checks.phaseDecision.ok, true);
      assert.equal(report.checks.phaseSignoffs.ok, true);
      assert.equal(report.checks.phaseIntake.ok, true);
      assert.equal(report.checks.phaseAttachments.ok, true);
      assert.equal(report.checks.phaseWaivers.ok, false);
      assert.ok(report.blockers.some((blocker) => blocker.gate === "phaseWaivers"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "deployment-target"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "phase-readiness"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "phase-review"));
      assert.ok(report.blockers.some((blocker) => blocker.gate === "phase-decision"));

      const saved = JSON.parse(readFileSync(outputPath, "utf8"));
      assert.equal(saved.blockerCount, report.blockerCount);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
