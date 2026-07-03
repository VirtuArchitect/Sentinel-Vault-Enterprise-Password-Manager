import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const createReleaseArchiveWorkspace = (dir) => {
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
  runScript("scripts/report-deployment-redaction.mjs", [
    "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
    "--out", path.join(dir, "deployment-redaction-report.json"),
    "--markdown-out", path.join(dir, "deployment-redaction-report.md"),
    "--fail-on-findings"
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
    "--target", "production",
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
  assert.throws(() => runScript("scripts/validate-production-release-gate.mjs", [
    "--dir", dir,
    "--target", "production",
    "--out", path.join(dir, "production-release-gate.json")
  ]), { status: 1 });
};

test("production release archive binds closure archive and release gate report", () => {
  const dir = path.join(tmpdir(), `sentinel-release-archive-${process.pid}-${Date.now()}`);
  try {
    createReleaseArchiveWorkspace(dir);
    const archivePath = path.join(dir, "production-release-archive-manifest.json");

    const result = JSON.parse(runScript("scripts/package-production-release-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]));

    assert.equal(result.format, "sentinel-production-release-archive-result-v1");
    assert.equal(result.target, "production");
    assert.equal(result.ready, false);
    assert.ok(result.blockerCount > 0);
    assert.ok(result.commandScriptCount > 20);
    assert.equal(result.validatorCommandCount, 15);
    assert.ok(existsSync(archivePath));

    const archive = JSON.parse(readFileSync(archivePath, "utf8"));
    assert.equal(archive.format, "sentinel-production-release-archive-manifest-v1");
    assert.match(archive.closure.manifest.sha256, /^[a-f0-9]{64}$/);
    assert.match(archive.releaseGate.report.sha256, /^[a-f0-9]{64}$/);
    assert.equal(archive.closure.evidenceKeySummary.waivedEvidenceKeyCount, 18);
    assert.ok(archive.closure.evidenceKeySummary.waivedEvidenceKeys.includes("windowsSigning"));
    assert.ok(archive.closure.commandCoverageSummary.signoffCommandScriptCount > 20);
    assert.equal(archive.closure.commandCoverageSummary.signoffValidatorCommandCount, 15);
    assert.ok(archive.closure.commandCoverageSummary.signoffCommandScripts.includes("validate:windows-signing"));
    assert.equal(archive.closure.markdownCoverageSummary.artifactCount, 7);
    assert.equal(archive.closure.markdownCoverageSummary.validatorCommandCount, 15);
    assert.deepEqual(archive.releaseGate.commandCoverageSummary, archive.closure.commandCoverageSummary);

    const validation = JSON.parse(runScript("scripts/validate-production-release-archive.mjs", [
      "--manifest", archivePath,
      "--dir", dir,
      "--target", "production"
    ]));
    assert.equal(validation.format, "sentinel-production-release-archive-validation-v1");
    assert.equal(validation.ready, false);
    assert.equal(validation.requireClean, false);
    assert.equal(validation.waivedEvidenceKeyCount, 18);
    assert.ok(validation.commandScriptCount > 20);
    assert.equal(validation.validatorCommandCount, 15);
    assert.equal(validation.commandCoverageMarkdownArtifactCount, 7);
    assert.equal(validation.closureValidated, true);
    assert.equal(validation.releaseGateValidated, true);
    assert.equal(validation.validated, true);

    assert.throws(() => runScript("scripts/validate-production-release-archive.mjs", [
      "--manifest", archivePath,
      "--dir", dir,
      "--target", "production",
      "--require-clean"
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /archive clean-source validation mode mismatch/);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production release archive rejects changed release gate reports and not-ready release mode", () => {
  const dir = path.join(tmpdir(), `sentinel-release-archive-tamper-${process.pid}-${Date.now()}`);
  try {
    createReleaseArchiveWorkspace(dir);
    const archivePath = path.join(dir, "production-release-archive-manifest.json");
    const releaseGatePath = path.join(dir, "production-release-gate.json");
    runScript("scripts/package-production-release-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]);

    const releaseGate = JSON.parse(readFileSync(releaseGatePath, "utf8"));
    releaseGate.ready = true;
    releaseGate.blockerCount = 0;
    releaseGate.blockers = [];
    writeFileSync(releaseGatePath, JSON.stringify(releaseGate, null, 2));

    assert.throws(() => runScript("scripts/validate-production-release-archive.mjs", [
      "--manifest", archivePath,
      "--dir", dir,
      "--target", "production"
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /release gate report .*changed/);
      return true;
    });

    assert.throws(() => runScript("scripts/validate-production-release-gate.mjs", [
      "--dir", dir,
      "--target", "production",
      "--out", releaseGatePath
    ]), { status: 1 });
    runScript("scripts/package-production-release-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]);

    assert.throws(() => runScript("scripts/validate-production-release-archive.mjs", [
      "--manifest", archivePath,
      "--dir", dir,
      "--target", "production",
      "--require-ready"
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /production release gate report is not ready/);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production release archive rejects stale closure evidence key summaries", () => {
  const dir = path.join(tmpdir(), `sentinel-release-archive-key-summary-${process.pid}-${Date.now()}`);
  try {
    createReleaseArchiveWorkspace(dir);
    const archivePath = path.join(dir, "production-release-archive-manifest.json");
    runScript("scripts/package-production-release-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]);

    const archive = JSON.parse(readFileSync(archivePath, "utf8"));
    archive.closure.evidenceKeySummary.waivedEvidenceKeys = [];
    archive.closure.evidenceKeySummary.waivedEvidenceKeyCount = 0;
    writeFileSync(archivePath, JSON.stringify(archive, null, 2));

    assert.throws(() => runScript("scripts/validate-production-release-archive.mjs", [
      "--manifest", archivePath,
      "--dir", dir,
      "--target", "production"
    ]), /closure evidence key summary/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production release archive rejects stale command coverage summaries", () => {
  const dir = path.join(tmpdir(), `sentinel-release-archive-command-summary-${process.pid}-${Date.now()}`);
  try {
    createReleaseArchiveWorkspace(dir);
    const archivePath = path.join(dir, "production-release-archive-manifest.json");
    runScript("scripts/package-production-release-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]);

    const archive = JSON.parse(readFileSync(archivePath, "utf8"));
    archive.closure.commandCoverageSummary.signoffCommandScripts = [];
    archive.closure.commandCoverageSummary.signoffCommandScriptCount = 0;
    archive.closure.commandCoverageSummary.signoffValidatorCommandCount = 0;
    writeFileSync(archivePath, JSON.stringify(archive, null, 2));

    assert.throws(() => runScript("scripts/validate-production-release-archive.mjs", [
      "--manifest", archivePath,
      "--dir", dir,
      "--target", "production"
    ]), /command coverage summary/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production release archive rejects stale markdown coverage summaries", () => {
  const dir = path.join(tmpdir(), `sentinel-release-archive-markdown-summary-${process.pid}-${Date.now()}`);
  try {
    createReleaseArchiveWorkspace(dir);
    const archivePath = path.join(dir, "production-release-archive-manifest.json");
    runScript("scripts/package-production-release-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]);

    const archive = JSON.parse(readFileSync(archivePath, "utf8"));
    archive.closure.markdownCoverageSummary.artifactNames = [];
    archive.closure.markdownCoverageSummary.artifactCount = 0;
    writeFileSync(archivePath, JSON.stringify(archive, null, 2));

    assert.throws(() => runScript("scripts/validate-production-release-archive.mjs", [
      "--manifest", archivePath,
      "--dir", dir,
      "--target", "production"
    ]), /markdown coverage summary/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
