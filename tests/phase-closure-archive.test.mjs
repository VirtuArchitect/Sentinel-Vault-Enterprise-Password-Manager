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

const createClosureWorkspace = (dir) => {
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
  runScript("scripts/validate-phase-action-register.mjs", [
    "--register", path.join(dir, "phase-action-register.json"),
    "--phase-gate", path.join(dir, "phase-gate-validation.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json")
  ]);
  runScript("scripts/prepare-phase-gap-matrix.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-gap-matrix.json"),
    "--markdown-out", path.join(dir, "phase-gap-matrix.md")
  ]);
  runScript("scripts/validate-phase-gap-matrix.mjs", [
    "--matrix", path.join(dir, "phase-gap-matrix.json"),
    "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json")
  ]);
  runScript("scripts/prepare-phase-decision-record.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-decision-record.json"),
    "--markdown-out", path.join(dir, "phase-decision-record.md")
  ]);
  runScript("scripts/validate-phase-decision-record.mjs", [
    "--record", path.join(dir, "phase-decision-record.json"),
    "--phase-gate", path.join(dir, "phase-gate-validation.json"),
    "--phase-actions", path.join(dir, "phase-action-register.json"),
    "--phase-gaps", path.join(dir, "phase-gap-matrix.json")
  ]);
  runScript("scripts/prepare-phase-signoff-matrix.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-signoff-matrix.json"),
    "--markdown-out", path.join(dir, "phase-signoff-matrix.md")
  ]);
  runScript("scripts/validate-phase-signoff-matrix.mjs", [
    "--matrix", path.join(dir, "phase-signoff-matrix.json"),
    "--phase-decision", path.join(dir, "phase-decision-record.json"),
    "--phase-actions", path.join(dir, "phase-action-register.json")
  ]);
  runScript("scripts/prepare-phase-evidence-intake.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-evidence-intake.json"),
    "--markdown-out", path.join(dir, "phase-evidence-intake.md")
  ]);
  runScript("scripts/validate-phase-evidence-intake.mjs", [
    "--intake", path.join(dir, "phase-evidence-intake.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--phase-gaps", path.join(dir, "phase-gap-matrix.json"),
    "--phase-signoffs", path.join(dir, "phase-signoff-matrix.json")
  ]);
  runScript("scripts/prepare-phase-attachment-inventory.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-attachment-inventory.json"),
    "--markdown-out", path.join(dir, "phase-attachment-inventory.md")
  ]);
  runScript("scripts/validate-phase-attachment-inventory.mjs", [
    "--inventory", path.join(dir, "phase-attachment-inventory.json"),
    "--intake", path.join(dir, "phase-evidence-intake.json")
  ]);
  runScript("scripts/package-phase-review-bundle.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-review-bundle-manifest.json")
  ]);
  runScript("scripts/validate-phase-review-bundle.mjs", [
    "--manifest", path.join(dir, "phase-review-bundle-manifest.json")
  ]);
};

test("phase closure archive binds review bundle to Git provenance", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-closure-${process.pid}-${Date.now()}`);
  try {
    createClosureWorkspace(dir);
    const archivePath = path.join(dir, "phase-closure-archive-manifest.json");
    const result = JSON.parse(runScript("scripts/package-phase-closure-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]));

    assert.equal(result.format, "sentinel-phase-closure-archive-result-v1");
    assert.match(result.sourceCommit, /^[a-f0-9]{40}$/);
    assert.equal(result.decision, "hold-phase-closure");
    assert.equal(result.artifactCount, 15);
    assert.ok(existsSync(archivePath));

    const archive = JSON.parse(readFileSync(archivePath, "utf8"));
    assert.equal(archive.format, "sentinel-phase-closure-archive-manifest-v1");
    assert.equal(archive.review.artifactNames.length, 15);
    assert.match(archive.review.manifest.sha256, /^[a-f0-9]{64}$/);

    const validation = JSON.parse(runScript("scripts/validate-phase-closure-archive.mjs", [
      "--manifest", archivePath,
      "--phase-review", path.join(dir, "phase-review-bundle-manifest.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-closure-archive-validation-v1");
    assert.equal(validation.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase closure archive validator rejects changed review manifests", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-closure-tamper-${process.pid}-${Date.now()}`);
  try {
    createClosureWorkspace(dir);
    const archivePath = path.join(dir, "phase-closure-archive-manifest.json");
    const reviewPath = path.join(dir, "phase-review-bundle-manifest.json");
    runScript("scripts/package-phase-closure-archive.mjs", [
      "--dir", dir,
      "--out", archivePath
    ]);
    const review = JSON.parse(readFileSync(reviewPath, "utf8"));
    review.decision = "changed";
    writeFileSync(reviewPath, JSON.stringify(review, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-closure-archive.mjs", [
      "--manifest", archivePath,
      "--phase-review", reviewPath
    ]), /review manifest .*changed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
