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

const createSignoffWorkspace = (dir) => {
  runScript("scripts/prepare-deployment-evidence-workspace.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out-dir", dir
  ]);
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", path.join(dir, "external-evidence-requests.json"),
    "--markdown-out", path.join(dir, "external-evidence-requests.md")
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
};

test("phase signoff matrix groups pending actions by owner role", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-signoffs-${process.pid}-${Date.now()}`);
  try {
    createSignoffWorkspace(dir);
    const matrixPath = path.join(dir, "phase-signoff-matrix.json");
    const markdownPath = path.join(dir, "phase-signoff-matrix.md");
    const result = JSON.parse(runScript("scripts/prepare-phase-signoff-matrix.mjs", [
      "--dir", dir,
      "--out", matrixPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-phase-signoff-matrix-result-v1");
    assert.equal(result.approvalCount, 7);
    assert.equal(result.blockedApprovalCount, 7);
    assert.equal(result.pendingActionCount, 7);
    assert.ok(result.commandScriptCount > 20);
    assert.equal(result.validatorCommandCount, 13);
    assert.ok(existsSync(matrixPath));
    assert.ok(existsSync(markdownPath));

    const matrix = JSON.parse(readFileSync(matrixPath, "utf8"));
    assert.equal(matrix.format, "sentinel-phase-signoff-matrix-v1");
    assert.equal(matrix.decision, "hold-phase-closure");
    assert.equal(matrix.summary.evidenceKeyCount, 18);
    assert.ok(matrix.summary.commandScriptCount > 20);
    assert.equal(matrix.summary.validatorCommandCount, 13);
    assert.ok(matrix.summary.commandScripts.includes("validate:windows-signing"));
    assert.ok(matrix.summary.evidenceKeys.includes("windowsSigning"));
    assert.ok(matrix.approvals.some((approval) => approval.evidenceKeys.includes("windowsSigning")));
    assert.ok(matrix.approvals.some((approval) => approval.commandScripts.includes("validate:windows-signing")));
    assert.ok(matrix.approvals.some((approval) => approval.ownerRole === "Security architecture owner"));
    assert.match(readFileSync(markdownPath, "utf8"), /Sentinel Vault Phase Signoff Matrix/);
    assert.match(readFileSync(markdownPath, "utf8"), /Command scripts:/);

    const validation = JSON.parse(runScript("scripts/validate-phase-signoff-matrix.mjs", [
      "--matrix", matrixPath,
      "--phase-decision", path.join(dir, "phase-decision-record.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-signoff-matrix-validation-v1");
    assert.equal(validation.validated, true);
    assert.equal(validation.evidenceKeyCount, 18);
    assert.ok(validation.commandScriptCount > 20);
    assert.equal(validation.validatorCommandCount, 13);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase signoff matrix validator rejects stale owner status", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-signoffs-stale-${process.pid}-${Date.now()}`);
  try {
    createSignoffWorkspace(dir);
    const matrixPath = path.join(dir, "phase-signoff-matrix.json");
    runScript("scripts/prepare-phase-signoff-matrix.mjs", [
      "--dir", dir,
      "--out", matrixPath,
      "--markdown-out", path.join(dir, "phase-signoff-matrix.md")
    ]);
    const matrix = JSON.parse(readFileSync(matrixPath, "utf8"));
    matrix.approvals[0].status = "ready-for-signoff";
    writeFileSync(matrixPath, JSON.stringify(matrix, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-signoff-matrix.mjs", [
      "--matrix", matrixPath,
      "--phase-decision", path.join(dir, "phase-decision-record.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json")
    ]), /summary blocked approval count mismatch|status mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase signoff matrix validator rejects stale evidence keys", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-signoffs-evidence-${process.pid}-${Date.now()}`);
  try {
    createSignoffWorkspace(dir);
    const matrixPath = path.join(dir, "phase-signoff-matrix.json");
    runScript("scripts/prepare-phase-signoff-matrix.mjs", [
      "--dir", dir,
      "--out", matrixPath,
      "--markdown-out", path.join(dir, "phase-signoff-matrix.md")
    ]);
    const matrix = JSON.parse(readFileSync(matrixPath, "utf8"));
    matrix.summary.evidenceKeys = [];
    matrix.summary.evidenceKeyCount = 0;
    matrix.approvals[0].evidenceKeys = ["changedEvidenceKey"];
    matrix.approvals[0].actions[0].evidenceKeys = ["changedEvidenceKey"];
    writeFileSync(matrixPath, JSON.stringify(matrix, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-signoff-matrix.mjs", [
      "--matrix", matrixPath,
      "--phase-decision", path.join(dir, "phase-decision-record.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json")
    ]), /evidence key/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase signoff matrix validator rejects stale command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-signoffs-commands-${process.pid}-${Date.now()}`);
  try {
    createSignoffWorkspace(dir);
    const matrixPath = path.join(dir, "phase-signoff-matrix.json");
    runScript("scripts/prepare-phase-signoff-matrix.mjs", [
      "--dir", dir,
      "--out", matrixPath,
      "--markdown-out", path.join(dir, "phase-signoff-matrix.md")
    ]);
    const matrix = JSON.parse(readFileSync(matrixPath, "utf8"));
    matrix.summary.commandScripts = [];
    matrix.summary.commandScriptCount = 0;
    matrix.summary.validatorCommandCount = 0;
    matrix.approvals[0].commandScripts = ["changed:command"];
    matrix.approvals[0].commandScriptCount = 1;
    matrix.approvals[0].actions[0].commandScripts = ["changed:command"];
    writeFileSync(matrixPath, JSON.stringify(matrix, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-signoff-matrix.mjs", [
      "--matrix", matrixPath,
      "--phase-decision", path.join(dir, "phase-decision-record.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json")
    ]), /command script|validator command/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
