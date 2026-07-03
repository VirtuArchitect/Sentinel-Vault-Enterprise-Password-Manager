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

const createDecisionWorkspace = (dir) => {
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
};

test("phase decision record holds closure while blockers remain", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-decision-${process.pid}-${Date.now()}`);
  try {
    createDecisionWorkspace(dir);
    const recordPath = path.join(dir, "phase-decision-record.json");
    const markdownPath = path.join(dir, "phase-decision-record.md");
    const result = JSON.parse(runScript("scripts/prepare-phase-decision-record.mjs", [
      "--dir", dir,
      "--out", recordPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-phase-decision-record-result-v1");
    assert.equal(result.decision, "hold-phase-closure");
    assert.equal(result.ready, false);
    assert.equal(result.pendingActionCount, 7);
    assert.ok(existsSync(recordPath));
    assert.ok(existsSync(markdownPath));

    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.equal(record.format, "sentinel-phase-decision-record-v1");
    assert.equal(record.decision, "hold-phase-closure");
    assert.equal(record.pendingActions.length, 7);
    assert.equal(record.evidenceKeySummary.actionEvidenceKeyCount, 18);
    assert.equal(record.evidenceKeySummary.gapEvidenceKeyCount, 18);
    assert.ok(record.commandCoverageSummary.actionCommandScriptCount > 20);
    assert.equal(record.commandCoverageSummary.gapCommandScriptCount, record.commandCoverageSummary.actionCommandScriptCount);
    assert.equal(record.commandCoverageSummary.validatorCommandCount, 15);
    assert.ok(record.commandCoverageSummary.actionCommandScripts.includes("validate:windows-signing"));
    assert.ok(record.evidenceKeySummary.actionEvidenceKeys.includes("windowsSigning"));
    assert.ok(record.pendingActions.some((action) => action.evidenceKeys.includes("windowsSigning")));
    assert.ok(record.requiredApprovals.some((approval) => approval.ownerRole === "Release owner"));
    const markdown = readFileSync(markdownPath, "utf8");
    assert.match(markdown, /Sentinel Vault Phase Decision Record/);
    assert.match(markdown, /Command Coverage Summary/);
    assert.match(markdown, /- Action command scripts: [2-9][0-9]/);
    assert.match(markdown, /- Gap command scripts: [2-9][0-9]/);
    assert.match(markdown, /- Validator commands: 15/);
    assert.match(markdown, /- `pnpm validate:windows-signing`/);

    const validation = JSON.parse(runScript("scripts/validate-phase-decision-record.mjs", [
      "--record", recordPath,
      "--markdown", markdownPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-decision-record-validation-v1");
    assert.equal(validation.validated, true);
    assert.equal(validation.evidenceKeyCount, 18);
    assert.ok(validation.commandScriptCount > 20);
    assert.equal(validation.gapCommandScriptCount, validation.commandScriptCount);
    assert.equal(validation.validatorCommandCount, 15);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase decision record validator rejects stale markdown command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-decision-markdown-${process.pid}-${Date.now()}`);
  try {
    createDecisionWorkspace(dir);
    const recordPath = path.join(dir, "phase-decision-record.json");
    const markdownPath = path.join(dir, "phase-decision-record.md");
    runScript("scripts/prepare-phase-decision-record.mjs", [
      "--dir", dir,
      "--out", recordPath,
      "--markdown-out", markdownPath
    ]);
    const markdown = readFileSync(markdownPath, "utf8").replaceAll(
      "- `pnpm validate:windows-signing`",
      "- `pnpm changed:command`"
    );
    writeFileSync(markdownPath, markdown);

    assert.throws(() => runScript("scripts/validate-phase-decision-record.mjs", [
      "--record", recordPath,
      "--markdown", markdownPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json")
    ]), /markdown missing action command script coverage|markdown missing gap command script coverage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase decision record validator rejects stale command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-decision-commands-${process.pid}-${Date.now()}`);
  try {
    createDecisionWorkspace(dir);
    const recordPath = path.join(dir, "phase-decision-record.json");
    runScript("scripts/prepare-phase-decision-record.mjs", [
      "--dir", dir,
      "--out", recordPath,
      "--markdown-out", path.join(dir, "phase-decision-record.md")
    ]);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    record.commandCoverageSummary.actionCommandScripts = [];
    record.commandCoverageSummary.actionCommandScriptCount = 0;
    writeFileSync(recordPath, JSON.stringify(record, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-decision-record.mjs", [
      "--record", recordPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json")
    ]), /command coverage summary/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase decision record validator rejects stale decisions", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-decision-stale-${process.pid}-${Date.now()}`);
  try {
    createDecisionWorkspace(dir);
    const recordPath = path.join(dir, "phase-decision-record.json");
    runScript("scripts/prepare-phase-decision-record.mjs", [
      "--dir", dir,
      "--out", recordPath,
      "--markdown-out", path.join(dir, "phase-decision-record.md")
    ]);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    record.decision = "approve-phase-closure";
    writeFileSync(recordPath, JSON.stringify(record, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-decision-record.mjs", [
      "--record", recordPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json")
    ]), /decision does not match/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase decision record validator rejects stale evidence keys", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-decision-evidence-${process.pid}-${Date.now()}`);
  try {
    createDecisionWorkspace(dir);
    const recordPath = path.join(dir, "phase-decision-record.json");
    runScript("scripts/prepare-phase-decision-record.mjs", [
      "--dir", dir,
      "--out", recordPath,
      "--markdown-out", path.join(dir, "phase-decision-record.md")
    ]);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    record.pendingActions[0].evidenceKeys = ["changedEvidenceKey"];
    record.evidenceKeySummary.actionEvidenceKeys = [];
    record.evidenceKeySummary.actionEvidenceKeyCount = 0;
    writeFileSync(recordPath, JSON.stringify(record, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-decision-record.mjs", [
      "--record", recordPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--phase-actions", path.join(dir, "phase-action-register.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json")
    ]), /evidence key/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
