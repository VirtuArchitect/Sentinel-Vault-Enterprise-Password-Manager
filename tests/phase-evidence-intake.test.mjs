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

const createIntakeWorkspace = (dir) => {
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
  runScript("scripts/prepare-phase-signoff-matrix.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-signoff-matrix.json"),
    "--markdown-out", path.join(dir, "phase-signoff-matrix.md")
  ]);
};

test("phase evidence intake maps owner requests to intake folders and validation commands", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-intake-${process.pid}-${Date.now()}`);
  try {
    createIntakeWorkspace(dir);
    const intakePath = path.join(dir, "phase-evidence-intake.json");
    const markdownPath = path.join(dir, "phase-evidence-intake.md");
    const result = JSON.parse(runScript("scripts/prepare-phase-evidence-intake.mjs", [
      "--dir", dir,
      "--out", intakePath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-phase-evidence-intake-result-v1");
    assert.equal(result.intakeCount, 7);
    assert.equal(result.expectedFileCount, 22);
    assert.equal(result.blockedIntakeCount, 7);
    assert.ok(result.commandScriptCount > 20);
    assert.equal(result.validatorCommandCount, 20);
    assert.ok(existsSync(intakePath));
    assert.ok(existsSync(markdownPath));

    const intake = JSON.parse(readFileSync(intakePath, "utf8"));
    assert.equal(intake.format, "sentinel-phase-evidence-intake-v1");
    assert.equal(intake.summary.evidenceKeyCount, 18);
    assert.ok(intake.summary.commandScriptCount > 20);
    assert.equal(intake.summary.validatorCommandCount, 20);
    assert.ok(intake.summary.commandScripts.includes("validate:windows-signing"));
    assert.ok(intake.intakeItems.some((item) => item.intakeDir === "intake/phase-6-certificate-backed-release"));
    assert.ok(intake.intakeItems.some((item) => item.evidenceKeys.includes("windowsSigning")));
    assert.ok(intake.intakeItems.some((item) => item.commandScripts.includes("validate:windows-signing")));
    assert.ok(intake.intakeItems.some((item) => item.expectedFiles.some((file) => file.evidenceKey === "windowsSigning")));
    assert.ok(intake.intakeItems.every((item) => item.redactionChecks.length >= 3));
    const markdown = readFileSync(markdownPath, "utf8");
    assert.match(markdown, /Sentinel Vault Phase Evidence Intake/);
    assert.match(markdown, /Command Coverage Summary/);
    assert.match(markdown, /- Command scripts: [2-9][0-9]/);
    assert.match(markdown, /- Validator commands: 20/);
    assert.match(markdown, /- `pnpm validate:windows-signing`/);

    const validation = JSON.parse(runScript("scripts/validate-phase-evidence-intake.mjs", [
      "--intake", intakePath,
      "--markdown", markdownPath,
      "--external-requests", path.join(dir, "external-evidence-requests.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json"),
      "--phase-signoffs", path.join(dir, "phase-signoff-matrix.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-evidence-intake-validation-v1");
    assert.equal(validation.validated, true);
    assert.ok(validation.commandScriptCount > 20);
    assert.equal(validation.validatorCommandCount, 20);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase evidence intake validator rejects stale target paths", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-intake-stale-${process.pid}-${Date.now()}`);
  try {
    createIntakeWorkspace(dir);
    const intakePath = path.join(dir, "phase-evidence-intake.json");
    runScript("scripts/prepare-phase-evidence-intake.mjs", [
      "--dir", dir,
      "--out", intakePath,
      "--markdown-out", path.join(dir, "phase-evidence-intake.md")
    ]);
    const intake = JSON.parse(readFileSync(intakePath, "utf8"));
    intake.intakeItems[0].expectedFiles[0].targetPath = "intake/changed/file.json";
    writeFileSync(intakePath, JSON.stringify(intake, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-evidence-intake.mjs", [
      "--intake", intakePath,
      "--external-requests", path.join(dir, "external-evidence-requests.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json"),
      "--phase-signoffs", path.join(dir, "phase-signoff-matrix.json")
    ]), /target mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase evidence intake validator rejects stale evidence key mappings", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-intake-key-stale-${process.pid}-${Date.now()}`);
  try {
    createIntakeWorkspace(dir);
    const intakePath = path.join(dir, "phase-evidence-intake.json");
    runScript("scripts/prepare-phase-evidence-intake.mjs", [
      "--dir", dir,
      "--out", intakePath,
      "--markdown-out", path.join(dir, "phase-evidence-intake.md")
    ]);
    const intake = JSON.parse(readFileSync(intakePath, "utf8"));
    intake.intakeItems[0].evidenceKeys = ["changedEvidenceKey"];
    writeFileSync(intakePath, JSON.stringify(intake, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-evidence-intake.mjs", [
      "--intake", intakePath,
      "--external-requests", path.join(dir, "external-evidence-requests.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json"),
      "--phase-signoffs", path.join(dir, "phase-signoff-matrix.json")
    ]), /evidence key mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase evidence intake validator rejects stale markdown command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-intake-markdown-${process.pid}-${Date.now()}`);
  try {
    createIntakeWorkspace(dir);
    const intakePath = path.join(dir, "phase-evidence-intake.json");
    const markdownPath = path.join(dir, "phase-evidence-intake.md");
    runScript("scripts/prepare-phase-evidence-intake.mjs", [
      "--dir", dir,
      "--out", intakePath,
      "--markdown-out", markdownPath
    ]);
    const markdown = readFileSync(markdownPath, "utf8").replace(
      "- `pnpm validate:windows-signing`",
      "- `pnpm changed:command`"
    );
    writeFileSync(markdownPath, markdown);

    assert.throws(() => runScript("scripts/validate-phase-evidence-intake.mjs", [
      "--intake", intakePath,
      "--markdown", markdownPath,
      "--external-requests", path.join(dir, "external-evidence-requests.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json"),
      "--phase-signoffs", path.join(dir, "phase-signoff-matrix.json")
    ]), /markdown missing command script coverage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase evidence intake validator rejects stale command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-intake-command-stale-${process.pid}-${Date.now()}`);
  try {
    createIntakeWorkspace(dir);
    const intakePath = path.join(dir, "phase-evidence-intake.json");
    runScript("scripts/prepare-phase-evidence-intake.mjs", [
      "--dir", dir,
      "--out", intakePath,
      "--markdown-out", path.join(dir, "phase-evidence-intake.md")
    ]);
    const intake = JSON.parse(readFileSync(intakePath, "utf8"));
    intake.summary.commandScripts = [];
    intake.summary.commandScriptCount = 0;
    intake.summary.validatorCommandCount = 0;
    intake.intakeItems[0].commandScripts = ["changed:command"];
    writeFileSync(intakePath, JSON.stringify(intake, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-evidence-intake.mjs", [
      "--intake", intakePath,
      "--external-requests", path.join(dir, "external-evidence-requests.json"),
      "--phase-gaps", path.join(dir, "phase-gap-matrix.json"),
      "--phase-signoffs", path.join(dir, "phase-signoff-matrix.json")
    ]), /command script|validator command/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
