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

const createActionWorkspace = (dir) => {
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
};

test("phase action register creates owner action records from the phase gate", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-actions-${process.pid}-${Date.now()}`);
  try {
    createActionWorkspace(dir);
    const registerPath = path.join(dir, "phase-action-register.json");
    const markdownPath = path.join(dir, "phase-action-register.md");
    const result = JSON.parse(runScript("scripts/prepare-phase-action-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-phase-action-register-result-v1");
    assert.equal(result.actionCount, 7);
    assert.equal(result.ready, false);
    assert.equal(result.validatorCommandCount, 20);
    assert.ok(existsSync(registerPath));
    assert.ok(existsSync(markdownPath));

    const register = JSON.parse(readFileSync(registerPath, "utf8"));
    assert.equal(register.format, "sentinel-phase-action-register-v1");
    assert.equal(register.actions.length, 7);
    assert.equal(register.summary.evidenceKeyCount, 18);
    assert.ok(register.summary.commandScriptCount > 20);
    assert.equal(register.summary.validatorCommandCount, 20);
    assert.ok(register.summary.commandScripts.includes("validate:windows-signing"));
    assert.equal(register.gate.externalRequestSummary.evidenceKeyCount, 18);
    assert.equal(register.actions[0].id, "ACT-01");
    assert.ok(register.actions.some((action) => action.evidenceKeys.includes("windowsSigning")));
    assert.ok(register.actions.some((action) => action.blockerType === "certificate-backed-release"));
    const markdown = readFileSync(markdownPath, "utf8");
    assert.match(markdown, /Sentinel Vault Phase Action Register/);
    assert.match(markdown, /Command Coverage Summary/);
    assert.match(markdown, /- Command scripts: [2-9][0-9]/);
    assert.match(markdown, /- Validator commands: 20/);
    assert.match(markdown, /- `pnpm validate:windows-signing`/);

    const validation = JSON.parse(runScript("scripts/validate-phase-action-register.mjs", [
      "--register", registerPath,
      "--markdown", markdownPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--external-requests", path.join(dir, "external-evidence-requests.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-action-register-validation-v1");
    assert.equal(validation.evidenceKeyCount, 18);
    assert.ok(validation.commandScriptCount > 20);
    assert.equal(validation.validatorCommandCount, 20);
    assert.equal(validation.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase action register validator rejects stale markdown command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-actions-markdown-${process.pid}-${Date.now()}`);
  try {
    createActionWorkspace(dir);
    const registerPath = path.join(dir, "phase-action-register.json");
    const markdownPath = path.join(dir, "phase-action-register.md");
    runScript("scripts/prepare-phase-action-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", markdownPath
    ]);
    const markdown = readFileSync(markdownPath, "utf8").replace(
      "- `pnpm validate:windows-signing`",
      "- `pnpm changed:command`"
    );
    writeFileSync(markdownPath, markdown);

    assert.throws(() => runScript("scripts/validate-phase-action-register.mjs", [
      "--register", registerPath,
      "--markdown", markdownPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--external-requests", path.join(dir, "external-evidence-requests.json")
    ]), /markdown missing command script coverage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase action register validator rejects stale command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-actions-commands-${process.pid}-${Date.now()}`);
  try {
    createActionWorkspace(dir);
    const registerPath = path.join(dir, "phase-action-register.json");
    runScript("scripts/prepare-phase-action-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", path.join(dir, "phase-action-register.md")
    ]);
    const register = JSON.parse(readFileSync(registerPath, "utf8"));
    register.summary.commandScripts = [];
    register.summary.commandScriptCount = 0;
    register.gate.externalRequestSummary.commandScripts = [];
    register.gate.externalRequestSummary.commandScriptCount = 0;
    writeFileSync(registerPath, JSON.stringify(register, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-action-register.mjs", [
      "--register", registerPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--external-requests", path.join(dir, "external-evidence-requests.json")
    ]), /external request summary|command script/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase action register validator rejects stale actions", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-actions-stale-${process.pid}-${Date.now()}`);
  try {
    createActionWorkspace(dir);
    const registerPath = path.join(dir, "phase-action-register.json");
    runScript("scripts/prepare-phase-action-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", path.join(dir, "phase-action-register.md")
    ]);
    const register = JSON.parse(readFileSync(registerPath, "utf8"));
    register.actions[0].title = "changed action title";
    writeFileSync(registerPath, JSON.stringify(register, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-action-register.mjs", [
      "--register", registerPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--external-requests", path.join(dir, "external-evidence-requests.json")
    ]), /action 1 title mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase action register validator rejects stale evidence keys", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-actions-keys-${process.pid}-${Date.now()}`);
  try {
    createActionWorkspace(dir);
    const registerPath = path.join(dir, "phase-action-register.json");
    runScript("scripts/prepare-phase-action-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", path.join(dir, "phase-action-register.md")
    ]);
    const register = JSON.parse(readFileSync(registerPath, "utf8"));
    register.actions[0].evidenceKeys = ["changedEvidenceKey"];
    writeFileSync(registerPath, JSON.stringify(register, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-action-register.mjs", [
      "--register", registerPath,
      "--phase-gate", path.join(dir, "phase-gate-validation.json"),
      "--external-requests", path.join(dir, "external-evidence-requests.json")
    ]), /evidence key mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
