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

const createChecklistWorkspace = (dir) => {
  const workspace = JSON.parse(runScript("scripts/prepare-deployment-evidence-workspace.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out-dir", dir
  ]));
  const requestsPath = path.join(dir, "external-evidence-requests.json");
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", requestsPath,
    "--markdown-out", path.join(dir, "external-evidence-requests.md")
  ]);

  const readinessPath = path.join(dir, "phase-readiness.json");
  runScript("scripts/report-phase-readiness.mjs", [
    "--bundle", workspace.bundlePath,
    "--external-requests", requestsPath,
    "--out", readinessPath
  ]);

  const checklistPath = path.join(dir, "phase-handoff-checklist.md");
  const result = JSON.parse(runScript("scripts/prepare-phase-handoff-checklist.mjs", [
    "--readiness", readinessPath,
    "--external-requests", requestsPath,
    "--out", checklistPath
  ]));

  return { checklistPath, readinessPath, requestsPath, result };
};

test("phase handoff checklist turns readiness and external requests into owner actions", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-handoff-${process.pid}-${Date.now()}`);
  try {
    const { checklistPath, result } = createChecklistWorkspace(dir);

    assert.equal(result.format, "sentinel-phase-handoff-checklist-result-v1");
    assert.equal(result.requestCount, 7);
    assert.ok(result.commandScriptCount > 20);
    assert.equal(result.validatorCommandCount, 22);
    assert.equal(result.ready, false);
    assert.ok(result.blockerCount > 0);
    assert.ok(existsSync(checklistPath));

    const checklist = readFileSync(checklistPath, "utf8");
    assert.match(checklist, /Sentinel Vault Phase Handoff Checklist/);
    assert.match(checklist, /Current Blocker Summary/);
    assert.match(checklist, /evidence-items:/);
    assert.match(checklist, /Phase 2: Postgres HA dependency and environment approval/);
    assert.match(checklist, /Phase 6: MSI\/MSIX signing evidence from approved release host/);
    assert.match(checklist, /- \[ \] Approved code-signing certificate or PFX access on the release host/);
    assert.match(checklist, /Command Coverage Summary/);
    assert.match(checklist, /- Command scripts: [2-9][0-9]/);
    assert.match(checklist, /- Validator commands: 22/);
    assert.match(checklist, /- `pnpm validate:windows-signing`/);
    assert.match(checklist, /pnpm report:phase-readiness/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase handoff checklist validator accepts generated checklists", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-handoff-valid-${process.pid}-${Date.now()}`);
  try {
    const { checklistPath, readinessPath, requestsPath } = createChecklistWorkspace(dir);
    const validation = JSON.parse(runScript("scripts/validate-phase-handoff-checklist.mjs", [
      "--checklist", checklistPath,
      "--readiness", readinessPath,
      "--external-requests", requestsPath
    ]));

    assert.equal(validation.format, "sentinel-phase-handoff-checklist-validation-v1");
    assert.equal(validation.validated, true);
    assert.equal(validation.requestCount, 7);
    assert.ok(validation.commandScriptCount > 20);
    assert.equal(validation.validatorCommandCount, 22);
    assert.ok(validation.blockerSummaryCount > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase handoff checklist validator rejects stale command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-handoff-command-invalid-${process.pid}-${Date.now()}`);
  try {
    const { checklistPath, readinessPath, requestsPath } = createChecklistWorkspace(dir);
    const checklist = readFileSync(checklistPath, "utf8").replace(
      "- `pnpm validate:windows-signing`",
      "- `pnpm changed:command`"
    );
    writeFileSync(checklistPath, checklist);

    assert.throws(() => runScript("scripts/validate-phase-handoff-checklist.mjs", [
      "--checklist", checklistPath,
      "--readiness", readinessPath,
      "--external-requests", requestsPath
    ]), /missing command script coverage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase handoff checklist validator rejects stale or edited checklists", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-handoff-invalid-${process.pid}-${Date.now()}`);
  try {
    const { checklistPath, readinessPath, requestsPath } = createChecklistWorkspace(dir);
    const checklist = readFileSync(checklistPath, "utf8").replace(
      "- [ ] All distributable Windows artifacts are signed and signature verification passes",
      "- [ ] Windows artifact signing evidence still pending"
    );
    writeFileSync(checklistPath, checklist);

    assert.throws(() => runScript("scripts/validate-phase-handoff-checklist.mjs", [
      "--checklist", checklistPath,
      "--readiness", readinessPath,
      "--external-requests", requestsPath
    ]), /missing acceptance criterion/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
