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

const createPhaseGateWorkspace = (dir) => {
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
};

test("phase gate validator accepts generated blocked-but-covered evidence packs", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-gate-${process.pid}-${Date.now()}`);
  try {
    createPhaseGateWorkspace(dir);
    const outputPath = path.join(dir, "phase-gate-validation.json");
    const markdownPath = path.join(dir, "phase-gate-validation.md");
    const report = JSON.parse(runScript("scripts/validate-phase-gate.mjs", [
      "--dir", dir,
      "--out", outputPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(report.format, "sentinel-phase-gate-validation-v1");
    assert.equal(report.validated, true);
    assert.equal(report.ready, false);
    assert.equal(report.failedChecks.length, 0);
    assert.ok(report.blockerCount > 0);
    assert.ok(report.remainingItemCount > 0);
    assert.ok(existsSync(outputPath));
    assert.ok(existsSync(markdownPath));
    assert.equal(JSON.parse(readFileSync(outputPath, "utf8")).format, "sentinel-phase-gate-validation-v1");
    assert.match(readFileSync(markdownPath, "utf8"), /Sentinel Vault Phase Gate Validation/);
    assert.match(readFileSync(markdownPath, "utf8"), /workspace: passed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase gate validator can fail release gates when blockers remain", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-gate-strict-${process.pid}-${Date.now()}`);
  try {
    createPhaseGateWorkspace(dir);
    assert.throws(() => runScript("scripts/validate-phase-gate.mjs", [
      "--dir", dir,
      "--fail-on-blockers"
    ]), (error) => {
      assert.equal(error.status, 1);
      const report = JSON.parse(error.stdout.toString());
      assert.equal(report.validated, true);
      assert.equal(report.ready, false);
      assert.ok(report.blockerCount > 0);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase gate report validator accepts current reports", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-gate-report-${process.pid}-${Date.now()}`);
  try {
    createPhaseGateWorkspace(dir);
    const reportPath = path.join(dir, "phase-gate-validation.json");
    runScript("scripts/validate-phase-gate.mjs", [
      "--dir", dir,
      "--out", reportPath
    ]);

    const result = JSON.parse(runScript("scripts/validate-phase-gate-report.mjs", [
      "--dir", dir,
      "--report", reportPath
    ]));

    assert.equal(result.format, "sentinel-phase-gate-report-validation-v1");
    assert.equal(result.ready, false);
    assert.ok(result.blockerCount > 0);
    assert.equal(result.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase gate report validator rejects stale reports and not-ready release mode", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-gate-report-stale-${process.pid}-${Date.now()}`);
  try {
    createPhaseGateWorkspace(dir);
    const reportPath = path.join(dir, "phase-gate-validation.json");
    runScript("scripts/validate-phase-gate.mjs", [
      "--dir", dir,
      "--out", reportPath
    ]);

    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    report.ready = true;
    report.blockerCount = 0;
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-gate-report.mjs", [
      "--dir", dir,
      "--report", reportPath
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /phase gate validation report is stale/);
      return true;
    });

    runScript("scripts/validate-phase-gate.mjs", [
      "--dir", dir,
      "--out", reportPath
    ]);

    assert.throws(() => runScript("scripts/validate-phase-gate-report.mjs", [
      "--dir", dir,
      "--report", reportPath,
      "--require-ready"
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /phase gate validation report is not ready/);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase gate validator rejects missing evidence pack artifacts", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-gate-missing-${process.pid}-${Date.now()}`);
  try {
    createPhaseGateWorkspace(dir);
    rmSync(path.join(dir, "phase-handoff-checklist.md"));

    assert.throws(() => runScript("scripts/validate-phase-gate.mjs", [
      "--dir", dir
    ]), /missing phase gate artifact handoff/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
