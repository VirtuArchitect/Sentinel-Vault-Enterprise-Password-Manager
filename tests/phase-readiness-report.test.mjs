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

const runValidator = (args) => runScript("scripts/validate-phase-readiness-report.mjs", args);

const createPlannedWorkspace = (dir) => {
  const workspace = JSON.parse(runScript("scripts/prepare-deployment-evidence-workspace.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out-dir", dir
  ]));
  const requestsPath = path.join(dir, "external-evidence-requests.json");
  const requestsMarkdownPath = path.join(dir, "external-evidence-requests.md");
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", requestsPath,
    "--markdown-out", requestsMarkdownPath
  ]);
  return { workspace, requestsPath };
};

test("phase readiness report combines deployment and external evidence blockers", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-readiness-${process.pid}-${Date.now()}`);
  try {
    const { workspace, requestsPath } = createPlannedWorkspace(dir);

    const reportPath = path.join(dir, "phase-readiness.json");
    const markdownPath = path.join(dir, "phase-readiness.md");
    const report = JSON.parse(runScript("scripts/report-phase-readiness.mjs", [
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath,
      "--out", reportPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(report.format, "sentinel-phase-readiness-report-v1");
    assert.equal(report.target, "pilot");
    assert.equal(report.failOnBlockers, false);
    assert.equal(report.externalRequests.validated, true);
    assert.equal(report.externalRequests.requestCount, 7);
    assert.equal(report.externalRequests.evidenceKeyCount, 18);
    assert.ok(report.externalRequests.commandScriptCount > 20);
    assert.equal(report.externalRequests.validatorCommandCount, 16);
    assert.equal(report.deploymentEvidence.validated, true);
    assert.equal(report.ready, false);
    assert.ok(report.blockers.some((blocker) => blocker.gate === "deployment-evidence-status"));
    assert.ok(report.blockers.some((blocker) => blocker.gate === "evidence.browserRollout"));
    assert.ok(existsSync(reportPath));
    assert.ok(existsSync(markdownPath));
    assert.match(readFileSync(markdownPath, "utf8"), /Ready: no/);
    assert.match(readFileSync(markdownPath, "utf8"), /Command scripts:/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase readiness report blocks production target unless bundle is production", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-readiness-prod-${process.pid}-${Date.now()}`);
  try {
    const { workspace, requestsPath } = createPlannedWorkspace(dir);

    const report = JSON.parse(runScript("scripts/report-phase-readiness.mjs", [
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath,
      "--target", "production"
    ]));

    assert.equal(report.target, "production");
    assert.equal(report.ready, false);
    assert.ok(report.blockers.some((blocker) => blocker.gate === "production-status"));
    assert.ok(report.warnings.some((warning) => warning.gate === "deployment-target"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase readiness report can fail CI when blockers are present", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-readiness-fail-${process.pid}-${Date.now()}`);
  try {
    const { workspace, requestsPath } = createPlannedWorkspace(dir);
    const reportPath = path.join(dir, "phase-readiness.json");

    assert.throws(() => runScript("scripts/report-phase-readiness.mjs", [
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath,
      "--out", reportPath,
      "--fail-on-blockers"
    ]), (error) => {
      assert.equal(error.status, 1);
      const report = JSON.parse(error.stdout.toString());
      assert.equal(report.failOnBlockers, true);
      assert.equal(report.ready, false);
      assert.ok(report.blockers.length > 0);
      assert.ok(existsSync(reportPath));
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase readiness validator accepts current reports", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-readiness-validate-${process.pid}-${Date.now()}`);
  try {
    const { workspace, requestsPath } = createPlannedWorkspace(dir);
    const reportPath = path.join(dir, "phase-readiness.json");
    runScript("scripts/report-phase-readiness.mjs", [
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath,
      "--out", reportPath
    ]);

    const result = JSON.parse(runValidator([
      "--report", reportPath,
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath
    ]));

    assert.equal(result.format, "sentinel-phase-readiness-report-validation-v1");
    assert.equal(result.ready, false);
    assert.ok(result.blockerCount > 0);
    assert.ok(result.commandScriptCount > 20);
    assert.equal(result.evidenceKeyCount, 18);
    assert.equal(result.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase readiness validator rejects stale reports and not-ready release mode", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-readiness-stale-${process.pid}-${Date.now()}`);
  try {
    const { workspace, requestsPath } = createPlannedWorkspace(dir);
    const reportPath = path.join(dir, "phase-readiness.json");
    runScript("scripts/report-phase-readiness.mjs", [
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath,
      "--out", reportPath
    ]);

    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    report.ready = true;
    report.blockers = [];
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator([
      "--report", reportPath,
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /phase readiness report is stale/);
      return true;
    });

    runScript("scripts/report-phase-readiness.mjs", [
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath,
      "--out", reportPath
    ]);

    assert.throws(() => runValidator([
      "--report", reportPath,
      "--bundle", workspace.bundlePath,
      "--external-requests", requestsPath,
      "--require-ready"
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /phase readiness report is not ready/);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
