import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runReport = (args) => execFileSync(process.execPath, [
  "scripts/report-deployment-redaction.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-deployment-redaction-report.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("deployment redaction report scans planned evidence bundle", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-redaction-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(dir, { recursive: true });
    const outputPath = path.join(dir, "deployment-redaction-report.json");
    const markdownPath = path.join(dir, "deployment-redaction-report.md");
    const report = JSON.parse(runReport([
      "--bundle", "docs/templates/deployment-evidence-bundle.json",
      "--out", outputPath,
      "--markdown-out", markdownPath,
      "--fail-on-findings"
    ]));

    assert.equal(report.format, "sentinel-deployment-redaction-report-v1");
    assert.equal(report.summary.total, 28);
    assert.equal(report.summary.missing, 0);
    assert.equal(report.summary.findingCount, 0);
    assert.equal(report.readyForRelease, true);
    assert.ok(existsSync(outputPath));
    assert.ok(existsSync(markdownPath));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment redaction validator accepts current reports", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-redaction-validate-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(dir, { recursive: true });
    const outputPath = path.join(dir, "deployment-redaction-report.json");
    runReport([
      "--bundle", "docs/templates/deployment-evidence-bundle.json",
      "--out", outputPath,
      "--fail-on-findings"
    ]);

    const result = JSON.parse(runValidator([
      "--report", outputPath,
      "--bundle", "docs/templates/deployment-evidence-bundle.json",
      "--require-ready"
    ]));

    assert.equal(result.format, "sentinel-deployment-redaction-report-validation-v1");
    assert.equal(result.readyForRelease, true);
    assert.equal(result.findingCount, 0);
    assert.equal(result.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment redaction report fails strict mode on leaked token evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-redaction-fail-${process.pid}-${Date.now()}`);
  try {
    const evidenceDir = path.join(dir, "evidence");
    mkdirSync(evidenceDir, { recursive: true });
    const leakedEvidencePath = path.join(evidenceDir, "leaked.json");
    const bundlePath = path.join(dir, "deployment-evidence-bundle.json");
    writeFileSync(leakedEvidencePath, JSON.stringify({
      format: "leaked-evidence",
      token: `svt_${"abcdefghijklmnopqrstuvwxyz"}`
    }, null, 2));
    writeFileSync(bundlePath, JSON.stringify({
      format: "sentinel-deployment-evidence-bundle-v1",
      environment: "pilot",
      status: "pilot",
      owner: "platform-security",
      generatedAt: "2026-07-01T10:00:00Z",
      evidence: {
        leaked: "evidence/leaked.json"
      },
      approvals: {
        securityOwner: "security",
        operationsOwner: "operations",
        releaseOwner: "release"
      }
    }, null, 2));

    assert.throws(() => runReport([
      "--bundle", bundlePath,
      "--fail-on-findings"
    ]), (error) => {
      assert.equal(error.status, 1);
      const report = JSON.parse(error.stdout.toString());
      assert.equal(report.readyForRelease, false);
      assert.equal(report.summary.findingCount, 1);
      assert.ok(report.items[0].findings.some((finding) => finding.rule === "sentinel-service-token"));
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment redaction validator rejects stale reports and not-ready release mode", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-redaction-stale-${process.pid}-${Date.now()}`);
  try {
    const evidenceDir = path.join(dir, "evidence");
    mkdirSync(evidenceDir, { recursive: true });
    const evidencePath = path.join(evidenceDir, "safe.json");
    const bundlePath = path.join(dir, "deployment-evidence-bundle.json");
    const reportPath = path.join(dir, "deployment-redaction-report.json");
    writeFileSync(evidencePath, JSON.stringify({
      format: "safe-evidence",
      status: "planned"
    }, null, 2));
    writeFileSync(bundlePath, JSON.stringify({
      format: "sentinel-deployment-evidence-bundle-v1",
      environment: "pilot",
      status: "pilot",
      owner: "platform-security",
      generatedAt: "2026-07-01T10:00:00Z",
      evidence: {
        safe: "evidence/safe.json"
      },
      approvals: {
        securityOwner: "security",
        operationsOwner: "operations",
        releaseOwner: "release"
      }
    }, null, 2));

    runReport([
      "--bundle", bundlePath,
      "--out", reportPath
    ]);

    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    report.summary.findingCount = 1;
    report.readyForRelease = false;
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator([
      "--report", reportPath,
      "--bundle", bundlePath
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /deployment redaction report is stale/);
      return true;
    });

    rmSync(evidencePath);
    runReport([
      "--bundle", bundlePath,
      "--out", reportPath
    ]);

    assert.throws(() => runValidator([
      "--report", reportPath,
      "--bundle", bundlePath,
      "--require-ready"
    ]), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /not ready for release/);
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
