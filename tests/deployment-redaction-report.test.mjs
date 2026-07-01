import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
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
