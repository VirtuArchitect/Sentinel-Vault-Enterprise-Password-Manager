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

const createExternalRequests = (dir) => {
  const requestsPath = path.join(dir, "external-evidence-requests.json");
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", requestsPath,
    "--markdown-out", path.join(dir, "external-evidence-requests.md")
  ]);
  return requestsPath;
};

test("phase completion audit maps roadmap remaining work to external handoff requests", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-completion-${process.pid}-${Date.now()}`);
  try {
    const requestsPath = createExternalRequests(dir);
    const reportPath = path.join(dir, "phase-completion-audit.json");
    const markdownPath = path.join(dir, "phase-completion-audit.md");
    const report = JSON.parse(runScript("scripts/report-phase-completion-audit.mjs", [
      "--external-requests", requestsPath,
      "--out", reportPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(report.format, "sentinel-phase-completion-audit-v1");
    assert.equal(report.complete, false);
    assert.equal(report.externallyCovered, true);
    assert.ok(report.remainingPhaseCount >= 6);
    assert.equal(report.uncoveredRemaining.length, 0);
    assert.ok(report.phases.some((phase) => phase.number === 2 && phase.externalRequests.some((request) => request.blockerType === "postgres-ha-approval")));
    assert.ok(report.phases.some((phase) => phase.number === 8 && phase.remaining.length >= 2));
    assert.ok(existsSync(reportPath));
    assert.ok(existsSync(markdownPath));
    assert.match(readFileSync(markdownPath, "utf8"), /Phase 2: Production Storage/);
    assert.match(readFileSync(markdownPath, "utf8"), /Postgres HA dependency and environment approval/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase completion audit reports uncovered roadmap gaps", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-completion-uncovered-${process.pid}-${Date.now()}`);
  try {
    const requestsPath = createExternalRequests(dir);
    const requests = JSON.parse(readFileSync(requestsPath, "utf8"));
    requests.requests = requests.requests.filter((request) => request.phase !== "Phase 2");
    writeFileSync(requestsPath, JSON.stringify(requests, null, 2));

    const report = JSON.parse(runScript("scripts/report-phase-completion-audit.mjs", [
      "--external-requests", requestsPath
    ]));

    assert.equal(report.complete, false);
    assert.equal(report.externallyCovered, false);
    assert.ok(report.uncoveredRemaining.some((item) => item.phase === "Phase 2"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
