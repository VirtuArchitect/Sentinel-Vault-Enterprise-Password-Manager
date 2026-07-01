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
    assert.ok(report.phases.some((phase) => phase.number === 2 && phase.implementedCount > 0));
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

test("phase completion audit validator accepts generated covered audits", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-completion-valid-${process.pid}-${Date.now()}`);
  try {
    const requestsPath = createExternalRequests(dir);
    const reportPath = path.join(dir, "phase-completion-audit.json");
    runScript("scripts/report-phase-completion-audit.mjs", [
      "--external-requests", requestsPath,
      "--out", reportPath
    ]);

    const validation = JSON.parse(runScript("scripts/validate-phase-completion-audit.mjs", [
      "--audit", reportPath,
      "--external-requests", requestsPath
    ]));

    assert.equal(validation.format, "sentinel-phase-completion-audit-validation-v1");
    assert.equal(validation.validated, true);
    assert.equal(validation.externallyCovered, true);
    assert.equal(validation.complete, false);
    assert.ok(validation.remainingItemCount > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase completion audit validator rejects stale counts", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-completion-stale-${process.pid}-${Date.now()}`);
  try {
    const requestsPath = createExternalRequests(dir);
    const reportPath = path.join(dir, "phase-completion-audit.json");
    runScript("scripts/report-phase-completion-audit.mjs", [
      "--external-requests", requestsPath,
      "--out", reportPath
    ]);
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    report.remainingItemCount = 0;
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-completion-audit.mjs", [
      "--audit", reportPath,
      "--external-requests", requestsPath
    ]), /remainingItemCount is stale/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase completion audit validator can fail when remaining work exists", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-completion-gate-${process.pid}-${Date.now()}`);
  try {
    const requestsPath = createExternalRequests(dir);
    const reportPath = path.join(dir, "phase-completion-audit.json");
    runScript("scripts/report-phase-completion-audit.mjs", [
      "--external-requests", requestsPath,
      "--out", reportPath
    ]);

    assert.throws(() => runScript("scripts/validate-phase-completion-audit.mjs", [
      "--audit", reportPath,
      "--external-requests", requestsPath,
      "--fail-on-remaining"
    ]), /phase completion audit still has remaining work/);
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
