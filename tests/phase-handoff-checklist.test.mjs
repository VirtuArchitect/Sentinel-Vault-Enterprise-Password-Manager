import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("phase handoff checklist turns readiness and external requests into owner actions", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-handoff-${process.pid}-${Date.now()}`);
  try {
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

    assert.equal(result.format, "sentinel-phase-handoff-checklist-result-v1");
    assert.equal(result.requestCount, 6);
    assert.equal(result.ready, false);
    assert.ok(result.blockerCount > 0);
    assert.ok(existsSync(checklistPath));

    const checklist = readFileSync(checklistPath, "utf8");
    assert.match(checklist, /Sentinel Vault Phase Handoff Checklist/);
    assert.match(checklist, /Current Blocker Summary/);
    assert.match(checklist, /evidence-items:/);
    assert.match(checklist, /Phase 6: MSI\/MSIX signing evidence from approved release host/);
    assert.match(checklist, /- \[ \] Approved code-signing certificate or PFX access on the release host/);
    assert.match(checklist, /pnpm report:phase-readiness/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
