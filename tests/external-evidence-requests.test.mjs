import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runRequests = (args) => execFileSync(process.execPath, [
  "scripts/generate-external-evidence-requests.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("external evidence request generator writes remaining phase request pack", () => {
  const dir = path.join(tmpdir(), `sentinel-external-evidence-${process.pid}-${Date.now()}`);
  const jsonPath = path.join(dir, "requests.json");
  const markdownPath = path.join(dir, "requests.md");
  try {
    const result = JSON.parse(runRequests([
      "--environment", "pilot",
      "--owner", "platform-security",
      "--out", jsonPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-external-evidence-requests-result-v1");
    assert.equal(result.environment, "pilot");
    assert.equal(result.requestCount, 6);
    assert.ok(existsSync(jsonPath));
    assert.ok(existsSync(markdownPath));

    const report = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(report.format, "sentinel-external-evidence-requests-v1");
    assert.equal(report.owner, "platform-security");
    assert.equal(report.summary.total, 6);
    assert.deepEqual(report.summary.phases, ["Phase 4", "Phase 5", "Phase 6", "Phase 7", "Phase 8"]);
    assert.ok(report.requests.some((request) => request.title.includes("MSI/MSIX signing")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:native-companion -- <native-companion-evidence.json>")));
    assert.ok(report.requests.every((request) => request.acceptanceCriteria.length >= 3));

    const markdown = readFileSync(markdownPath, "utf8");
    assert.match(markdown, /Production browser extension rollout evidence/);
    assert.match(markdown, /Provider SDK-backed KMS\/HSM approval/);
    assert.match(markdown, /pnpm validate:deployment-evidence/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
