import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

const runValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-external-evidence-requests.mjs",
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
    assert.equal(result.requestCount, 7);
    assert.ok(existsSync(jsonPath));
    assert.ok(existsSync(markdownPath));

    const report = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(report.format, "sentinel-external-evidence-requests-v1");
    assert.equal(report.owner, "platform-security");
    assert.equal(report.summary.total, 7);
    assert.deepEqual(report.summary.phases, ["Phase 2", "Phase 4", "Phase 5", "Phase 6", "Phase 7", "Phase 8"]);
    assert.ok(report.requests.some((request) => request.title.includes("Postgres HA")));
    assert.ok(report.requests.some((request) => request.title.includes("MSI/MSIX signing")));
    assert.ok(report.requests.some((request) => request.evidenceTemplates.includes("docs/templates/windows-signing-execution-evidence.json")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:native-companion -- <native-companion-evidence.json>")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:windows-signing -- <windows-signing-execution-evidence.json>")));
    assert.ok(report.requests.every((request) => request.acceptanceCriteria.length >= 3));

    const markdown = readFileSync(markdownPath, "utf8");
    assert.match(markdown, /Production browser extension rollout evidence/);
    assert.match(markdown, /Provider SDK-backed KMS\/HSM approval/);
    assert.match(markdown, /pnpm validate:deployment-evidence/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("external evidence request validator accepts strict generated request packs", () => {
  const dir = path.join(tmpdir(), `sentinel-external-evidence-validate-${process.pid}-${Date.now()}`);
  const jsonPath = path.join(dir, "requests.json");
  const markdownPath = path.join(dir, "requests.md");
  try {
    runRequests([
      "--environment", "pilot",
      "--owner", "platform-security",
      "--out", jsonPath,
      "--markdown-out", markdownPath
    ]);

    const result = JSON.parse(runValidator(["--requests", jsonPath, "--strict"]));
    assert.equal(result.format, "sentinel-external-evidence-requests-validation-v1");
    assert.equal(result.validated, true);
    assert.equal(result.strict, true);
    assert.equal(result.requestCount, 7);
    assert.ok(result.templateCount >= 10);
    assert.equal(result.validatorCommandCount, 10);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("external evidence request validator rejects incomplete request packs", () => {
  const dir = path.join(tmpdir(), `sentinel-external-evidence-invalid-${process.pid}-${Date.now()}`);
  const jsonPath = path.join(dir, "requests.json");
  const markdownPath = path.join(dir, "requests.md");
  try {
    runRequests([
      "--environment", "pilot",
      "--owner", "platform-security",
      "--out", jsonPath,
      "--markdown-out", markdownPath
    ]);
    const report = JSON.parse(readFileSync(jsonPath, "utf8"));
    report.requests = report.requests.filter((request) => request.blockerType !== "native-security-approval");
    writeFileSync(jsonPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator(["--requests", jsonPath, "--strict"]), /requests must include at least 7 item/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
