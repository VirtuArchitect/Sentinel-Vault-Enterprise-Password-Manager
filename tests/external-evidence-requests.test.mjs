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
    assert.ok(report.summary.commandScriptCount > 20);
    assert.ok(report.summary.commandScripts.includes("validate:windows-signing"));
    assert.ok(report.summary.commandScripts.includes("validate:postgres-schema"));
    assert.ok(report.summary.commandScripts.includes("validate:extension-package"));
    assert.ok(report.summary.commandScripts.includes("validate:native-artifacts"));
    assert.ok(report.summary.commandScripts.includes("release:kms-hsm-sdk-approval"));
    assert.ok(report.requests.some((request) => request.title.includes("Postgres HA")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:postgres-schema -- --out <postgres-schema-validation.json>")));
    assert.ok(report.requests.some((request) => request.title.includes("MSI/MSIX signing")));
    assert.ok(report.requests.some((request) => request.evidenceTemplates.includes("docs/templates/windows-signing-execution-evidence.json")));
    assert.ok(report.requests.some((request) => request.evidenceKeys.includes("windowsSigning")));
    assert.ok(report.requests.some((request) => request.evidenceKeys.includes("sourceMigration")));
    assert.ok(report.requests.some((request) => request.evidenceKeys.includes("kmsHsmSdkApproval")));
    assert.ok(report.requests.every((request) => request.evidenceKeys.length >= 2));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:native-companion -- <native-companion-evidence.json>")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:windows-signing -- <windows-signing-execution-evidence.json>")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:kms-hsm-sdk-approval -- <kms-hsm-sdk-approval-evidence.json>")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:browser-identity -- <browser-extension-identity-evidence.json>")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:extension-package -- --package <sentinel-vault-autofill.zip> --out <browser-extension-package-validation.json>")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:credential-provider-approval -- <credential-provider-approval-evidence.json>")));
    assert.ok(report.requests.some((request) => request.commands.includes("pnpm validate:native-artifacts -- --artifact <signed-credential-provider-artifact> --require-signature --out <native-artifact-validation.json>")));
    assert.ok(report.requests.every((request) => request.acceptanceCriteria.length >= 3));

    const markdown = readFileSync(markdownPath, "utf8");
    assert.match(markdown, /Production browser extension rollout evidence/);
    assert.match(markdown, /Provider SDK-backed KMS\/HSM approval/);
    assert.match(markdown, /Command scripts:/);
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

    const result = JSON.parse(runValidator(["--requests", jsonPath, "--markdown", markdownPath, "--strict"]));
    assert.equal(result.format, "sentinel-external-evidence-requests-validation-v1");
    assert.equal(result.validated, true);
    assert.equal(result.strict, true);
    assert.equal(result.markdownPath, markdownPath);
    assert.equal(result.requestCount, 7);
    assert.ok(result.templateCount >= 10);
    assert.equal(result.evidenceKeyCount, 18);
    assert.ok(result.commandScriptCount > 20);
    assert.equal(result.validatorCommandCount, 17);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("external evidence request validator rejects stale markdown request packs", () => {
  const dir = path.join(tmpdir(), `sentinel-external-evidence-markdown-invalid-${process.pid}-${Date.now()}`);
  const jsonPath = path.join(dir, "requests.json");
  const markdownPath = path.join(dir, "requests.md");
  try {
    runRequests([
      "--environment", "pilot",
      "--owner", "platform-security",
      "--out", jsonPath,
      "--markdown-out", markdownPath
    ]);
    const markdown = readFileSync(markdownPath, "utf8")
      .replace("- `pnpm validate:native-companion -- <native-companion-evidence.json>`\n", "");
    writeFileSync(markdownPath, markdown);

    assert.throws(() => runValidator([
      "--requests", jsonPath,
      "--markdown", markdownPath,
      "--strict"
    ]), /markdown is missing command/);
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

test("external evidence request validator rejects missing package scripts", () => {
  const dir = path.join(tmpdir(), `sentinel-external-evidence-command-invalid-${process.pid}-${Date.now()}`);
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
    report.requests[0].commands.push("pnpm missing:script -- <evidence.json>");
    report.summary.commandScripts.push("missing:script");
    report.summary.commandScripts.sort();
    report.summary.commandScriptCount = report.summary.commandScripts.length;
    writeFileSync(jsonPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator(["--requests", jsonPath, "--strict"]), /missing package script/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("external evidence request validator rejects evidence keys missing from bundle template", () => {
  const dir = path.join(tmpdir(), `sentinel-external-evidence-key-invalid-${process.pid}-${Date.now()}`);
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
    report.requests[0].evidenceKeys.push("missingBundleEvidenceKey");
    writeFileSync(jsonPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator(["--requests", jsonPath, "--strict"]), /evidence key is not present/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("external evidence request validator rejects evidence keys mapped to the wrong template", () => {
  const dir = path.join(tmpdir(), `sentinel-external-evidence-template-invalid-${process.pid}-${Date.now()}`);
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
    const request = report.requests.find((candidate) => candidate.evidenceKeys.includes("windowsSigning"));
    request.evidenceTemplates = request.evidenceTemplates.filter((template) => template !== "docs/templates/windows-signing-execution-evidence.json");
    writeFileSync(jsonPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator(["--requests", jsonPath, "--strict"]), /must reference bundle template path/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
