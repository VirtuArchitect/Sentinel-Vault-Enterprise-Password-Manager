import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runWorkspace = (args) => execFileSync(process.execPath, [
  "scripts/prepare-deployment-evidence-workspace.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runBundleValidator = (bundlePath) => execFileSync(process.execPath, [
  "scripts/validate-deployment-evidence-bundle.mjs",
  bundlePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runWorkspaceValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-deployment-evidence-workspace.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("deployment evidence workspace generator copies templates and validates planned bundle", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-workspace-${process.pid}-${Date.now()}`);
  try {
    const output = runWorkspace([
      "--environment", "lab",
      "--owner", "platform-team",
      "--out-dir", dir
    ]);
    const result = JSON.parse(output);
    assert.equal(result.format, "sentinel-deployment-evidence-workspace-v1");
    assert.equal(result.environment, "lab");
    assert.ok(result.evidenceCount >= 20);
    assert.ok(existsSync(result.manifestPath));
    assert.ok(existsSync(path.join(dir, "README.md")));

    const bundle = JSON.parse(readFileSync(result.bundlePath, "utf8"));
    assert.equal(bundle.environment, "lab");
    assert.equal(bundle.owner, "platform-team");
    assert.equal(bundle.status, "planned");
    assert.match(bundle.evidence.connector, /^evidence\//);
    assert.ok(existsSync(path.join(dir, bundle.evidence.connector)));

    const validation = JSON.parse(runBundleValidator(result.bundlePath));
    assert.equal(validation.status, "planned");
    assert.equal(validation.results.connector.validated, true);
    assert.equal(validation.results.releaseAttestation.validated, true);

    const workspaceValidation = JSON.parse(runWorkspaceValidator([
      "--manifest", result.manifestPath,
      "--bundle", result.bundlePath
    ]));
    assert.equal(workspaceValidation.format, "sentinel-deployment-evidence-workspace-validation-v1");
    assert.equal(workspaceValidation.validated, true);
    assert.equal(workspaceValidation.evidenceCount, result.evidenceCount);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment evidence workspace validator rejects changed evidence files", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-workspace-tamper-${process.pid}-${Date.now()}`);
  try {
    const result = JSON.parse(runWorkspace([
      "--environment", "lab",
      "--owner", "platform-team",
      "--out-dir", dir
    ]));
    writeFileSync(path.join(dir, "evidence", "connector-certification-evidence.json"), "{}\n");

    assert.throws(() => runWorkspaceValidator([
      "--manifest", result.manifestPath,
      "--bundle", result.bundlePath
    ]), /evidence\.connector .*changed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment evidence workspace validator rejects template drift", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-workspace-template-drift-${process.pid}-${Date.now()}`);
  try {
    const result = JSON.parse(runWorkspace([
      "--environment", "lab",
      "--owner", "platform-team",
      "--out-dir", dir
    ]));
    const bundle = JSON.parse(readFileSync(result.bundlePath, "utf8"));
    const templatePath = path.join(dir, "deployment-evidence-bundle-template.json");
    writeFileSync(templatePath, JSON.stringify({
      ...bundle,
      evidence: {
        ...bundle.evidence,
        futureGate: "docs/templates/connector-certification-evidence.json"
      }
    }, null, 2));

    assert.throws(() => runWorkspaceValidator([
      "--manifest", result.manifestPath,
      "--bundle", result.bundlePath,
      "--template", templatePath
    ]), /workspace evidence names do not match current deployment evidence template/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment evidence workspace generator rejects unsupported status", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-workspace-fail-${process.pid}-${Date.now()}`);
  try {
    assert.throws(() => runWorkspace([
      "--environment", "lab",
      "--status", "complete",
      "--out-dir", dir
    ]), /status must be/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
