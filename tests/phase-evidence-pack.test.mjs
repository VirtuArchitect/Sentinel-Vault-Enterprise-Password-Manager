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

const prepareEvidencePackInputs = (dir) => {
  const workspace = JSON.parse(runScript("scripts/prepare-deployment-evidence-workspace.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out-dir", dir
  ]));
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", path.join(dir, "external-evidence-requests.json"),
    "--markdown-out", path.join(dir, "external-evidence-requests.md")
  ]);
  runScript("scripts/report-deployment-evidence-status.mjs", [
    "--bundle", workspace.bundlePath,
    "--out", path.join(dir, "deployment-evidence-status.json")
  ]);
  runScript("scripts/report-phase-completion-audit.mjs", [
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-completion-audit.json"),
    "--markdown-out", path.join(dir, "phase-completion-audit.md")
  ]);
  runScript("scripts/validate-phase-completion-audit.mjs", [
    "--audit", path.join(dir, "phase-completion-audit.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json")
  ]);
  runScript("scripts/report-phase-readiness.mjs", [
    "--bundle", workspace.bundlePath,
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-readiness.json"),
    "--markdown-out", path.join(dir, "phase-readiness.md")
  ]);
  runScript("scripts/prepare-phase-handoff-checklist.mjs", [
    "--readiness", path.join(dir, "phase-readiness.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-handoff-checklist.md")
  ]);
};

test("phase evidence pack manifest hashes release review artifacts", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-pack-${process.pid}-${Date.now()}`);
  try {
    prepareEvidencePackInputs(dir);
    const manifestPath = path.join(dir, "phase-evidence-pack-manifest.json");
    const result = JSON.parse(runScript("scripts/package-phase-evidence.mjs", [
      "--dir", dir,
      "--out", manifestPath
    ]));

    assert.equal(result.format, "sentinel-phase-evidence-pack-result-v1");
    assert.equal(result.artifactCount, 10);
    assert.equal(result.ready, false);
    assert.ok(result.blockerCount > 0);
    assert.ok(existsSync(manifestPath));

    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.format, "sentinel-phase-evidence-pack-manifest-v1");
    assert.equal(manifest.environment, "pilot");
    assert.equal(manifest.requestCount, 7);
    assert.equal(manifest.remainingExternallyCovered, true);
    assert.equal(Object.keys(manifest.artifacts).length, 10);
    assert.ok(manifest.artifacts.deploymentWorkspaceManifest);
    assert.match(manifest.artifacts.phaseReadiness.sha256, /^[a-f0-9]{64}$/);
    assert.ok(manifest.artifacts.phaseHandoffChecklist.bytes > 0);
    assert.equal(manifest.deploymentEvidenceSummary.total, 26);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase evidence pack validator accepts unchanged manifests", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-pack-valid-${process.pid}-${Date.now()}`);
  try {
    prepareEvidencePackInputs(dir);
    const manifestPath = path.join(dir, "phase-evidence-pack-manifest.json");
    runScript("scripts/package-phase-evidence.mjs", [
      "--dir", dir,
      "--out", manifestPath
    ]);

    const validation = JSON.parse(runScript("scripts/validate-phase-evidence-pack.mjs", [
      "--manifest", manifestPath
    ]));

    assert.equal(validation.format, "sentinel-phase-evidence-pack-validation-v1");
    assert.equal(validation.validated, true);
    assert.equal(validation.artifactCount, 10);
    assert.equal(validation.ready, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase evidence pack validator rejects changed artifacts", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-pack-tampered-${process.pid}-${Date.now()}`);
  try {
    prepareEvidencePackInputs(dir);
    const manifestPath = path.join(dir, "phase-evidence-pack-manifest.json");
    runScript("scripts/package-phase-evidence.mjs", [
      "--dir", dir,
      "--out", manifestPath
    ]);
    writeFileSync(path.join(dir, "phase-readiness.md"), "# tampered readiness report\n");

    assert.throws(() => runScript("scripts/validate-phase-evidence-pack.mjs", [
      "--manifest", manifestPath
    ]), /phaseReadinessMarkdown .*changed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase evidence pack manifest rejects incomplete artifact sets", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-pack-missing-${process.pid}-${Date.now()}`);
  try {
    prepareEvidencePackInputs(dir);
    rmSync(path.join(dir, "phase-handoff-checklist.md"));

    assert.throws(() => runScript("scripts/package-phase-evidence.mjs", [
      "--dir", dir
    ]), /Missing phase evidence artifact phaseHandoffChecklist/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
