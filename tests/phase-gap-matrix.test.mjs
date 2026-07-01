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

const createGapWorkspace = (dir) => {
  runScript("scripts/prepare-deployment-evidence-workspace.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out-dir", dir
  ]);
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", path.join(dir, "external-evidence-requests.json"),
    "--markdown-out", path.join(dir, "external-evidence-requests.md")
  ]);
};

test("phase gap matrix maps remaining blockers to deployment evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-gaps-${process.pid}-${Date.now()}`);
  try {
    createGapWorkspace(dir);
    const matrixPath = path.join(dir, "phase-gap-matrix.json");
    const markdownPath = path.join(dir, "phase-gap-matrix.md");
    const result = JSON.parse(runScript("scripts/prepare-phase-gap-matrix.mjs", [
      "--dir", dir,
      "--out", matrixPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-phase-gap-matrix-result-v1");
    assert.equal(result.phaseCount, 7);
    assert.equal(result.deploymentBundleCoveredPhaseCount, 7);
    assert.equal(result.missingArtifactCount, 0);
    assert.ok(existsSync(matrixPath));
    assert.ok(existsSync(markdownPath));

    const matrix = JSON.parse(readFileSync(matrixPath, "utf8"));
    assert.equal(matrix.format, "sentinel-phase-gap-matrix-v1");
    assert.equal(matrix.summary.phaseCount, 7);
    assert.equal(matrix.summary.deploymentBundleCoveredPhaseCount, 7);
    assert.ok(matrix.phases.some((phase) => phase.blockerType === "postgres-ha-approval"));
    assert.ok(matrix.phases.some((phase) => phase.templateMappings.some((mapping) => mapping.bundleEvidenceName === "windowsRelease")));
    assert.match(readFileSync(markdownPath, "utf8"), /Sentinel Vault Phase Gap Matrix/);

    const validation = JSON.parse(runScript("scripts/validate-phase-gap-matrix.mjs", [
      "--matrix", matrixPath,
      "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
      "--external-requests", path.join(dir, "external-evidence-requests.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-gap-matrix-validation-v1");
    assert.equal(validation.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase gap matrix validator rejects stale mapping", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-gaps-stale-${process.pid}-${Date.now()}`);
  try {
    createGapWorkspace(dir);
    const matrixPath = path.join(dir, "phase-gap-matrix.json");
    runScript("scripts/prepare-phase-gap-matrix.mjs", [
      "--dir", dir,
      "--out", matrixPath,
      "--markdown-out", path.join(dir, "phase-gap-matrix.md")
    ]);
    const matrix = JSON.parse(readFileSync(matrixPath, "utf8"));
    matrix.phases[0].templateMappings[0].bundleEvidenceName = "connector";
    writeFileSync(matrixPath, JSON.stringify(matrix, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-gap-matrix.mjs", [
      "--matrix", matrixPath,
      "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
      "--external-requests", path.join(dir, "external-evidence-requests.json")
    ]), /deployment evidence mapping mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
