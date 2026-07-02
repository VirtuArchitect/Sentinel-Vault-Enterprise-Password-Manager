import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
for (let index = 0; index < cliArgs.length; index += 1) {
  const arg = cliArgs[index];
  if (arg.startsWith("--")) {
    const next = cliArgs[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(arg, true);
    } else {
      args.set(arg, next);
      index += 1;
    }
  }
}

const rootDir = path.resolve(import.meta.dirname, "..");
const archivePath = path.resolve(args.get("--manifest") || "artifacts/deployment/pilot/production-release-archive-manifest.json");
const evidenceDir = args.get("--dir") ? path.resolve(args.get("--dir")) : null;
const closurePath = args.get("--phase-closure") ? path.resolve(args.get("--phase-closure")) : null;
const releaseGatePath = args.get("--release-gate") ? path.resolve(args.get("--release-gate")) : null;
const target = args.get("--target") || null;
const requireCleanArg = args.has("--require-clean") ? args.get("--require-clean") : null;
const requireReady = args.get("--require-ready") === true || args.get("--require-ready") === "true";
const requireApprovedWaivers = args.get("--require-approved-waivers") === true || args.get("--require-approved-waivers") === "true";

const runJson = (script, scriptArgs) => JSON.parse(execFileSync(process.execPath, [script, ...scriptArgs], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
}));

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

assert.ok(existsSync(archivePath), `Production release archive manifest not found: ${archivePath}`);
const archive = JSON.parse(readFileSync(archivePath, "utf8"));
assert.equal(archive.format, "sentinel-production-release-archive-manifest-v1");
assert.ok(!Number.isNaN(Date.parse(archive.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(archive.evidenceDir, "archive evidence directory is required");
assert.ok(archive.target, "archive target is required");
assert.equal(typeof archive.ready, "boolean", "archive ready flag must be boolean");
assert.equal(typeof archive.requireClean, "boolean", "archive requireClean flag must be boolean");
assert.ok(archive.closure?.manifest?.path, "closure manifest path is required");
assert.ok(archive.releaseGate?.report?.path, "release gate report path is required");

const selectedEvidenceDir = evidenceDir || path.resolve(archive.evidenceDir);
const selectedClosurePath = closurePath || archive.closure.manifest.path;
const selectedReleaseGatePath = releaseGatePath || archive.releaseGate.report.path;
const selectedTarget = target || archive.target;
const selectedRequireClean = requireCleanArg === null
  ? archive.requireClean
  : requireCleanArg === true || requireCleanArg === "true";

assert.equal(path.resolve(archive.evidenceDir), selectedEvidenceDir, "archive evidence directory mismatch");
assert.equal(archive.target, selectedTarget, "archive target mismatch");
assert.equal(archive.closure.manifest.path, selectedClosurePath, "archive closure manifest path mismatch");
assert.equal(archive.releaseGate.report.path, selectedReleaseGatePath, "archive release gate report path mismatch");
assert.ok(existsSync(selectedClosurePath), `Phase closure archive manifest not found: ${selectedClosurePath}`);
assert.ok(existsSync(selectedReleaseGatePath), `Production release gate report not found: ${selectedReleaseGatePath}`);

const closureHash = hashFile(selectedClosurePath);
assert.equal(closureHash.bytes, archive.closure.manifest.bytes, "closure manifest byte length changed");
assert.equal(closureHash.sha256, archive.closure.manifest.sha256, "closure manifest SHA-256 changed");

const releaseGateHash = hashFile(selectedReleaseGatePath);
assert.equal(releaseGateHash.bytes, archive.releaseGate.report.bytes, "release gate report byte length changed");
assert.equal(releaseGateHash.sha256, archive.releaseGate.report.sha256, "release gate report SHA-256 changed");

const closure = JSON.parse(readFileSync(selectedClosurePath, "utf8"));
const releaseGate = JSON.parse(readFileSync(selectedReleaseGatePath, "utf8"));
assert.equal(closure.format, "sentinel-phase-closure-archive-manifest-v1");
assert.equal(releaseGate.format, "sentinel-production-release-gate-v1");
assert.equal(path.resolve(closure.evidenceDir), selectedEvidenceDir, "closure evidence directory mismatch");
assert.equal(path.resolve(releaseGate.evidenceDir), selectedEvidenceDir, "release gate evidence directory mismatch");
assert.equal(closure.review?.target, archive.target, "closure target mismatch");
assert.equal(releaseGate.target, archive.target, "release gate target mismatch");
assert.equal(releaseGate.requireClean, archive.requireClean, "release gate clean-source mode mismatch");
assert.equal(selectedRequireClean, archive.requireClean, "archive clean-source validation mode mismatch");
assert.equal(archive.ready, releaseGate.ready, "archive ready flag mismatch");
assert.equal(archive.blockerCount, releaseGate.blockerCount, "archive blocker count mismatch");
assert.equal(archive.warningCount, releaseGate.warningCount, "archive warning count mismatch");
assert.equal(archive.releaseGate.ready, releaseGate.ready, "release gate ready summary mismatch");
assert.equal(archive.releaseGate.blockerCount, releaseGate.blockerCount, "release gate blocker summary mismatch");
assert.equal(archive.releaseGate.warningCount, releaseGate.warningCount, "release gate warning summary mismatch");
assert.deepEqual(archive.source, closure.source, "archive source provenance must match closure archive");
assert.equal(archive.closure.decision, closure.review?.decision, "closure decision mismatch");
assert.equal(archive.closure.ready, closure.review?.ready, "closure ready flag mismatch");
assert.equal(archive.closure.validated, closure.review?.validated, "closure validated flag mismatch");
assert.deepEqual(archive.closure.waiverSummary, closure.review?.waiverSummary, "closure waiver summary mismatch");

const closureValidation = runJson("scripts/validate-phase-closure-archive.mjs", [
  "--manifest", selectedClosurePath,
  ...(selectedRequireClean ? ["--require-clean"] : []),
  ...(requireApprovedWaivers ? ["--require-approved-waivers"] : [])
]);
const releaseGateValidation = runJson("scripts/validate-production-release-gate-report.mjs", [
  "--dir", selectedEvidenceDir,
  "--report", selectedReleaseGatePath,
  "--target", selectedTarget,
  ...(selectedRequireClean ? ["--require-clean"] : []),
  ...(requireReady ? ["--require-ready"] : [])
]);

if (requireReady) {
  assert.equal(archive.ready, true, "production release archive is not ready");
}

console.log(JSON.stringify({
  format: "sentinel-production-release-archive-validation-v1",
  archivePath,
  evidenceDir: selectedEvidenceDir,
  target: selectedTarget,
  ready: archive.ready,
  blockerCount: archive.blockerCount,
  warningCount: archive.warningCount,
  requireClean: selectedRequireClean,
  cleanTree: archive.source?.cleanTree === true,
  closureValidated: closureValidation.validated === true,
  releaseGateValidated: releaseGateValidation.validated === true,
  validated: true
}, null, 2));
