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
const archivePath = path.resolve(args.get("--manifest") || "artifacts/deployment/pilot/phase-closure-archive-manifest.json");
const reviewManifestPath = args.get("--phase-review") ? path.resolve(args.get("--phase-review")) : null;
const requireClean = args.get("--require-clean") === true || args.get("--require-clean") === "true";
const requireApprovedWaivers = args.get("--require-approved-waivers") === true || args.get("--require-approved-waivers") === "true";

const git = (gitArgs) => execFileSync("git", gitArgs, {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
}).trim();

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

assert.ok(existsSync(archivePath), `Phase closure archive manifest not found: ${archivePath}`);
const archive = JSON.parse(readFileSync(archivePath, "utf8"));
assert.equal(archive.format, "sentinel-phase-closure-archive-manifest-v1");
assert.ok(!Number.isNaN(Date.parse(archive.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.match(archive.source.commit, /^[a-f0-9]{40}$/, "source commit must be a full Git SHA");
assert.ok(archive.source.branch, "source branch is required");
assert.ok(archive.source.remote, "source remote is required");
assert.equal(typeof archive.source.cleanTree, "boolean", "cleanTree must be boolean");
assert.ok(archive.review?.manifest?.path, "review manifest path is required");
assert.match(archive.review.manifest.sha256, /^[a-f0-9]{64}$/, "review manifest SHA-256 is required");
assert.ok(Number.isInteger(archive.review.manifest.bytes) && archive.review.manifest.bytes > 0, "review manifest byte count is required");

const selectedReviewPath = reviewManifestPath || archive.review.manifest.path;
assert.equal(archive.review.manifest.path, selectedReviewPath, "archive review manifest path mismatch");
assert.ok(existsSync(selectedReviewPath), `Phase review bundle manifest not found: ${selectedReviewPath}`);

const actualReviewHash = hashFile(selectedReviewPath);
assert.equal(actualReviewHash.bytes, archive.review.manifest.bytes, "review manifest byte length changed");
assert.equal(actualReviewHash.sha256, archive.review.manifest.sha256, "review manifest SHA-256 changed");

const reviewManifest = JSON.parse(readFileSync(selectedReviewPath, "utf8"));
assert.equal(reviewManifest.format, "sentinel-phase-review-bundle-manifest-v1");
assert.equal(archive.review.environment, reviewManifest.environment, "review environment mismatch");
assert.equal(archive.review.target, reviewManifest.target, "review target mismatch");
assert.equal(archive.review.ready, reviewManifest.ready, "review ready flag mismatch");
assert.equal(archive.review.validated, reviewManifest.validated, "review validated flag mismatch");
assert.equal(archive.review.decision, reviewManifest.decision, "review decision mismatch");
assert.equal(archive.review.blockerCount, reviewManifest.blockerCount, "review blocker count mismatch");
assert.equal(archive.review.warningCount, reviewManifest.warningCount, "review warning count mismatch");
assert.equal(archive.review.artifactCount, Object.keys(reviewManifest.artifacts || {}).length, "review artifact count mismatch");
assert.deepEqual(archive.review.artifactNames, Object.keys(reviewManifest.artifacts || {}), "review artifact names mismatch");
assert.deepEqual(archive.review.waiverSummary, reviewManifest.waiverSummary, "review waiver summary mismatch");
assert.deepEqual(archive.review.evidenceKeySummary, reviewManifest.evidenceKeySummary, "review evidence key summary mismatch");

if (requireApprovedWaivers) {
  const waiverRegisterPath = reviewManifest.artifacts?.phaseWaiverRegister?.path;
  assert.ok(waiverRegisterPath, "phase waiver register artifact is required");
  const phaseWaivers = JSON.parse(readFileSync(waiverRegisterPath, "utf8"));
  const today = new Date().toISOString().slice(0, 10);
  const placeholder = /replace-with/i;
  for (const [index, waiver] of phaseWaivers.waivers.entries()) {
    assert.equal(waiver.status, "approved", `waiver ${index + 1} must be approved for closure archive`);
    assert.match(waiver.expiresAt || "", /^\d{4}-\d{2}-\d{2}$/, `waiver ${index + 1} expiry must be YYYY-MM-DD`);
    assert.ok(waiver.expiresAt > today, `waiver ${index + 1} approval is expired`);
    assert.ok(waiver.approvalReference && !placeholder.test(waiver.approvalReference), `waiver ${index + 1} approval reference is required`);
    assert.ok(waiver.compensatingControl && !placeholder.test(waiver.compensatingControl), `waiver ${index + 1} compensating control is required`);
  }
}

assert.equal(archive.source.commit, git(["rev-parse", "HEAD"]), "archive source commit does not match current HEAD");
assert.equal(archive.source.branch, git(["rev-parse", "--abbrev-ref", "HEAD"]), "archive source branch does not match current branch");
assert.equal(archive.source.remote, git(["remote", "get-url", "origin"]), "archive source remote does not match origin");

if (requireClean) {
  assert.equal(archive.source.cleanTree, true, "archive source tree must be clean");
  assert.equal(archive.source.statusPorcelain, "", "archive source status must be empty");
}

console.log(JSON.stringify({
  format: "sentinel-phase-closure-archive-validation-v1",
  archivePath,
  sourceCommit: archive.source.commit,
  cleanTree: archive.source.cleanTree,
  decision: archive.review.decision,
  artifactCount: archive.review.artifactCount,
  waiverCount: archive.review.waiverSummary?.waiverCount || 0,
  approvedWaiverCount: archive.review.waiverSummary?.approvedCount || 0,
  waivedEvidenceKeyCount: archive.review.evidenceKeySummary?.waivedEvidenceKeyCount || 0,
  validated: true
}, null, 2));
