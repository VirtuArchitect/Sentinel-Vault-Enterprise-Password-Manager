import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const reviewManifestPath = path.resolve(args.get("--phase-review") || path.join(evidenceDir, "phase-review-bundle-manifest.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-closure-archive-manifest.json"));

const git = (gitArgs) => execFileSync("git", gitArgs, {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
}).trim();

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    path: path.resolve(filePath),
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

assert.ok(existsSync(reviewManifestPath), `Phase review bundle manifest not found: ${reviewManifestPath}`);
const reviewManifest = JSON.parse(readFileSync(reviewManifestPath, "utf8"));
assert.equal(reviewManifest.format, "sentinel-phase-review-bundle-manifest-v1");

const statusPorcelain = git(["status", "--porcelain"]);
const sourceCommit = git(["rev-parse", "HEAD"]);
const sourceBranch = git(["rev-parse", "--abbrev-ref", "HEAD"]);
const sourceRemote = git(["remote", "get-url", "origin"]);

const artifactNames = Object.keys(reviewManifest.artifacts || {});
const archive = {
  format: "sentinel-phase-closure-archive-manifest-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  source: {
    commit: sourceCommit,
    branch: sourceBranch,
    remote: sourceRemote,
    cleanTree: statusPorcelain.length === 0,
    statusPorcelain
  },
  review: {
    manifest: hashFile(reviewManifestPath),
    environment: reviewManifest.environment,
    target: reviewManifest.target,
    ready: reviewManifest.ready,
    validated: reviewManifest.validated,
    decision: reviewManifest.decision,
    blockerCount: reviewManifest.blockerCount,
    warningCount: reviewManifest.warningCount,
    waiverSummary: reviewManifest.waiverSummary,
    artifactCount: artifactNames.length,
    artifactNames
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(archive, null, 2));

console.log(JSON.stringify({
  format: "sentinel-phase-closure-archive-result-v1",
  outputPath,
  sourceCommit,
  cleanTree: archive.source.cleanTree,
  decision: archive.review.decision,
  artifactCount: archive.review.artifactCount,
  waiverCount: archive.review.waiverSummary?.waiverCount || 0,
  approvedWaiverCount: archive.review.waiverSummary?.approvedCount || 0
}, null, 2));
