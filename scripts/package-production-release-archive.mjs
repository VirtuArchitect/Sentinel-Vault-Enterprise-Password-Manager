import assert from "node:assert/strict";
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

const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const closurePath = path.resolve(args.get("--phase-closure") || path.join(evidenceDir, "phase-closure-archive-manifest.json"));
const releaseGatePath = path.resolve(args.get("--release-gate") || path.join(evidenceDir, "production-release-gate.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "production-release-archive-manifest.json"));

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    path: path.resolve(filePath),
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

assert.ok(existsSync(closurePath), `Phase closure archive manifest not found: ${closurePath}`);
assert.ok(existsSync(releaseGatePath), `Production release gate report not found: ${releaseGatePath}`);

const closure = JSON.parse(readFileSync(closurePath, "utf8"));
const releaseGate = JSON.parse(readFileSync(releaseGatePath, "utf8"));

assert.equal(closure.format, "sentinel-phase-closure-archive-manifest-v1");
assert.equal(releaseGate.format, "sentinel-production-release-gate-v1");
assert.equal(path.resolve(closure.evidenceDir), evidenceDir, "closure evidence directory mismatch");
assert.equal(path.resolve(releaseGate.evidenceDir), evidenceDir, "release gate evidence directory mismatch");
assert.equal(closure.review?.target, releaseGate.target, "closure target must match release gate target");

const archive = {
  format: "sentinel-production-release-archive-manifest-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  target: releaseGate.target,
  ready: releaseGate.ready,
  blockerCount: releaseGate.blockerCount,
  warningCount: releaseGate.warningCount,
  requireClean: releaseGate.requireClean,
  source: closure.source,
  closure: {
    manifest: hashFile(closurePath),
    decision: closure.review?.decision,
    ready: closure.review?.ready,
    validated: closure.review?.validated,
    waiverSummary: closure.review?.waiverSummary,
    evidenceKeySummary: closure.review?.evidenceKeySummary
  },
  releaseGate: {
    report: hashFile(releaseGatePath),
    ready: releaseGate.ready,
    blockerCount: releaseGate.blockerCount,
    warningCount: releaseGate.warningCount,
    generatedAt: releaseGate.generatedAt
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(archive, null, 2));

console.log(JSON.stringify({
  format: "sentinel-production-release-archive-result-v1",
  outputPath,
  target: archive.target,
  ready: archive.ready,
  blockerCount: archive.blockerCount,
  warningCount: archive.warningCount,
  cleanTree: archive.source?.cleanTree === true,
  waivedEvidenceKeyCount: archive.closure.evidenceKeySummary?.waivedEvidenceKeyCount || 0
}, null, 2));
