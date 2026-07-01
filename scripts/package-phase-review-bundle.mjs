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
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-review-bundle-manifest.json"));

const artifactMap = {
  phaseEvidenceManifest: args.get("--phase-evidence") || path.join(evidenceDir, "phase-evidence-pack-manifest.json"),
  phaseGateValidation: args.get("--phase-gate") || path.join(evidenceDir, "phase-gate-validation.json"),
  phaseGateValidationMarkdown: args.get("--phase-gate-markdown") || path.join(evidenceDir, "phase-gate-validation.md")
};

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    path: path.resolve(filePath),
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

for (const [name, filePath] of Object.entries(artifactMap)) {
  assert.ok(existsSync(filePath), `Missing phase review artifact ${name}: ${filePath}`);
}

const phaseEvidence = JSON.parse(readFileSync(artifactMap.phaseEvidenceManifest, "utf8"));
const phaseGate = JSON.parse(readFileSync(artifactMap.phaseGateValidation, "utf8"));

assert.equal(phaseEvidence.format, "sentinel-phase-evidence-pack-manifest-v1");
assert.equal(phaseGate.format, "sentinel-phase-gate-validation-v1");
assert.equal(phaseGate.paths.phaseEvidenceManifest, path.resolve(artifactMap.phaseEvidenceManifest), "phase gate does not reference selected phase evidence manifest");

const artifacts = Object.fromEntries(Object.entries(artifactMap).map(([name, filePath]) => [name, hashFile(filePath)]));
const manifest = {
  format: "sentinel-phase-review-bundle-manifest-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  environment: phaseEvidence.environment,
  target: phaseEvidence.target,
  ready: phaseGate.ready,
  validated: phaseGate.validated,
  blockerCount: phaseGate.blockerCount,
  warningCount: phaseGate.warningCount,
  remainingPhaseCount: phaseGate.remainingPhaseCount,
  remainingItemCount: phaseGate.remainingItemCount,
  artifacts
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(manifest, null, 2));

console.log(JSON.stringify({
  format: "sentinel-phase-review-bundle-result-v1",
  outputPath,
  artifactCount: Object.keys(artifacts).length,
  ready: manifest.ready,
  validated: manifest.validated,
  blockerCount: manifest.blockerCount
}, null, 2));
