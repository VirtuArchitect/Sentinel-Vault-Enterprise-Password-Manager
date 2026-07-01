import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = args.get("--out") || "artifacts/release/release-attestation-evidence.json";
const provenancePath = args.get("--provenance") || "artifacts/release/release-provenance.json";
const statementPath = args.get("--statement") || "replace-with-attestation-path";
const signaturePath = args.get("--signature") || "replace-with-signature-path";
const status = args.get("--status") || "planned";
const artifactArgs = cliArgs.flatMap((arg, index) => (arg === "--artifact" ? [cliArgs[index + 1]] : [])).filter(Boolean);

const sha256File = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const safeGit = (...gitArgs) => {
  try {
    return execFileSync("git", gitArgs, { encoding: "utf8" }).trim();
  } catch {
    return null;
  }
};
const checkStatus = (argName, fallback = "planned") => {
  const value = args.get(argName) || fallback;
  const allowed = new Set(["planned", "passed", "failed", "not-applicable"]);
  if (!allowed.has(value)) {
    throw new Error(`${argName} must be planned, passed, failed, or not-applicable`);
  }
  return value;
};
const asBool = (value, fallback) => {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  return fallback;
};
const placeholderSha = "replace-with-sha256";
const provenance = existsSync(provenancePath) ? readJson(provenancePath) : null;
const source = provenance?.source || {};
const packageInfo = provenance?.package || {};
const lockfile = provenance?.lockfile || {};
const provenanceArtifacts = Array.isArray(provenance?.artifacts) ? provenance.artifacts.filter((artifact) => artifact.exists) : [];
const artifactPaths = artifactArgs.length > 0 ? artifactArgs : provenanceArtifacts.map((artifact) => artifact.path).filter(Boolean);
const artifactEvidence = artifactPaths.length > 0
  ? artifactPaths.map((artifactPath) => ({
      name: path.basename(artifactPath),
      sha256: existsSync(artifactPath) ? sha256File(artifactPath) : placeholderSha,
      size: existsSync(artifactPath) ? statSync(artifactPath).size : 0
    }))
  : [{
      name: "replace-with-artifact-name",
      sha256: placeholderSha,
      size: 0
    }];
const sampleText = [
  provenance ? JSON.stringify(provenance) : "",
  existsSync(statementPath) ? readFileSync(statementPath, "utf8") : "",
  existsSync(signaturePath) ? readFileSync(signaturePath, "utf8") : "",
  ...artifactPaths.filter((artifactPath) => existsSync(artifactPath)).map((artifactPath) => readFileSync(artifactPath, "utf8"))
].join("\n");

const evidence = {
  format: "sentinel-release-attestation-evidence-v1",
  status,
  releaseVersion: args.get("--release-version") || packageInfo.version || "replace-with-version",
  generatedAt: args.get("--generated-at") || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : new Date().toISOString().replace(/\.\d{3}Z$/, "Z")),
  source: {
    commit: args.get("--commit") || source.commit || safeGit("rev-parse", "HEAD") || "replace-with-git-sha",
    branch: args.get("--branch") || source.branch || safeGit("branch", "--show-current") || "main",
    remote: args.get("--remote") || source.remote || safeGit("remote", "get-url", "origin") || "https://github.com/VirtuArchitect/Sentinel-Vault-Enterprise-Password-Manager.git",
    dirty: asBool(args.get("--dirty"), Boolean(source.dirty ?? safeGit("status", "--porcelain")))
  },
  provenance: {
    path: provenancePath,
    sha256: existsSync(provenancePath) ? sha256File(provenancePath) : placeholderSha,
    lockfileSha256: existsSync(lockfile.path || "pnpm-lock.yaml") ? sha256File(lockfile.path || "pnpm-lock.yaml") : placeholderSha
  },
  checks: {
    pnpmVerify: checkStatus("--pnpm-verify"),
    secretScan: checkStatus("--secret-scan"),
    dependencyAudit: checkStatus("--dependency-audit"),
    windowsSignatureVerification: checkStatus("--windows-signature-verification"),
    provenanceMatchesArtifacts: checkStatus("--provenance-matches-artifacts")
  },
  attestation: {
    type: args.get("--attestation-type") || "replace-with-sigstore-gpg-or-certificate",
    statementPath,
    statementSha256: existsSync(statementPath) ? sha256File(statementPath) : placeholderSha,
    signaturePath,
    signatureSha256: existsSync(signaturePath) ? sha256File(signaturePath) : placeholderSha,
    signerIdentity: args.get("--signer-identity") || "replace-with-signer",
    certificateThumbprint: args.get("--certificate-thumbprint") || "replace-with-thumbprint",
    transparencyLogUrl: args.get("--transparency-log-url") || "replace-with-url-or-not-applicable"
  },
  artifacts: artifactEvidence,
  redaction: {
    privateKeysFound: asBool(args.get("--private-keys-found"), /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i.test(sampleText)),
    tokensFound: asBool(args.get("--tokens-found"), /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(sampleText)),
    secretValuesFound: asBool(args.get("--secret-values-found"), /secret(Value)?\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}|Passw0rd!/i.test(sampleText))
  },
  approvals: {
    releaseOwner: args.get("--release-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsReviewer: args.get("--operations-reviewer") || "replace-with-reviewer"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Release attestation evidence written: ${outputPath}`);
