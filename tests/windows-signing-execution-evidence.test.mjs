import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-windows-signing-execution-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-windows-signing-execution-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const hex = (char, length) => char.repeat(length);
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("windows signing execution evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "windows-signing-execution-evidence.json")), /validated/);
});

test("windows signing generator creates signed evidence from release host report", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-signing-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.msix");
    const reportPath = path.join(dir, "signing-report.json");
    const evidencePath = path.join(dir, "windows-signing-execution-evidence.json");
    writeFileSync(artifactPath, "signed msix fixture");
    writeFileSync(reportPath, JSON.stringify({
      signedAt: "2026-07-01T10:00:00Z",
      releaseHost: {
        hostnameHash: hash("release-host-01"),
        osBuild: "Windows Server 2025 10.0.26100",
        runnerIdentity: "sentinel-release-runner",
        certificateSource: "certificate-store",
        approvedHost: "passed"
      },
      certificate: {
        subject: "CN=Sentinel Vault Publisher",
        thumbprint: hex("a", 40),
        issuer: "CN=Example Code Signing CA",
        validFrom: "2026-01-01",
        validTo: "2027-01-01",
        timestampAuthority: "https://timestamp.example.test"
      },
      artifacts: [{
        type: "msix",
        path: artifactPath,
        signatureStatus: "passed",
        timestampStatus: "passed",
        authenticodeStatus: "valid"
      }],
      approvals: {
        releaseOwner: "Release Owner",
        securityReviewer: "Security Reviewer",
        operationsOwner: "Operations Owner",
        changeTicket: "CHG-1001"
      }
    }, null, 2));

    assert.match(runGenerator([
      "--status", "signed",
      "--environment", "pilot",
      "--release-version", "1.0.0",
      "--report", reportPath,
      "--out", evidencePath
    ]), /written/);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.format, "sentinel-windows-signing-execution-evidence-v1");
    assert.equal(evidence.artifacts[0].sha256, hash("signed msix fixture"));
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows signing validator rejects leaked signing secrets and mismatched hashes", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-signing-fail-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.msi");
    const evidencePath = path.join(dir, "windows-signing-execution-evidence.json");
    writeFileSync(artifactPath, "real artifact bytes");
    writeFileSync(evidencePath, JSON.stringify({
      format: "sentinel-windows-signing-execution-evidence-v1",
      status: "signed",
      environment: "pilot",
      releaseVersion: "1.0.0",
      signedAt: "2026-07-01T10:00:00Z",
      releaseHost: {
        hostnameHash: hash("release-host-01"),
        osBuild: "Windows Server 2025 10.0.26100",
        runnerIdentity: "sentinel-release-runner",
        certificateSource: "pfx",
        approvedHost: "passed"
      },
      certificate: {
        subject: "CN=Sentinel Vault Publisher",
        thumbprint: hex("b", 40),
        issuer: "CN=Example Code Signing CA",
        validFrom: "2026-01-01",
        validTo: "2027-01-01",
        timestampAuthority: "https://timestamp.example.test"
      },
      artifacts: [{
        type: "msi",
        path: artifactPath,
        sha256: hex("c", 64),
        signatureStatus: "passed",
        timestampStatus: "passed",
        authenticodeStatus: "valid"
      }],
      checks: {
        packageBuiltOnReleaseHost: "passed",
        signaturesVerified: "passed",
        timestampsVerified: "passed",
        hashesRecorded: "passed",
        rollbackArtifactSigned: "passed",
        uninstallDrillCovered: "passed"
      },
      approvals: {
        releaseOwner: "Release Owner",
        securityReviewer: "Security Reviewer",
        operationsOwner: "Operations Owner",
        changeTicket: "CHG-1001"
      },
      redaction: {
        containsPfxPassword: true,
        containsPrivateKeyMaterial: false,
        containsSigningToken: false
      }
    }, null, 2));

    assert.throws(() => runValidator(evidencePath), /cannot contain a PFX password/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
