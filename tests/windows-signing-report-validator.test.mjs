import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-windows-signing-report.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const hex = (char, length) => char.repeat(length);
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");

const validReport = (artifactPath) => ({
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
    sha256: hash("signed msix fixture"),
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
    containsPfxPassword: false,
    containsPrivateKeyMaterial: false,
    containsSigningToken: false
  }
});

test("windows signing report validator accepts release-host report", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-signing-report-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.msix");
    const reportPath = path.join(dir, "signing-report.json");
    const outputPath = path.join(dir, "signing-report-validation.json");
    writeFileSync(artifactPath, "signed msix fixture");
    writeFileSync(reportPath, JSON.stringify(validReport(artifactPath), null, 2));

    const result = JSON.parse(runValidator(["--report", reportPath, "--strict", "--out", outputPath]));
    const output = JSON.parse(readFileSync(outputPath, "utf8"));
    assert.equal(result.validated, true);
    assert.equal(result.artifactCount, 1);
    assert.equal(output.artifacts[0].sha256, hash("signed msix fixture"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows signing report validator rejects mismatched artifact hashes", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-signing-report-hash-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.msi");
    const reportPath = path.join(dir, "signing-report.json");
    writeFileSync(artifactPath, "real artifact bytes");
    const report = validReport(artifactPath);
    report.artifacts[0].type = "msi";
    report.artifacts[0].sha256 = hex("b", 64);
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator(["--report", reportPath]), /sha256 does not match/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows signing report validator rejects leaked signing secrets", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-signing-report-secret-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.msix");
    const reportPath = path.join(dir, "signing-report.json");
    writeFileSync(artifactPath, "signed msix fixture");
    const report = validReport(artifactPath);
    report.pfxPassword = "super-secret-password";
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    assert.throws(() => runValidator(["--report", reportPath]), /signing secrets|private key/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
