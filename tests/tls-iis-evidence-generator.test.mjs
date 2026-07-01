import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-tls-iis-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-tls-iis-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

const writeReport = (filePath, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    hostname: "sentinel.example.test",
    reviewedAt: "2026-07-01T10:00:00Z",
    iis: {
      siteName: "Sentinel Vault",
      httpsBinding: "passed",
      httpRedirect: "passed",
      arrProxyEnabled: "passed",
      urlRewriteEnabled: "passed",
      apiProxyValidated: "passed",
      staticAssetCachingReviewed: "passed"
    },
    certificate: {
      issuer: "Example Enterprise CA",
      subject: "CN=sentinel.example.test",
      thumbprint: "a".repeat(40),
      notBefore: "2026-06-01",
      notAfter: "2027-06-01",
      autoRenewal: "passed",
      privateKeyAclRestricted: "passed",
      chainTrusted: "passed",
      revocationCheck: "passed"
    },
    headers: {
      hsts: "passed",
      contentSecurityPolicy: "passed",
      xContentTypeOptions: "passed",
      referrerPolicy: "passed",
      frameAncestors: "passed"
    },
    healthChecks: {
      httpsHealthz: "passed",
      loginThroughIis: "passed",
      apiConsoleThroughIis: "passed",
      httpToHttpsRedirect: "passed",
      tlsProtocolReview: "passed"
    },
    ...extra
  }, null, 2));
};

test("tls iis generator summarizes planned review evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tls-iis-generator-"));
  try {
    const reportPath = path.join(dir, "tls-iis-review.json");
    const evidencePath = path.join(dir, "tls-iis.json");
    writeReport(reportPath);

    assert.match(runGenerator([
      "--report", reportPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /TLS\/IIS evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.hostname, "sentinel.example.test");
    assert.equal(evidence.iis.httpsBinding, "passed");
    assert.equal(evidence.certificate.thumbprint, "a".repeat(40));
    assert.equal(evidence.healthChecks.httpsHealthz, "passed");
    assert.equal(evidence.redaction.privateKeysFound, false);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tls iis generator flags private keys and runtime secrets", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tls-iis-leak-generator-"));
  try {
    const reportPath = path.join(dir, "tls-iis-review.json");
    const samplesPath = path.join(dir, "samples.log");
    const evidencePath = path.join(dir, "tls-iis.json");
    writeReport(reportPath);
    writeFileSync(samplesPath, [
      "-----BEGIN ",
      "PRIVATE KEY-----\n",
      "SESSION_SECRET=",
      "sampleRuntimeSecret12345\n",
      "certificatePassword=",
      "sampleCertificatePassword123"
    ].join(""));

    runGenerator([
      "--report", reportPath,
      "--samples", samplesPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.privateKeysFound, true);
    assert.equal(evidence.redaction.certificatePasswordsFound, true);
    assert.equal(evidence.redaction.runtimeSecretsFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tls iis generator creates production evidence with approvals", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tls-iis-production-generator-"));
  try {
    const reportPath = path.join(dir, "tls-iis-review.json");
    const evidencePath = path.join(dir, "tls-iis.json");
    writeReport(reportPath);

    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--report", reportPath,
      "--windows-owner", "Windows Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-owner", "Operations Owner",
      "--change-ticket", "CHG-96002",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
