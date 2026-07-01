import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-tls-iis-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "tls-iis-evidence.json"), "utf8"));

const productionEvidence = () => {
  const evidence = template();
  evidence.status = "production";
  evidence.environment = "prod";
  evidence.hostname = "sentinel.example.test";
  evidence.reviewedAt = "2026-07-01T10:00:00Z";
  evidence.iis = {
    siteName: "Sentinel Vault",
    httpsBinding: "passed",
    httpRedirect: "passed",
    arrProxyEnabled: "passed",
    urlRewriteEnabled: "passed",
    apiProxyValidated: "passed",
    staticAssetCachingReviewed: "passed"
  };
  evidence.certificate = {
    issuer: "Example Enterprise CA",
    subject: "CN=sentinel.example.test",
    thumbprint: "a".repeat(40),
    notBefore: "2026-06-01",
    notAfter: "2027-06-01",
    autoRenewal: "passed",
    privateKeyAclRestricted: "passed",
    chainTrusted: "passed",
    revocationCheck: "passed"
  };
  evidence.headers = Object.fromEntries(Object.keys(evidence.headers).map((name) => [name, "passed"]));
  evidence.healthChecks = Object.fromEntries(Object.keys(evidence.healthChecks).map((name) => [name, "passed"]));
  evidence.redaction = {
    privateKeysFound: false,
    certificatePasswordsFound: false,
    runtimeSecretsFound: false
  };
  evidence.approvals = {
    windowsOwner: "Windows Owner",
    securityReviewer: "Security Reviewer",
    operationsOwner: "Operations Owner",
    changeTicket: "CHG-96001"
  };
  return evidence;
};

test("tls iis evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "tls-iis-evidence.json")), /validated/);
});

test("production tls iis evidence validates certificate, headers, and health checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tls-iis-"));
  try {
    const evidencePath = path.join(dir, "tls-iis.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production tls iis evidence rejects expired certificates", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tls-iis-expired-"));
  try {
    const evidence = productionEvidence();
    evidence.certificate.notAfter = "2026-06-30";
    const evidencePath = path.join(dir, "tls-iis.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /certificate must not be expired/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production tls iis evidence rejects private key leakage", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-tls-iis-key-"));
  try {
    const evidence = productionEvidence();
    evidence.redaction.privateKeysFound = true;
    const evidencePath = path.join(dir, "tls-iis.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /private keys/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
