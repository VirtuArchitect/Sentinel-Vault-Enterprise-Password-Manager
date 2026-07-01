import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-identity-provider-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-identity-provider-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const writePreflight = (filePath, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    format: "sentinel-identity-provider-preflight-v1",
    checkedAt: "2026-07-01T10:00:00Z",
    issuer: "https://login.microsoftonline.com/sentinel-tenant/v2.0",
    discovery: {
      jwksUriHost: "login.microsoftonline.com"
    },
    checks: {
      discoveryReachable: true,
      issuerMatchesDiscovery: true,
      jwksReachable: true,
      rs256KeyAvailable: true
    },
    token: {
      checks: {
        audienceIncludesClient: true,
        signatureValid: true,
        algRs256: true,
        signingKeyFound: true,
        expiryValid: true,
        notBeforeValid: true,
        mfaClaimPresent: true,
        roleMappingPresent: true
      }
    },
    ...extra
  }, null, 2));
};

test("identity provider generator creates planned evidence from preflight", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-identity-generator-"));
  try {
    const preflightPath = path.join(dir, "identity-provider-preflight.json");
    const evidencePath = path.join(dir, "identity-provider-evidence.json");
    writePreflight(preflightPath);

    assert.match(runGenerator([
      "--preflight", preflightPath,
      "--environment", "lab",
      "--client-id", "sentinel-client",
      "--out", evidencePath
    ]), /Identity provider evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.tenantId, "sentinel-tenant");
    assert.equal(evidence.checks.signatureValidation, "passed");
    assert.equal(evidence.checks.logoutRevocation, "planned");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("identity provider generator reflects failed token checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-identity-failed-generator-"));
  try {
    const preflightPath = path.join(dir, "identity-provider-preflight.json");
    const evidencePath = path.join(dir, "identity-provider-evidence.json");
    writePreflight(preflightPath, { token: { checks: { audienceIncludesClient: false } } });

    runGenerator([
      "--preflight", preflightPath,
      "--client-id", "sentinel-client",
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.checks.audienceValidation, "failed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("identity provider generator creates production evidence with approvals", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-identity-production-generator-"));
  try {
    const preflightPath = path.join(dir, "identity-provider-preflight.json");
    const evidencePath = path.join(dir, "identity-provider-evidence.json");
    writePreflight(preflightPath);

    runGenerator([
      "--status", "production",
      "--preflight", preflightPath,
      "--environment", "prod",
      "--client-id", "sentinel-client",
      "--jwks-uri", "https://login.microsoftonline.com/sentinel-tenant/discovery/v2.0/keys",
      "--logout-revocation", "passed",
      "--rollback-tested", "true",
      "--identity-owner", "Identity Owner",
      "--security-reviewer", "Security Reviewer",
      "--change-ticket", "CHG-97001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
