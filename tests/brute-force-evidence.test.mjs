import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-brute-force-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "brute-force-evidence.json"), "utf8"));

const productionEvidence = () => {
  const evidence = template();
  evidence.status = "production";
  evidence.environment = "prod";
  evidence.testedAt = "2026-07-01T10:00:00Z";
  evidence.appControls = {
    failedLoginLimit: 5,
    lockoutMinutes: 15,
    temporaryAccountLockout: "passed",
    sessionInvalidationAfterLogout: "passed",
    mfaClaimRequired: "passed",
    identityProviderPreflight: "passed"
  };
  evidence.networkControls = {
    edgeName: "IIS/WAF edge",
    sourceIpPreserved: "passed",
    trustedProxyConfigured: "passed",
    perIpRateLimit: "passed",
    distributedAttackDetection: "passed",
    geoOrAsnPolicy: "not-applicable",
    wafOrReverseProxyLogging: "passed"
  };
  evidence.drills = {
    singleAccountLockout: "passed",
    singleIpSpray: "passed",
    distributedSpray: "passed",
    validUserAfterLockout: "passed",
    mfaRequiredAfterNewDevice: "passed"
  };
  evidence.samples = {
    failedAttempts: 12,
    distinctSourceIps: 3,
    lockedAccounts: 1,
    alertsGenerated: 2
  };
  evidence.monitoring = {
    siemAlertCreated: "passed",
    ticketOrIncidentCreated: "passed",
    dashboardReviewed: "passed",
    falsePositiveDisposition: "passed"
  };
  evidence.redaction = {
    passwordsFound: false,
    tokensFound: false,
    sourceIpsScopedOrHashed: "passed"
  };
  evidence.approvals = {
    identityOwner: "Identity Owner",
    securityReviewer: "Security Reviewer",
    operationsOwner: "Operations Owner",
    changeTicket: "CHG-90004"
  };
  return evidence;
};

test("brute-force evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "brute-force-evidence.json")), /validated/);
});

test("production brute-force evidence validates controls, drills, and monitoring", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-brute-force-"));
  try {
    const evidencePath = path.join(dir, "brute-force.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production brute-force evidence rejects missing alerts", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-brute-force-alerts-"));
  try {
    const evidence = productionEvidence();
    evidence.samples.alertsGenerated = 0;
    const evidencePath = path.join(dir, "brute-force.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /generated alert/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production brute-force evidence rejects leaked passwords", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-brute-force-password-"));
  try {
    const evidence = productionEvidence();
    evidence.redaction.passwordsFound = true;
    const evidencePath = path.join(dir, "brute-force.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /passwords/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
