import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-windows-install-hardening-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "windows-install-hardening-evidence.json"), "utf8"));

const productionEvidence = () => {
  const evidence = template();
  evidence.deploymentStatus = "production";
  evidence.environment = "prod";
  evidence.reviewDate = "2026-07-01";
  evidence.installHost = "sentinel-prod-01";
  evidence.nodeBinding = {
    host: "127.0.0.1",
    port: 5173,
    iisFrontend: true,
    tlsTermination: "IIS site certificate CN=sentinel.example.test"
  };
  evidence.serviceIdentity.leastPrivilegeReview = "passed";
  evidence.filesystemAcls = Object.fromEntries(Object.keys(evidence.filesystemAcls).map((name) => [name, "passed"]));
  evidence.runtimeSecrets = Object.fromEntries(Object.keys(evidence.runtimeSecrets).map((name) => [name, "passed"]));
  evidence.installerChecks = Object.fromEntries(Object.keys(evidence.installerChecks).map((name) => [name, "passed"]));
  evidence.approvals = {
    windowsOwner: "Windows Owner",
    securityReviewer: "Security Reviewer",
    operationsReviewer: "Operations Reviewer",
    changeTicket: "CHG-67890"
  };
  return evidence;
};

test("windows install hardening evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "windows-install-hardening-evidence.json")), /validated/);
});

test("production windows install hardening evidence validates completed controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-hardening-"));
  try {
    const evidencePath = path.join(dir, "windows-install-hardening.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production windows install hardening evidence rejects exposed node binding", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-hardening-fail-"));
  try {
    const evidence = productionEvidence();
    evidence.nodeBinding.host = "0.0.0.0";
    const evidencePath = path.join(dir, "windows-install-hardening.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /Node should bind to localhost/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production windows install hardening evidence rejects incomplete ACL review", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-hardening-acl-fail-"));
  try {
    const evidence = productionEvidence();
    evidence.filesystemAcls.sentinelEnvRestricted = "planned";
    const evidencePath = path.join(dir, "windows-install-hardening.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /sentinelEnvRestricted must pass/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
