import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-native-companion-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "native-companion-evidence.json"), "utf8"));
const hex = (char, length) => char.repeat(length);

const productionEvidence = () => {
  const evidence = template();
  evidence.releaseStatus = "production";
  evidence.releaseVersion = "1.0.0";
  evidence.releaseDate = "2026-07-01";
  evidence.buildHost = "release-host-01";
  evidence.sourceCommit = hex("a", 40);
  evidence.artifacts = [
    {
      name: "SentinelVault.Companion.exe",
      type: "companion-exe",
      sha256: hex("b", 64),
      authenticodeStatus: "Valid",
      signerThumbprint: hex("c", 40)
    },
    {
      name: "SentinelVault.CredentialProvider.dll",
      type: "credential-provider-dll",
      sha256: hex("d", 64),
      authenticodeStatus: "Valid",
      signerThumbprint: hex("e", 40)
    }
  ];
  evidence.nativeMessaging = {
    enabled: true,
    manifestPath: "C:\\Program Files\\Sentinel Vault\\native-messaging\\sentinel-vault.json",
    allowedExtensionIds: ["abcdefghijklmnopabcdefghijklmnop"],
    hostPath: "C:\\Program Files\\Sentinel Vault\\SentinelVault.Companion.exe"
  };
  evidence.credentialProvider = {
    enabled: true,
    clsid: "{12345678-1234-4234-9234-1234567890ab}",
    registrationPath: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{12345678-1234-4234-9234-1234567890ab}",
    allowListedVaultEntriesOnly: true,
    offlineLogonDocumented: true
  };
  evidence.securityControls = Object.fromEntries(Object.keys(evidence.securityControls).map((name) => [name, "passed"]));
  evidence.testResults = Object.fromEntries(Object.keys(evidence.testResults).map((name) => [name, "passed"]));
  evidence.approvals = {
    securityReviewer: "Security Reviewer",
    desktopEngineering: "Desktop Engineering",
    releaseOwner: "Release Owner",
    changeTicket: "CHG-12345"
  };
  evidence.rollback = {
    disableProcedure: "Disable native messaging policy, unregister credential provider, and uninstall companion package.",
    tested: true
  };
  return evidence;
};

test("native companion evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "native-companion-evidence.json")), /validated/);
});

test("production native companion evidence requires signed artifacts and security approvals", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-evidence-"));
  try {
    const evidencePath = path.join(dir, "native-companion.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production native companion evidence rejects unsigned credential provider artifacts", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-evidence-fail-"));
  try {
    const evidence = productionEvidence();
    evidence.artifacts[1].authenticodeStatus = "NotSigned";
    const evidencePath = path.join(dir, "native-companion.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /must have a valid Authenticode signature/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production native companion evidence rejects incomplete security controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-controls-fail-"));
  try {
    const evidence = productionEvidence();
    evidence.securityControls.secureDesktopBlocked = "planned";
    const evidencePath = path.join(dir, "native-companion.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /secureDesktopBlocked must be passed or not-applicable/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
