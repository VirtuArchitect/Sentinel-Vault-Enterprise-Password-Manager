import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const createWaiverWorkspace = (dir) => {
  runScript("scripts/prepare-deployment-evidence-workspace.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out-dir", dir
  ]);
  runScript("scripts/generate-external-evidence-requests.mjs", [
    "--environment", "pilot",
    "--owner", "platform-security",
    "--out", path.join(dir, "external-evidence-requests.json"),
    "--markdown-out", path.join(dir, "external-evidence-requests.md")
  ]);
  runScript("scripts/report-deployment-evidence-status.mjs", [
    "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
    "--out", path.join(dir, "deployment-evidence-status.json")
  ]);
  runScript("scripts/report-deployment-redaction.mjs", [
    "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
    "--out", path.join(dir, "deployment-redaction-report.json"),
    "--markdown-out", path.join(dir, "deployment-redaction-report.md"),
    "--fail-on-findings"
  ]);
  runScript("scripts/report-phase-completion-audit.mjs", [
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-completion-audit.json"),
    "--markdown-out", path.join(dir, "phase-completion-audit.md")
  ]);
  runScript("scripts/report-phase-readiness.mjs", [
    "--bundle", path.join(dir, "deployment-evidence-bundle.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-readiness.json"),
    "--markdown-out", path.join(dir, "phase-readiness.md")
  ]);
  runScript("scripts/prepare-phase-handoff-checklist.mjs", [
    "--readiness", path.join(dir, "phase-readiness.json"),
    "--external-requests", path.join(dir, "external-evidence-requests.json"),
    "--out", path.join(dir, "phase-handoff-checklist.md")
  ]);
  runScript("scripts/package-phase-evidence.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-evidence-pack-manifest.json")
  ]);
  runScript("scripts/validate-phase-gate.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-gate-validation.json"),
    "--markdown-out", path.join(dir, "phase-gate-validation.md")
  ]);
  runScript("scripts/prepare-phase-action-register.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-action-register.json"),
    "--markdown-out", path.join(dir, "phase-action-register.md")
  ]);
  runScript("scripts/prepare-phase-gap-matrix.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-gap-matrix.json"),
    "--markdown-out", path.join(dir, "phase-gap-matrix.md")
  ]);
  runScript("scripts/prepare-phase-decision-record.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-decision-record.json"),
    "--markdown-out", path.join(dir, "phase-decision-record.md")
  ]);
  runScript("scripts/prepare-phase-signoff-matrix.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-signoff-matrix.json"),
    "--markdown-out", path.join(dir, "phase-signoff-matrix.md")
  ]);
  runScript("scripts/prepare-phase-evidence-intake.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-evidence-intake.json"),
    "--markdown-out", path.join(dir, "phase-evidence-intake.md")
  ]);
  runScript("scripts/prepare-phase-attachment-inventory.mjs", [
    "--dir", dir,
    "--out", path.join(dir, "phase-attachment-inventory.json"),
    "--markdown-out", path.join(dir, "phase-attachment-inventory.md")
  ]);
};

test("phase waiver register creates proposed waivers for missing attachments", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-waivers-${process.pid}-${Date.now()}`);
  try {
    createWaiverWorkspace(dir);
    const registerPath = path.join(dir, "phase-waiver-register.json");
    const markdownPath = path.join(dir, "phase-waiver-register.md");
    const result = JSON.parse(runScript("scripts/prepare-phase-waiver-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-phase-waiver-register-result-v1");
    assert.equal(result.waiverCount, 22);
    assert.equal(result.proposedCount, 22);

    const register = JSON.parse(readFileSync(registerPath, "utf8"));
    assert.equal(register.format, "sentinel-phase-waiver-register-v1");
    assert.equal(register.summary.missingEvidenceCount, 22);
    assert.ok(register.waivers.every((waiver) => waiver.status === "proposed"));
    assert.ok(register.waivers.some((waiver) => waiver.evidenceKey === "windowsSigning"));
    assert.ok(register.waivers.some((waiver) => waiver.evidenceKeys.includes("windowsRelease")));
    assert.match(readFileSync(markdownPath, "utf8"), /Sentinel Vault Phase Waiver Register/);

    const validation = JSON.parse(runScript("scripts/validate-phase-waiver-register.mjs", [
      "--register", registerPath,
      "--attachments", path.join(dir, "phase-attachment-inventory.json"),
      "--phase-decision", path.join(dir, "phase-decision-record.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-waiver-register-validation-v1");
    assert.equal(validation.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase waiver register validator rejects unapproved release waivers", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-waivers-unapproved-${process.pid}-${Date.now()}`);
  try {
    createWaiverWorkspace(dir);
    const registerPath = path.join(dir, "phase-waiver-register.json");
    runScript("scripts/prepare-phase-waiver-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", path.join(dir, "phase-waiver-register.md")
    ]);

    assert.throws(() => runScript("scripts/validate-phase-waiver-register.mjs", [
      "--register", registerPath,
      "--attachments", path.join(dir, "phase-attachment-inventory.json"),
      "--phase-decision", path.join(dir, "phase-decision-record.json"),
      "--require-approved"
    ]), /must be approved/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase waiver register validator accepts completed approvals", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-waivers-approved-${process.pid}-${Date.now()}`);
  try {
    createWaiverWorkspace(dir);
    const registerPath = path.join(dir, "phase-waiver-register.json");
    runScript("scripts/prepare-phase-waiver-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", path.join(dir, "phase-waiver-register.md")
    ]);
    const register = JSON.parse(readFileSync(registerPath, "utf8"));
    register.waivers = register.waivers.map((waiver, index) => ({
      ...waiver,
      status: "approved",
      expiresAt: "2099-12-31",
      approvalReference: `RISK-${String(index + 1).padStart(3, "0")}`,
      compensatingControl: "Approved temporary control until deployment evidence is attached."
    }));
    register.summary.proposedCount = 0;
    register.summary.approvedCount = register.waivers.length;
    writeFileSync(registerPath, JSON.stringify(register, null, 2));

    const validation = JSON.parse(runScript("scripts/validate-phase-waiver-register.mjs", [
      "--register", registerPath,
      "--attachments", path.join(dir, "phase-attachment-inventory.json"),
      "--phase-decision", path.join(dir, "phase-decision-record.json"),
      "--require-approved"
    ]));
    assert.equal(validation.validated, true);
    assert.equal(validation.approvedCount, 22);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase waiver register validator rejects stale evidence key mappings", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-waivers-key-stale-${process.pid}-${Date.now()}`);
  try {
    createWaiverWorkspace(dir);
    const registerPath = path.join(dir, "phase-waiver-register.json");
    runScript("scripts/prepare-phase-waiver-register.mjs", [
      "--dir", dir,
      "--out", registerPath,
      "--markdown-out", path.join(dir, "phase-waiver-register.md")
    ]);
    const register = JSON.parse(readFileSync(registerPath, "utf8"));
    register.waivers[0].evidenceKey = "changedEvidenceKey";
    writeFileSync(registerPath, JSON.stringify(register, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-waiver-register.mjs", [
      "--register", registerPath,
      "--attachments", path.join(dir, "phase-attachment-inventory.json"),
      "--phase-decision", path.join(dir, "phase-decision-record.json")
    ]), /evidence key mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
