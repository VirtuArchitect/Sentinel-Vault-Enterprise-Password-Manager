import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const createInventoryWorkspace = (dir) => {
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
};

test("phase attachment inventory reports missing and attached intake files", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-attachments-${process.pid}-${Date.now()}`);
  try {
    createInventoryWorkspace(dir);
    const attachedPath = path.join(dir, "intake", "phase-6-certificate-backed-release", "windows-release-evidence.json");
    mkdirSync(path.dirname(attachedPath), { recursive: true });
    writeFileSync(attachedPath, JSON.stringify({ format: "sample-redacted-evidence", status: "redacted" }, null, 2));

    const inventoryPath = path.join(dir, "phase-attachment-inventory.json");
    const markdownPath = path.join(dir, "phase-attachment-inventory.md");
    const result = JSON.parse(runScript("scripts/prepare-phase-attachment-inventory.mjs", [
      "--dir", dir,
      "--out", inventoryPath,
      "--markdown-out", markdownPath
    ]));

    assert.equal(result.format, "sentinel-phase-attachment-inventory-result-v1");
    assert.equal(result.expectedFileCount, 22);
    assert.equal(result.attachedFileCount, 1);
    assert.equal(result.missingFileCount, 21);
    assert.equal(result.redactionFindingCount, 0);
    assert.ok(result.commandScriptCount > 20);
    assert.equal(result.validatorCommandCount, 21);
    assert.ok(existsSync(inventoryPath));
    assert.ok(existsSync(markdownPath));

    const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
    assert.equal(inventory.format, "sentinel-phase-attachment-inventory-v1");
    assert.ok(inventory.summary.commandScriptCount > 20);
    assert.equal(inventory.summary.validatorCommandCount, 21);
    assert.ok(inventory.summary.commandScripts.includes("validate:windows-signing"));
    assert.ok(inventory.attachments.some((item) => item.attachedFileCount === 1));
    assert.ok(inventory.attachments.some((item) => item.evidenceKeys.includes("windowsSigning")));
    assert.ok(inventory.attachments.some((item) => item.commandScripts.includes("validate:windows-signing")));
    assert.ok(inventory.attachments.some((item) => item.files.some((file) => file.evidenceKey === "windowsRelease")));
    const markdown = readFileSync(markdownPath, "utf8");
    assert.match(markdown, /Sentinel Vault Phase Attachment Inventory/);
    assert.match(markdown, /Command Coverage Summary/);
    assert.match(markdown, /- Command scripts: [2-9][0-9]/);
    assert.match(markdown, /- Validator commands: 21/);
    assert.match(markdown, /- `pnpm validate:windows-signing`/);

    const validation = JSON.parse(runScript("scripts/validate-phase-attachment-inventory.mjs", [
      "--inventory", inventoryPath,
      "--markdown", markdownPath,
      "--intake", path.join(dir, "phase-evidence-intake.json")
    ]));
    assert.equal(validation.format, "sentinel-phase-attachment-inventory-validation-v1");
    assert.equal(validation.validated, true);
    assert.ok(validation.commandScriptCount > 20);
    assert.equal(validation.validatorCommandCount, 21);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase attachment inventory validator rejects changed attachments", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-attachments-stale-${process.pid}-${Date.now()}`);
  try {
    createInventoryWorkspace(dir);
    const attachedPath = path.join(dir, "intake", "phase-6-certificate-backed-release", "windows-release-evidence.json");
    mkdirSync(path.dirname(attachedPath), { recursive: true });
    writeFileSync(attachedPath, JSON.stringify({ format: "sample-redacted-evidence", status: "redacted" }, null, 2));
    const inventoryPath = path.join(dir, "phase-attachment-inventory.json");
    runScript("scripts/prepare-phase-attachment-inventory.mjs", [
      "--dir", dir,
      "--out", inventoryPath,
      "--markdown-out", path.join(dir, "phase-attachment-inventory.md")
    ]);
    writeFileSync(attachedPath, JSON.stringify({ format: "sample-redacted-evidence", status: "changed" }, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-attachment-inventory.mjs", [
      "--inventory", inventoryPath,
      "--intake", path.join(dir, "phase-evidence-intake.json")
    ]), /byte length changed|SHA-256 changed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase attachment inventory validator rejects stale evidence key mappings", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-attachments-key-stale-${process.pid}-${Date.now()}`);
  try {
    createInventoryWorkspace(dir);
    const inventoryPath = path.join(dir, "phase-attachment-inventory.json");
    runScript("scripts/prepare-phase-attachment-inventory.mjs", [
      "--dir", dir,
      "--out", inventoryPath,
      "--markdown-out", path.join(dir, "phase-attachment-inventory.md")
    ]);
    const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
    inventory.attachments[0].evidenceKeys = ["changedEvidenceKey"];
    writeFileSync(inventoryPath, JSON.stringify(inventory, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-attachment-inventory.mjs", [
      "--inventory", inventoryPath,
      "--intake", path.join(dir, "phase-evidence-intake.json")
    ]), /evidence key mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase attachment inventory validator rejects stale markdown command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-attachments-markdown-${process.pid}-${Date.now()}`);
  try {
    createInventoryWorkspace(dir);
    const inventoryPath = path.join(dir, "phase-attachment-inventory.json");
    const markdownPath = path.join(dir, "phase-attachment-inventory.md");
    runScript("scripts/prepare-phase-attachment-inventory.mjs", [
      "--dir", dir,
      "--out", inventoryPath,
      "--markdown-out", markdownPath
    ]);
    const markdown = readFileSync(markdownPath, "utf8").replace(
      "- `pnpm validate:windows-signing`",
      "- `pnpm changed:command`"
    );
    writeFileSync(markdownPath, markdown);

    assert.throws(() => runScript("scripts/validate-phase-attachment-inventory.mjs", [
      "--inventory", inventoryPath,
      "--markdown", markdownPath,
      "--intake", path.join(dir, "phase-evidence-intake.json")
    ]), /markdown missing command script coverage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("phase attachment inventory validator rejects stale command coverage", () => {
  const dir = path.join(tmpdir(), `sentinel-phase-attachments-command-stale-${process.pid}-${Date.now()}`);
  try {
    createInventoryWorkspace(dir);
    const inventoryPath = path.join(dir, "phase-attachment-inventory.json");
    runScript("scripts/prepare-phase-attachment-inventory.mjs", [
      "--dir", dir,
      "--out", inventoryPath,
      "--markdown-out", path.join(dir, "phase-attachment-inventory.md")
    ]);
    const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
    inventory.summary.commandScripts = [];
    inventory.summary.commandScriptCount = 0;
    inventory.summary.validatorCommandCount = 0;
    inventory.attachments[0].commandScripts = ["changed:command"];
    writeFileSync(inventoryPath, JSON.stringify(inventory, null, 2));

    assert.throws(() => runScript("scripts/validate-phase-attachment-inventory.mjs", [
      "--inventory", inventoryPath,
      "--intake", path.join(dir, "phase-evidence-intake.json")
    ]), /command script|validator command/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
