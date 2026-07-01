import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const writeReport = (reportPath, overrides = {}) => {
  const report = {
    environment: "production",
    system: "ServiceNow",
    ticketRef: "CHG-12345",
    workNotes: [
      { action: "access_requested", workNoteId: "wn-1", createdAt: "2026-07-01T10:00:00Z", redacted: true, ticketRef: "CHG-12345", body: "redacted request note" },
      { action: "access_approved", workNoteId: "wn-2", createdAt: "2026-07-01T10:05:00Z", redacted: true, ticketRef: "CHG-12345", body: "redacted approval note" },
      { action: "access_denied", workNoteId: "wn-3", createdAt: "2026-07-01T10:10:00Z", redacted: true, ticketRef: "CHG-12345", body: "redacted denial note" },
      { action: "access_revoked", workNoteId: "wn-4", createdAt: "2026-07-01T10:15:00Z", redacted: true, ticketRef: "CHG-12345", body: "redacted revocation note" }
    ],
    ...overrides
  };
  writeFileSync(reportPath, JSON.stringify(report, null, 2));
};

test("ITSM work-note evidence template validates in planned mode", () => {
  const output = runScript("scripts/validate-itsm-worknote-evidence.mjs", [
    "docs/templates/itsm-worknote-evidence.json"
  ]);

  assert.match(output, /ITSM work-note evidence validated/);
});

test("ITSM work-note generator creates production evidence without raw note text", () => {
  const dir = path.join(tmpdir(), `sentinel-itsm-worknotes-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(dir, { recursive: true });
    const reportPath = path.join(dir, "worknotes.json");
    const evidencePath = path.join(dir, "itsm-worknote-evidence.json");
    writeReport(reportPath);

    const result = JSON.parse(runScript("scripts/generate-itsm-worknote-evidence.mjs", [
      "--status", "production",
      "--report", reportPath,
      "--ticket-ref", "CHG-12345",
      "--integration-owner", "Integrations",
      "--security-reviewer", "Security",
      "--operations-owner", "Operations",
      "--change-ticket", "CHG-12345",
      "--out", evidencePath
    ]));

    assert.equal(result.format, "sentinel-itsm-worknote-evidence-result-v1");
    assert.equal(result.workNoteCount, 4);

    const evidenceText = readFileSync(evidencePath, "utf8");
    assert.equal(evidenceText.includes("redacted request note"), false);

    const validation = runScript("scripts/validate-itsm-worknote-evidence.mjs", [evidencePath]);
    assert.match(validation, /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ITSM work-note validator rejects unredacted deployed notes", () => {
  const dir = path.join(tmpdir(), `sentinel-itsm-worknotes-unredacted-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(dir, { recursive: true });
    const reportPath = path.join(dir, "worknotes.json");
    const evidencePath = path.join(dir, "itsm-worknote-evidence.json");
    writeReport(reportPath, {
      workNotes: [
        { action: "access_requested", workNoteId: "wn-1", createdAt: "2026-07-01T10:00:00Z", redacted: false, ticketRef: "CHG-12345", body: "request note" },
        { action: "access_approved", workNoteId: "wn-2", createdAt: "2026-07-01T10:05:00Z", redacted: true, ticketRef: "CHG-12345", body: "approval note" },
        { action: "access_denied", workNoteId: "wn-3", createdAt: "2026-07-01T10:10:00Z", redacted: true, ticketRef: "CHG-12345", body: "denial note" },
        { action: "access_revoked", workNoteId: "wn-4", createdAt: "2026-07-01T10:15:00Z", redacted: true, ticketRef: "CHG-12345", body: "revocation note" }
      ]
    });
    runScript("scripts/generate-itsm-worknote-evidence.mjs", [
      "--status", "production",
      "--report", reportPath,
      "--ticket-ref", "CHG-12345",
      "--integration-owner", "Integrations",
      "--security-reviewer", "Security",
      "--operations-owner", "Operations",
      "--change-ticket", "CHG-12345",
      "--out", evidencePath
    ]);

    assert.throws(() => runScript("scripts/validate-itsm-worknote-evidence.mjs", [
      evidencePath
    ]), /must be redacted/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
