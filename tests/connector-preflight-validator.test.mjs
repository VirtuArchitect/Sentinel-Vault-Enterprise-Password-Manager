import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-connector-preflight.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const validPreflight = () => ({
  format: "sentinel-enterprise-connector-live-preflight-v1",
  checkedAt: "2026-07-03T10:00:00.000Z",
  connectors: {
    siem: {
      endpointHost: "siem.example.test",
      status: 200,
      ok: true,
      deliveryId: "11111111-2222-4333-8444-555555555555",
      signed: true,
      replayWindowSeconds: 300,
      requestBodySha256: "a".repeat(43),
      receiver: {
        accepted: true,
        deliveryId: "11111111-2222-4333-8444-555555555555",
        replayStored: true,
        schemaValidated: true
      }
    },
    itsm: {
      endpointHost: "itsm.example.test",
      ticketRef: "INC-12345",
      status: 200,
      ok: true,
      active: true,
      stateAllowed: true,
      state: "approved",
      allowedStates: ["open", "approved", "scheduled"],
      changeWindow: {
        start: "2026-07-03T09:00:00.000Z",
        end: "2099-07-03T11:00:00.000Z",
        valid: true,
        started: true,
        notExpired: true
      },
      requesterHash: "requester-hash",
      assignmentGroupHash: "assignment-hash"
    }
  },
  checks: {
    siemDeliveryAccepted: true,
    siemReplayEvidencePresent: true,
    itsmTicketLookupPassed: true,
    itsmTicketActive: true,
    itsmTicketStateAllowed: true,
    itsmChangeWindowActive: true,
    redactedOutput: true
  }
});

test("connector preflight validator accepts signed SIEM and active ITSM evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-preflight-validator-"));
  try {
    const evidencePath = path.join(dir, "connector-live-preflight.json");
    writeFileSync(evidencePath, JSON.stringify(validPreflight(), null, 2));

    const result = JSON.parse(runValidator([
      "--preflight", evidencePath,
      "--require-siem",
      "--require-itsm"
    ]));

    assert.equal(result.format, "sentinel-connector-preflight-validation-v1");
    assert.equal(result.hasSiem, true);
    assert.equal(result.hasItsm, true);
    assert.equal(result.checkCount, 7);
    assert.equal(result.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("connector preflight validator rejects failed connector checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-preflight-validator-fail-"));
  try {
    const evidencePath = path.join(dir, "connector-live-preflight.json");
    const evidence = validPreflight();
    evidence.checks.itsmTicketStateAllowed = false;
    evidence.connectors.itsm.stateAllowed = false;
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(["--preflight", evidencePath]), /checks\.itsmTicketStateAllowed must pass/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("connector preflight validator rejects leaked secret markers", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-preflight-validator-leak-"));
  try {
    const evidencePath = path.join(dir, "connector-live-preflight.json");
    const evidence = validPreflight();
    evidence.connectors.siem.debug = "preflight-secret";
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(["--preflight", evidencePath]), /secret material/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
