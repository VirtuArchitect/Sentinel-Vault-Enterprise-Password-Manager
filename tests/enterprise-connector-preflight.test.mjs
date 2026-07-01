import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const execFileAsync = promisify(execFile);
const siemSecret = "preflight-secret";

const startFixture = async ({ closedTicket = false, state = "open", changeWindow = null } = {}) => {
  const server = http.createServer((req, res) => {
    const base = `http://127.0.0.1:${server.address().port}`;
    const url = new URL(req.url, base);
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/siem" && req.method === "POST") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
      });
      req.on("end", () => {
        const signature = req.headers["x-sentinel-signature"];
        const timestamp = req.headers["x-sentinel-timestamp"];
        const nonce = req.headers["x-sentinel-nonce"];
        const expected = `sha256=${crypto.createHmac("sha256", siemSecret).update(`${timestamp}.${nonce}.${raw}`, "utf8").digest("hex")}`;
        if (signature !== expected) {
          res.statusCode = 401;
          res.end(JSON.stringify({ accepted: false }));
          return;
        }
        res.end(JSON.stringify({
          accepted: true,
          deliveryId: req.headers["x-sentinel-delivery-id"],
          replayStored: true,
          schemaValidated: true
        }));
      });
      return;
    }
    if (url.pathname.startsWith("/tickets/")) {
      res.end(JSON.stringify({
        state: closedTicket ? "closed" : state,
        active: !closedTicket,
        requester: "ada@defence.local",
        assignmentGroup: "Security Operations",
        changeWindow
      }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  });
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return server;
};

const runPreflight = (endpoint, outputPath) => execFileAsync(process.execPath, [
  "scripts/preflight-enterprise-connectors.mjs",
  "--siem-url", `${endpoint}/siem`,
  "--siem-secret", siemSecret,
  "--itsm-url", endpoint,
  "--ticket-ref", "INC-12345",
  "--out", outputPath
], {
  cwd: rootDir,
  encoding: "utf8",
  windowsHide: true
});

test("enterprise connector preflight validates SIEM and ITSM receivers", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-preflight-"));
  const server = await startFixture();
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const evidencePath = path.join(dir, "preflight.json");
    await runPreflight(endpoint, evidencePath);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

    assert.equal(evidence.format, "sentinel-enterprise-connector-live-preflight-v1");
    assert.equal(evidence.checks.siemDeliveryAccepted, true);
    assert.equal(evidence.checks.itsmTicketActive, true);
    assert.equal(evidence.checks.itsmTicketStateAllowed, true);
    assert.equal(evidence.checks.itsmChangeWindowActive, true);
    assert.equal(evidence.connectors.siem.signed, true);
    assert.equal(JSON.stringify(evidence).includes(siemSecret), false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("enterprise connector preflight rejects unapproved ITSM states", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-preflight-state-"));
  const server = await startFixture({ state: "awaiting_approval" });
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const evidencePath = path.join(dir, "preflight.json");
    await assert.rejects(() => runPreflight(endpoint, evidencePath), /itsmTicketStateAllowed/);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.checks.itsmTicketStateAllowed, false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("enterprise connector preflight rejects future ITSM change windows", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-preflight-window-"));
  const server = await startFixture({
    state: "scheduled",
    changeWindow: {
      start: new Date(Date.now() + 3600000).toISOString(),
      end: new Date(Date.now() + 7200000).toISOString()
    }
  });
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const evidencePath = path.join(dir, "preflight.json");
    await assert.rejects(() => runPreflight(endpoint, evidencePath), /itsmChangeWindowActive/);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.checks.itsmChangeWindowActive, false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("enterprise connector preflight rejects inactive ITSM tickets", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-preflight-fail-"));
  const server = await startFixture({ closedTicket: true });
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const evidencePath = path.join(dir, "preflight.json");
    await assert.rejects(() => runPreflight(endpoint, evidencePath), /itsmTicketActive/);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.checks.itsmTicketActive, false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});
