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

const startGateway = async (options = {}) => {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${server.address().port}`);
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/status") {
      res.end(JSON.stringify({
        provider: options.provider || "external-kms",
        keyId: url.searchParams.get("keyId"),
        keyVersion: "test-v1",
        keyExportDisabled: options.keyExportDisabled ?? true,
        auditLoggingEnabled: options.auditLoggingEnabled ?? true,
        operations: options.operations || ["sign"]
      }));
      return;
    }
    if (url.pathname === "/sign" && req.method === "POST") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
      });
      req.on("end", () => {
        const body = JSON.parse(raw || "{}");
        res.end(JSON.stringify({
          keyId: body.keyId,
          algorithm: "HMAC-SHA256-PREFLIGHT",
          signature: crypto.createHmac("sha256", "fixture-key").update(`${body.purpose}:${body.value}:${body.nonce}`).digest("base64url")
        }));
      });
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  });
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return server;
};

const runPreflight = (endpoint, outputPath, provider = "external-kms") => execFileAsync(process.execPath, [
  "scripts/preflight-kms-hsm-gateway.mjs",
  "--provider", provider,
  "--endpoint", endpoint,
  "--key-id", "sentinel-test-key",
  "--out", outputPath
], {
  cwd: rootDir,
  encoding: "utf8",
  windowsHide: true
});

test("kms gateway preflight validates status and sign operation", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-kms-preflight-"));
  const server = await startGateway();
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const outputPath = path.join(dir, "preflight.json");
    await runPreflight(endpoint, outputPath);

    const evidence = JSON.parse(readFileSync(outputPath, "utf8"));
    assert.equal(evidence.format, "sentinel-kms-hsm-gateway-preflight-v1");
    assert.equal(evidence.checks.providerMatches, true);
    assert.equal(evidence.checks.keyExportDisabled, true);
    assert.equal(evidence.checks.auditLoggingEnabled, true);
    assert.equal(evidence.checks.signatureReturned, true);
    assert.equal(evidence.signature.algorithm, "HMAC-SHA256-PREFLIGHT");
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("kms gateway preflight rejects exportable keys", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-kms-preflight-fail-"));
  const server = await startGateway({ keyExportDisabled: false });
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const outputPath = path.join(dir, "preflight.json");
    await assert.rejects(() => runPreflight(endpoint, outputPath), /keyExportDisabled/);
    const evidence = JSON.parse(readFileSync(outputPath, "utf8"));
    assert.equal(evidence.checks.keyExportDisabled, false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});
