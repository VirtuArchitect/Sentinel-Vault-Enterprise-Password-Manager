import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const execFileAsync = promisify(execFile);
const revokedToken = "revoked-token-fixture";
const replacementToken = "replacement-token-fixture";
const secretValue = "runtime-value-returned-by-fixture";

const startFixture = async ({ allowReplacement = true } = {}) => {
  const server = http.createServer((req, res) => {
    const base = `http://127.0.0.1:${server.address().port}`;
    const url = new URL(req.url, base);
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/api/devops/secrets/s-allowed") {
      if (req.headers["x-sentinel-service-token"] === replacementToken && allowReplacement) {
        res.end(JSON.stringify({
          id: "s-allowed",
          name: "Allowed runtime secret",
          value: secretValue
        }));
        return;
      }
      res.statusCode = 401;
      res.end(JSON.stringify({ error: "Scoped service token required" }));
      return;
    }
    if (url.pathname === "/api/devops/secrets/s-blocked") {
      res.statusCode = 401;
      res.end(JSON.stringify({ error: "Scoped service token required" }));
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
  "scripts/preflight-devops-token-response.mjs",
  "--base-url", endpoint,
  "--secret-id", "s-allowed",
  "--blocked-secret-id", "s-blocked",
  "--revoked-token", revokedToken,
  "--replacement-token", replacementToken,
  "--out", outputPath
], {
  cwd: rootDir,
  encoding: "utf8",
  windowsHide: true
});

test("devops token response preflight validates revoke and replacement evidence", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-preflight-"));
  const server = await startFixture();
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const evidencePath = path.join(dir, "devops-token-response.json");
    await runPreflight(endpoint, evidencePath);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

    assert.equal(evidence.format, "sentinel-devops-token-response-preflight-v1");
    assert.equal(evidence.checks.revokedTokenRejected, true);
    assert.equal(evidence.checks.replacementTokenAccepted, true);
    assert.equal(evidence.checks.replacementScopeEnforced, true);
    assert.equal(JSON.stringify(evidence).includes(revokedToken), false);
    assert.equal(JSON.stringify(evidence).includes(replacementToken), false);
    assert.equal(JSON.stringify(evidence).includes(secretValue), false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("devops token response preflight rejects failed replacement token", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-preflight-fail-"));
  const server = await startFixture({ allowReplacement: false });
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const evidencePath = path.join(dir, "devops-token-response.json");
    await assert.rejects(() => runPreflight(endpoint, evidencePath), /replacementTokenAccepted/);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.checks.replacementTokenAccepted, false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});
