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
const clientId = "sentinel-client";
const keyId = "preflight-key";

const base64urlJson = (value) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
const signJwt = ({ issuer, privateKey, claims = {} }) => {
  const header = { alg: "RS256", typ: "JWT", kid: keyId };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    aud: clientId,
    sub: "subject-123",
    email: "ada@defence.local",
    exp: now + 300,
    groups: ["Sentinel Vault Admins"],
    amr: ["pwd", "mfa"],
    ...claims
  };
  const signingInput = `${base64urlJson(header)}.${base64urlJson(payload)}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
};

const startFixture = async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = keyId;
  jwk.alg = "RS256";
  jwk.use = "sig";

  const server = http.createServer((req, res) => {
    const issuer = `http://127.0.0.1:${server.address().port}`;
    res.setHeader("Content-Type", "application/json");
    if (req.url === "/.well-known/openid-configuration") {
      res.end(JSON.stringify({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"]
      }));
      return;
    }
    if (req.url === "/jwks") {
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  });
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return { server, privateKey };
};

const runPreflight = (issuer, idToken, outputPath) => execFileAsync(process.execPath, [
  "scripts/preflight-identity-provider.mjs",
  "--issuer", issuer,
  "--client-id", clientId,
  "--id-token", idToken,
  "--out", outputPath
], {
  cwd: rootDir,
  encoding: "utf8",
  windowsHide: true
});

test("identity provider preflight validates discovery, JWKS, and token claims", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-identity-preflight-"));
  const { server, privateKey } = await startFixture();
  try {
    const issuer = `http://127.0.0.1:${server.address().port}`;
    const idToken = signJwt({ issuer, privateKey });
    const evidencePath = path.join(dir, "identity-preflight.json");
    await runPreflight(issuer, idToken, evidencePath);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

    assert.equal(evidence.format, "sentinel-identity-provider-preflight-v1");
    assert.equal(evidence.checks.discoveryReachable, true);
    assert.equal(evidence.checks.jwksReachable, true);
    assert.equal(evidence.checks.idTokenValidated, true);
    assert.equal(evidence.token.checks.signatureValid, true);
    assert.equal(evidence.token.checks.mfaClaimPresent, true);
    assert.equal(evidence.token.claims.audienceHashes.length, 1);
    assert.equal(Object.hasOwn(evidence.token.claims, "audience"), false);
    assert.equal(JSON.stringify(evidence).includes(idToken), false);
    assert.equal(JSON.stringify(evidence).includes(clientId), false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("identity provider preflight rejects tokens without required MFA", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-identity-preflight-fail-"));
  const { server, privateKey } = await startFixture();
  try {
    const issuer = `http://127.0.0.1:${server.address().port}`;
    const idToken = signJwt({ issuer, privateKey, claims: { amr: ["pwd"] } });
    const evidencePath = path.join(dir, "identity-preflight.json");

    await assert.rejects(() => runPreflight(issuer, idToken, evidencePath), /idTokenValidated/);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.token.checks.mfaClaimPresent, false);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});
