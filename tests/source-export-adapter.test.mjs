import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runAdapter = (sourcePath, format, outPath, evidencePath) => execFileSync(process.execPath, [
  "scripts/convert-source-export.mjs",
  "--source", sourcePath,
  "--format", format,
  "--vault-id", "v-import",
  "--out", outPath,
  "--evidence", evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("bitwarden csv export converts to Sentinel import csv with redacted evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-bitwarden-export-"));
  try {
    const sourcePath = path.join(dir, "bitwarden.csv");
    const outPath = path.join(dir, "normalized.csv");
    const evidencePath = path.join(dir, "evidence.json");
    writeFileSync(sourcePath, [
      "folder,favorite,type,name,notes,login_uri,login_username,login_password",
      "Ops,1,login,Router Admin,\"shared admin\",https://router.local,admin,S3cret!Value"
    ].join("\n"));

    runAdapter(sourcePath, "bitwarden-csv", outPath, evidencePath);
    const csv = readFileSync(outPath, "utf8");
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

    assert.match(csv, /^vaultId,type,name,username,password,url,tags,risk,notes/m);
    assert.match(csv, /v-import,login,Router Admin,admin,S3cret!Value,https:\/\/router.local,Ops;favorite,medium,shared admin/);
    assert.equal(evidence.sourceFormat, "bitwarden-csv");
    assert.equal(evidence.convertedCount, 1);
    assert.equal(evidence.passwordValuesIncluded, false);
    assert.equal(JSON.stringify(evidence).includes("S3cret!Value"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("onepassword csv export converts to Sentinel import csv", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-onepassword-export-"));
  try {
    const sourcePath = path.join(dir, "onepassword.csv");
    const outPath = path.join(dir, "normalized.csv");
    const evidencePath = path.join(dir, "evidence.json");
    writeFileSync(sourcePath, [
      "title,website,username,password,notes,tags,vault",
      "Build Registry,https://registry.local,robot,BuildSecret!,CI token,devops,Engineering"
    ].join("\n"));

    runAdapter(sourcePath, "onepassword-csv", outPath, evidencePath);
    const csv = readFileSync(outPath, "utf8");
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

    assert.match(csv, /v-import,password,Build Registry,robot,BuildSecret!,https:\/\/registry.local,devops;Engineering,medium,CI token/);
    assert.equal(evidence.sourceFormat, "onepassword-csv");
    assert.equal(evidence.entries[0].tags.includes("Engineering"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dashlane csv credentials export converts to Sentinel import csv with redacted evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-dashlane-export-"));
  try {
    const sourcePath = path.join(dir, "credentials.csv");
    const outPath = path.join(dir, "normalized.csv");
    const evidencePath = path.join(dir, "evidence.json");
    writeFileSync(sourcePath, [
      "name,url,username,password,note,category,collections,otpSecret",
      "Finance Portal,https://finance.example.test,ada,Dashlane-Secret-Value,\"Quarterly close login\",Finance,Executive,otpauth-secret-value"
    ].join("\n"));

    runAdapter(sourcePath, "dashlane-csv", outPath, evidencePath);
    const csv = readFileSync(outPath, "utf8");
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

    assert.match(csv, /v-import,password,Finance Portal,ada,Dashlane-Secret-Value,https:\/\/finance.example.test,Executive;Finance,medium,Quarterly close login/);
    assert.equal(evidence.sourceFormat, "dashlane-csv");
    assert.equal(evidence.convertedCount, 1);
    assert.equal(evidence.passwordValuesIncluded, false);
    assert.equal(JSON.stringify(evidence).includes("Dashlane-Secret-Value"), false);
    assert.equal(JSON.stringify(evidence).includes("otpauth-secret-value"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("lastpass csv export converts to Sentinel import csv with redacted evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-lastpass-export-"));
  try {
    const sourcePath = path.join(dir, "lastpass.csv");
    const outPath = path.join(dir, "normalized.csv");
    const evidencePath = path.join(dir, "evidence.json");
    writeFileSync(sourcePath, [
      "url,username,password,extra,name,grouping,fav",
      "https://vpn.example.test,ada,VPN-Secret-Value,\"VPN admin note\",VPN Admin,Infrastructure\\Network,1"
    ].join("\n"));

    runAdapter(sourcePath, "lastpass-csv", outPath, evidencePath);
    const csv = readFileSync(outPath, "utf8");
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

    assert.match(csv, /v-import,password,VPN Admin,ada,VPN-Secret-Value,https:\/\/vpn.example.test,Infrastructure\\Network;favorite,medium,VPN admin note/);
    assert.equal(evidence.sourceFormat, "lastpass-csv");
    assert.equal(evidence.convertedCount, 1);
    assert.equal(evidence.passwordValuesIncluded, false);
    assert.equal(JSON.stringify(evidence).includes("VPN-Secret-Value"), false);
    assert.equal(evidence.entries[0].tags.includes("favorite"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("source export adapter rejects rows missing required fields", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-source-export-fail-"));
  try {
    const sourcePath = path.join(dir, "bad.csv");
    const outPath = path.join(dir, "normalized.csv");
    const evidencePath = path.join(dir, "evidence.json");
    writeFileSync(sourcePath, "name,username,password\nMissing Password,svc,\n");

    assert.throws(() => runAdapter(sourcePath, "sentinel-csv", outPath, evidencePath), /missing password/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
