import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
for (let index = 0; index < cliArgs.length; index += 1) {
  const arg = cliArgs[index];
  if (arg.startsWith("--")) {
    const next = cliArgs[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(arg, true);
    } else {
      args.set(arg, next);
      index += 1;
    }
  }
}

const artifactPaths = cliArgs.flatMap((arg, index) => (arg === "--artifact" ? [cliArgs[index + 1]] : [])).filter(Boolean);
const outPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const requireSignature = args.has("--require-signature");
const allowedArtifactTypes = new Set(["companion-exe", "native-messaging-host", "credential-provider-dll", "installer", "script"]);
const signedNativeArtifact = /\.(exe|dll|msi|msix)$/i;

assert.ok(artifactPaths.length > 0, "At least one --artifact path is required");

const artifactType = (artifactPath) => {
  const name = path.basename(artifactPath).toLowerCase();
  if (name.endsWith(".dll")) return "credential-provider-dll";
  if (name.endsWith(".msi") || name.endsWith(".msix")) return "installer";
  if (name.endsWith(".json")) return "native-messaging-host";
  if (name.endsWith(".ps1")) return "script";
  return "companion-exe";
};

const authenticode = (artifactPath) => {
  if (process.platform !== "win32" || !signedNativeArtifact.test(artifactPath)) {
    return { status: "not-applicable", signerThumbprint: null, subject: null };
  }

  try {
    const output = execFileSync("powershell", [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      "$signature = Get-AuthenticodeSignature -LiteralPath $args[0]; [pscustomobject]@{ Status = [string]$signature.Status; SignerThumbprint = $signature.SignerCertificate.Thumbprint; Subject = $signature.SignerCertificate.Subject } | ConvertTo-Json -Compress",
      artifactPath
    ], { encoding: "utf8", windowsHide: true });
    const parsed = JSON.parse(output);
    return {
      status: parsed.Status || "Unknown",
      signerThumbprint: parsed.SignerThumbprint || null,
      subject: parsed.Subject || null
    };
  } catch (error) {
    return {
      status: "signature-check-error",
      signerThumbprint: null,
      subject: null,
      error: String(error.stderr || error.message || error)
    };
  }
};

const artifacts = artifactPaths.map((artifactPath) => {
  const resolvedPath = path.resolve(artifactPath);
  assert.ok(existsSync(resolvedPath), `Native release artifact not found: ${resolvedPath}`);
  const stats = statSync(resolvedPath);
  assert.ok(stats.isFile(), `Native release artifact must be a file: ${resolvedPath}`);
  const type = artifactType(resolvedPath);
  assert.ok(allowedArtifactTypes.has(type), `Unsupported native release artifact type: ${type}`);
  const signature = authenticode(resolvedPath);
  if (requireSignature && signedNativeArtifact.test(resolvedPath)) {
    assert.equal(signature.status, "Valid", `${path.basename(resolvedPath)} must have a valid Authenticode signature`);
  }

  return {
    name: path.basename(resolvedPath),
    type,
    path: resolvedPath,
    size: stats.size,
    sha256: crypto.createHash("sha256").update(readFileSync(resolvedPath)).digest("hex"),
    authenticodeStatus: signature.status,
    signerThumbprint: signature.signerThumbprint,
    signerSubject: signature.subject
  };
});

const result = {
  format: "sentinel-native-release-artifact-validation-v1",
  requireSignature,
  artifactCount: artifacts.length,
  signedArtifactCount: artifacts.filter((artifact) => artifact.authenticodeStatus === "Valid").length,
  artifacts,
  validated: true
};

const json = JSON.stringify(result, null, 2);
if (outPath) {
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, json, { encoding: "utf8" });
}
console.log(json);
