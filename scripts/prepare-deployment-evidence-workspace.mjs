import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const rootDir = path.resolve(import.meta.dirname, "..");
const environment = args.get("--environment") || args.get("--env") || "replace-with-environment";
const owner = args.get("--owner") || "replace-with-owner";
const status = args.get("--status") || "planned";
const outputDir = path.resolve(args.get("--out-dir") || path.join("artifacts", "deployment", environment));
const manifestPath = path.resolve(args.get("--manifest") || path.join(outputDir, "deployment-evidence-workspace-manifest.json"));
const bundleTemplatePath = path.join(rootDir, "docs", "templates", "deployment-evidence-bundle.json");
const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);

assert.ok(allowedStatuses.has(status), "status must be planned, pilot, production, or retired");
assert.ok(existsSync(bundleTemplatePath), `Missing deployment evidence bundle template: ${bundleTemplatePath}`);

const evidenceDir = path.join(outputDir, "evidence");
mkdirSync(evidenceDir, { recursive: true });

const templateBundle = JSON.parse(readFileSync(bundleTemplatePath, "utf8"));
const evidence = {};
const checklist = [];
const copiedEvidence = {};

for (const [name, templatePath] of Object.entries(templateBundle.evidence || {})) {
  const sourcePath = path.resolve(rootDir, templatePath);
  assert.ok(existsSync(sourcePath), `Missing evidence template for ${name}: ${sourcePath}`);
  const fileName = path.basename(sourcePath);
  const targetPath = path.join(evidenceDir, fileName);
  copyFileSync(sourcePath, targetPath);
  evidence[name] = path.join("evidence", fileName).replaceAll("\\", "/");
  copiedEvidence[name] = targetPath;
  checklist.push(`- [ ] Replace placeholders and validate \`${evidence[name]}\`.`);
}

const generatedAt = status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const bundle = {
  ...templateBundle,
  environment,
  status,
  owner,
  generatedAt,
  evidence,
  approvals: {
    securityOwner: "replace-with-owner",
    operationsOwner: "replace-with-owner",
    releaseOwner: "replace-with-owner"
  }
};

const bundlePath = path.join(outputDir, "deployment-evidence-bundle.json");
writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));

const readme = `# Sentinel Vault Deployment Evidence Workspace

Environment: ${environment}
Status: ${status}
Owner: ${owner}

Use this workspace for deployment-specific evidence. Keep the repository templates unchanged, replace placeholders in the copied files under \`evidence/\`, then validate the bundle:

\`\`\`powershell
pnpm validate:deployment-evidence -- "${bundlePath}"
\`\`\`

Before marking the bundle \`pilot\` or \`production\`, every referenced evidence file must be deployment-specific, placeholder-free, redacted, approved, and passing its validator.

## Evidence Checklist

${checklist.join("\n")}
`;

writeFileSync(path.join(outputDir, "README.md"), readme);

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    path: path.relative(outputDir, filePath).replaceAll("\\", "/"),
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

const manifest = {
  format: "sentinel-deployment-evidence-workspace-manifest-v1",
  generatedAt: new Date().toISOString(),
  environment,
  status,
  owner,
  outputDir,
  bundle: hashFile(bundlePath),
  readme: hashFile(path.join(outputDir, "README.md")),
  evidence: Object.fromEntries(Object.entries(copiedEvidence).map(([name, filePath]) => [name, hashFile(filePath)]))
};
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

console.log(JSON.stringify({
  format: "sentinel-deployment-evidence-workspace-v1",
  environment,
  status,
  owner,
  outputDir,
  bundlePath,
  manifestPath,
  evidenceCount: Object.keys(evidence).length
}, null, 2));
