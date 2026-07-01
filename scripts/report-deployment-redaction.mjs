import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

const rootDir = path.resolve(import.meta.dirname, "..");
const bundlePath = path.resolve(args.get("--bundle") || cliArgs.find((arg) => !arg.startsWith("--")) || "docs/templates/deployment-evidence-bundle.json");
const outputPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const markdownPath = args.get("--markdown-out") ? path.resolve(args.get("--markdown-out")) : null;
const failOnFindings = args.get("--fail-on-findings") === true || args.get("--fail-on-findings") === "true";

const strictRules = [
  { name: "private-key-block", pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "aws-access-key-id", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "github-token", pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/ },
  { name: "slack-token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  { name: "sentinel-service-token", pattern: /\bsvt_[A-Za-z0-9_-]{20,}\b/ }
];

const quotedGenericAssignment =
  /\b(api[_-]?key|secret|token|password|private[_-]?key)\b\s*[:=]\s*["']([^"']{12,})["']/gi;

const envGenericAssignment =
  /^(?:export\s+)?[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*([^"'#\s]{12,})/i;

const placeholderValues = [
  /^change-me/i,
  /^demo/i,
  /^not-configured$/i,
  /^planned$/i,
  /^replace-with/i,
  /^your-/i
];

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const isBinary = (buffer) => buffer.includes(0);
const isPlaceholder = (value) => placeholderValues.some((pattern) => pattern.test(String(value || "").trim()));

const resolveEvidencePath = (candidate) => {
  const bundleRelative = path.resolve(path.dirname(bundlePath), candidate);
  if (existsSync(bundleRelative)) return bundleRelative;
  return path.resolve(rootDir, candidate);
};

const scanLine = (line) => {
  const findings = [];
  for (const rule of strictRules) {
    if (rule.pattern.test(line)) findings.push(rule.name);
  }

  quotedGenericAssignment.lastIndex = 0;
  for (const match of line.matchAll(quotedGenericAssignment)) {
    if (!isPlaceholder(match[2])) findings.push("generic-secret-assignment");
  }

  const envMatch = line.match(envGenericAssignment);
  if (envMatch && !isPlaceholder(envMatch[1])) findings.push("generic-env-secret");

  return findings;
};

const scanEvidence = (name, evidencePath) => {
  if (!existsSync(evidencePath)) {
    return {
      name,
      path: evidencePath,
      exists: false,
      scanned: false,
      skippedReason: "missing",
      findingCount: 0,
      findings: []
    };
  }

  const buffer = readFileSync(evidencePath);
  if (buffer.byteLength > 2_000_000) {
    return {
      name,
      path: evidencePath,
      exists: true,
      scanned: false,
      skippedReason: "file-too-large",
      bytes: buffer.byteLength,
      findingCount: 0,
      findings: []
    };
  }

  if (isBinary(buffer)) {
    return {
      name,
      path: evidencePath,
      exists: true,
      scanned: false,
      skippedReason: "binary-file",
      bytes: buffer.byteLength,
      findingCount: 0,
      findings: []
    };
  }

  const findings = [];
  const lines = buffer.toString("utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    for (const rule of scanLine(line)) {
      findings.push({
        rule,
        lineNumber: index + 1
      });
    }
  });

  return {
    name,
    path: evidencePath,
    exists: true,
    scanned: true,
    skippedReason: null,
    bytes: buffer.byteLength,
    findingCount: findings.length,
    findings
  };
};

assert.ok(existsSync(bundlePath), `Deployment evidence bundle not found: ${bundlePath}`);
const bundle = readJson(bundlePath);
assert.equal(bundle.format, "sentinel-deployment-evidence-bundle-v1");
assert.ok(bundle.evidence && typeof bundle.evidence === "object", "evidence map is required");

const items = Object.entries(bundle.evidence).map(([name, candidate]) => scanEvidence(name, resolveEvidencePath(candidate)));
const summary = {
  total: items.length,
  present: items.filter((item) => item.exists).length,
  missing: items.filter((item) => !item.exists).length,
  scanned: items.filter((item) => item.scanned).length,
  skipped: items.filter((item) => item.exists && !item.scanned).length,
  withFindings: items.filter((item) => item.findingCount > 0).length,
  findingCount: items.reduce((total, item) => total + item.findingCount, 0)
};

const report = {
  format: "sentinel-deployment-redaction-report-v1",
  bundle: bundlePath,
  environment: bundle.environment,
  status: bundle.status,
  owner: bundle.owner,
  generatedAt: new Date().toISOString(),
  readyForRelease: summary.missing === 0 && summary.findingCount === 0,
  summary,
  items
};

const renderMarkdown = () => `# Sentinel Vault Deployment Redaction Report

Environment: ${report.environment}
Owner: ${report.owner}
Generated: ${report.generatedAt}

Summary:
- Evidence items: ${summary.total}
- Present: ${summary.present}
- Missing: ${summary.missing}
- Scanned: ${summary.scanned}
- Redaction findings: ${summary.findingCount}

${items.map((item) => `## ${item.name}

Path: \`${item.path}\`
Status: ${item.exists ? item.scanned ? "scanned" : `skipped (${item.skippedReason})` : "missing"}
Findings: ${item.findingCount}
${item.findings.length > 0 ? item.findings.map((finding) => `- line ${finding.lineNumber}: ${finding.rule}`).join("\n") : ""}`).join("\n\n")}
`;

const text = JSON.stringify(report, null, 2);
if (outputPath) {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, text);
}
if (markdownPath) {
  mkdirSync(path.dirname(markdownPath), { recursive: true });
  writeFileSync(markdownPath, renderMarkdown());
}

console.log(text);

if (failOnFindings && !report.readyForRelease) {
  process.exitCode = 1;
}
