import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const excludedFiles = new Set([
  "pnpm-lock.yaml",
  "scripts/scan-secrets.mjs"
]);

const excludedPrefixes = [
  ".git/",
  "coverage/",
  "data/",
  "dist/",
  "node_modules/"
];

const strictRules = [
  {
    name: "private-key-block",
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/
  },
  {
    name: "aws-access-key-id",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/
  },
  {
    name: "github-token",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/
  },
  {
    name: "slack-token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/
  },
  {
    name: "sentinel-service-token",
    pattern: /\bsvt_[A-Za-z0-9_-]{20,}\b/
  }
];

const quotedGenericAssignment =
  /\b(api[_-]?key|secret|token|password|private[_-]?key)\b\s*[:=]\s*["']([^"']{12,})["']/gi;

const envGenericAssignment =
  /^(?:export\s+)?[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*([^"'#\s]{12,})/i;

const placeholderValues = [
  /^change-me/i,
  /^correctpassw0rd!$/i,
  /^demo/i,
  /^not-configured$/i,
  /^passw0rd!$/i,
  /^replace-with/i,
  /^sentinel-vault$/i,
  /^your-/i
];

const genericFixturePaths = [
  "src/server/data/seedData.mjs",
  "tests/"
];

function normalizeGitPath(filePath) {
  return filePath.replaceAll("\\", "/");
}

function isExcluded(filePath) {
  const normalized = normalizeGitPath(filePath);
  return (
    excludedFiles.has(normalized) ||
    excludedPrefixes.some((prefix) => normalized.startsWith(prefix))
  );
}

function isBinary(buffer) {
  return buffer.includes(0);
}

function isIntentionalFixture(filePath) {
  const normalized = normalizeGitPath(filePath);
  return genericFixturePaths.some((fixturePath) => normalized.startsWith(fixturePath));
}

function isPlaceholder(value) {
  return placeholderValues.some((pattern) => pattern.test(value));
}

function trackedFiles() {
  const output = execFileSync("git", ["ls-files"], {
    cwd: rootDir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });

  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((filePath) => !isExcluded(filePath));
}

function scanLine(filePath, line, lineNumber) {
  const findings = [];

  for (const rule of strictRules) {
    if (rule.pattern.test(line)) {
      findings.push({ filePath, lineNumber, rule: rule.name });
    }
  }

  if (!isIntentionalFixture(filePath)) {
    quotedGenericAssignment.lastIndex = 0;
    for (const match of line.matchAll(quotedGenericAssignment)) {
      const value = match[2].trim();
      if (!isPlaceholder(value)) {
        findings.push({ filePath, lineNumber, rule: "generic-secret-assignment" });
      }
    }

    const envMatch = line.match(envGenericAssignment);
    if (envMatch) {
      const value = envMatch[1].trim();
      if (!isPlaceholder(value)) {
        findings.push({ filePath, lineNumber, rule: "generic-env-secret" });
      }
    }
  }

  return findings;
}

const findings = [];

for (const filePath of trackedFiles()) {
  const absolutePath = path.join(rootDir, filePath);
  if (!existsSync(absolutePath)) {
    continue;
  }

  const buffer = readFileSync(absolutePath);
  if (buffer.byteLength > 2_000_000 || isBinary(buffer)) {
    continue;
  }

  const lines = buffer.toString("utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    findings.push(...scanLine(filePath, line, index + 1));
  });
}

if (findings.length > 0) {
  console.error("Potential committed secrets detected:");
  for (const finding of findings) {
    console.error(`- ${finding.filePath}:${finding.lineNumber} ${finding.rule}`);
  }
  console.error("Replace secrets with environment variables or add a narrow scanner exception for intentional fixtures.");
  process.exit(1);
}

console.log("Secret scan passed.");
