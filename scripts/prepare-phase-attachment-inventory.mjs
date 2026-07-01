import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const intakePath = path.resolve(args.get("--intake") || path.join(evidenceDir, "phase-evidence-intake.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-attachment-inventory.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join(evidenceDir, "phase-attachment-inventory.md"));

const secretRules = [
  { name: "private-key-block", pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "aws-access-key-id", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "github-token", pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/ },
  { name: "slack-token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  { name: "sentinel-service-token", pattern: /\bsvt_[A-Za-z0-9_-]{20,}\b/ },
  { name: "generic-secret-assignment", pattern: /\b(api[_-]?key|secret|token|password|private[_-]?key)\b\s*[:=]\s*["']([^"']{12,})["']/i }
];

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const isBinary = (buffer) => buffer.includes(0);
const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex"),
    buffer
  };
};

const scanAttachment = (filePath, buffer) => {
  if (buffer.byteLength > 2_000_000 || isBinary(buffer)) {
    return [];
  }

  const findings = [];
  const lines = buffer.toString("utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    for (const rule of secretRules) {
      if (rule.pattern.test(line)) {
        findings.push({
          rule: rule.name,
          lineNumber: index + 1
        });
      }
    }
  });
  return findings;
};

assert.ok(existsSync(intakePath), `Phase evidence intake not found: ${intakePath}`);
const intake = readJson(intakePath);
assert.equal(intake.format, "sentinel-phase-evidence-intake-v1");

const attachments = intake.intakeItems.map((item) => {
  const files = item.expectedFiles.map((expectedFile) => {
    const resolvedPath = path.resolve(evidenceDir, expectedFile.targetPath);
    if (!existsSync(resolvedPath)) {
      return {
        templatePath: expectedFile.templatePath,
        targetPath: expectedFile.targetPath,
        resolvedPath,
        status: "missing",
        bytes: 0,
        sha256: null,
        redactionFindings: []
      };
    }

    const hashed = hashFile(resolvedPath);
    const redactionFindings = scanAttachment(resolvedPath, hashed.buffer);
    return {
      templatePath: expectedFile.templatePath,
      targetPath: expectedFile.targetPath,
      resolvedPath,
      status: redactionFindings.length > 0 ? "redaction-review-required" : "attached",
      bytes: hashed.bytes,
      sha256: hashed.sha256,
      redactionFindings
    };
  });

  return {
    id: item.id,
    phase: item.phase,
    title: item.title,
    ownerRole: item.ownerRole,
    blockerType: item.blockerType,
    intakeDir: item.intakeDir,
    expectedFileCount: files.length,
    attachedFileCount: files.filter((file) => file.status !== "missing").length,
    missingFileCount: files.filter((file) => file.status === "missing").length,
    redactionFindingCount: files.reduce((total, file) => total + file.redactionFindings.length, 0),
    files
  };
});

const inventory = {
  format: "sentinel-phase-attachment-inventory-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  intakePath,
  environment: intake.environment,
  owner: intake.owner,
  summary: {
    intakeCount: attachments.length,
    expectedFileCount: attachments.reduce((total, item) => total + item.expectedFileCount, 0),
    attachedFileCount: attachments.reduce((total, item) => total + item.attachedFileCount, 0),
    missingFileCount: attachments.reduce((total, item) => total + item.missingFileCount, 0),
    redactionFindingCount: attachments.reduce((total, item) => total + item.redactionFindingCount, 0)
  },
  attachments
};

const renderMarkdown = () => `# Sentinel Vault Phase Attachment Inventory

Environment: ${inventory.environment}
Owner: ${inventory.owner}
Generated: ${inventory.generatedAt}

Summary:
- Intake items: ${inventory.summary.intakeCount}
- Expected files: ${inventory.summary.expectedFileCount}
- Attached files: ${inventory.summary.attachedFileCount}
- Missing files: ${inventory.summary.missingFileCount}
- Redaction findings: ${inventory.summary.redactionFindingCount}

${attachments.map((item) => `## ${item.id}: ${item.phase} - ${item.title}

Owner role: ${item.ownerRole}
Attached files: ${item.attachedFileCount}
Missing files: ${item.missingFileCount}
Redaction findings: ${item.redactionFindingCount}

Files:
${item.files.map((file) => `- ${file.status}: \`${file.targetPath}\`${file.sha256 ? ` (${file.sha256})` : ""}`).join("\n")}`).join("\n\n")}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(inventory, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-phase-attachment-inventory-result-v1",
  outputPath,
  markdownPath,
  expectedFileCount: inventory.summary.expectedFileCount,
  attachedFileCount: inventory.summary.attachedFileCount,
  missingFileCount: inventory.summary.missingFileCount,
  redactionFindingCount: inventory.summary.redactionFindingCount
}, null, 2));
