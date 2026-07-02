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

const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const externalRequestsPath = path.resolve(args.get("--external-requests") || path.join(evidenceDir, "external-evidence-requests.json"));
const gapMatrixPath = path.resolve(args.get("--phase-gaps") || path.join(evidenceDir, "phase-gap-matrix.json"));
const signoffMatrixPath = path.resolve(args.get("--phase-signoffs") || path.join(evidenceDir, "phase-signoff-matrix.json"));
const bundleTemplatePath = path.resolve(args.get("--bundle-template") || "docs/templates/deployment-evidence-bundle.json");
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-evidence-intake.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join(evidenceDir, "phase-evidence-intake.md"));

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const slug = (value) => value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const commandScriptsFor = (commands = []) => [...new Set(commands
  .map((command) => command.match(/^pnpm\s+([^\s]+)/)?.[1])
  .filter(Boolean))].sort();

assert.ok(existsSync(externalRequestsPath), `External evidence requests not found: ${externalRequestsPath}`);
assert.ok(existsSync(gapMatrixPath), `Phase gap matrix not found: ${gapMatrixPath}`);
assert.ok(existsSync(signoffMatrixPath), `Phase signoff matrix not found: ${signoffMatrixPath}`);
assert.ok(existsSync(bundleTemplatePath), `Deployment evidence bundle template not found: ${bundleTemplatePath}`);

const externalRequests = readJson(externalRequestsPath);
const gapMatrix = readJson(gapMatrixPath);
const signoffMatrix = readJson(signoffMatrixPath);
const bundleTemplate = readJson(bundleTemplatePath);

assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(gapMatrix.format, "sentinel-phase-gap-matrix-v1");
assert.equal(signoffMatrix.format, "sentinel-phase-signoff-matrix-v1");
assert.equal(bundleTemplate.format, "sentinel-deployment-evidence-bundle-v1");
assert.equal(gapMatrix.summary.phaseCount, externalRequests.requests.length, "gap matrix request count mismatch");
assert.equal(signoffMatrix.summary.pendingActionCount, externalRequests.requests.length, "signoff matrix pending action count mismatch");
assert.deepEqual(gapMatrix.summary.commandScripts, externalRequests.summary.commandScripts, "gap matrix command scripts do not match request pack");
assert.deepEqual(signoffMatrix.summary.commandScripts, externalRequests.summary.commandScripts, "signoff matrix command scripts do not match request pack");

const signoffByOwner = new Map(signoffMatrix.approvals.map((approval) => [approval.ownerRole, approval]));
const evidenceKeyByTemplate = new Map(Object.entries(bundleTemplate.evidence || {}).map(([key, templatePath]) => [templatePath, key]));
const intakeItems = externalRequests.requests.map((request, index) => {
  const gap = gapMatrix.phases[index];
  const signoff = signoffByOwner.get(request.ownerRole);
  const phaseSlug = slug(`${request.phase}-${request.blockerType}`);
  const intakeDir = `intake/${phaseSlug}`;
  return {
    id: `INTAKE-${String(index + 1).padStart(2, "0")}`,
    phase: request.phase,
    title: request.title,
    ownerRole: request.ownerRole,
    blockerType: request.blockerType,
    status: signoff?.status || "blocked-pending-evidence",
    intakeDir,
    evidenceKeys: request.evidenceKeys || [],
    expectedFiles: request.evidenceTemplates.map((templatePath) => ({
      evidenceKey: evidenceKeyByTemplate.get(templatePath) || null,
      templatePath,
      targetPath: `${intakeDir}/${path.basename(templatePath)}`,
      coverage: gap.templateMappings.find((mapping) => mapping.templatePath === templatePath)?.coverage || "supporting-artifact"
    })),
    validationCommands: request.commands,
    commandScripts: commandScriptsFor(request.commands),
    acceptanceCriteria: request.acceptanceCriteria,
    redactionChecks: [
      "No plaintext secrets, bearer tokens, private keys, PFX passwords, or root-key material",
      "No customer-only hostnames, ticket contents, usernames, or tenant identifiers unless deployment-scoped",
      "Evidence filenames and metadata match the deployment environment and owner approval"
    ],
    signoffEvidence: signoff?.requiredSignoffEvidence || []
  };
});

const intake = {
  format: "sentinel-phase-evidence-intake-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  externalRequestsPath,
  gapMatrixPath,
  signoffMatrixPath,
  bundleTemplatePath,
  environment: externalRequests.environment,
  owner: externalRequests.owner,
  summary: {
    intakeCount: intakeItems.length,
    blockedIntakeCount: intakeItems.filter((item) => item.status !== "ready-for-signoff").length,
    expectedFileCount: intakeItems.reduce((total, item) => total + item.expectedFiles.length, 0),
    evidenceKeyCount: new Set(intakeItems.flatMap((item) => item.evidenceKeys)).size,
    commandCount: intakeItems.reduce((total, item) => total + item.validationCommands.length, 0),
    commandScriptCount: externalRequests.summary.commandScriptCount || 0,
    validatorCommandCount: gapMatrix.summary.validatorCommandCount || signoffMatrix.summary.validatorCommandCount || 0,
    commandScripts: externalRequests.summary.commandScripts || []
  },
  intakeItems
};

const renderMarkdown = () => `# Sentinel Vault Phase Evidence Intake

Environment: ${intake.environment}
Owner: ${intake.owner}
Generated: ${intake.generatedAt}

Summary:
- Intake items: ${intake.summary.intakeCount}
- Blocked items: ${intake.summary.blockedIntakeCount}
- Expected files: ${intake.summary.expectedFileCount}
- Validation commands: ${intake.summary.commandCount}
- Command scripts: ${intake.summary.commandScriptCount}
- Validator commands: ${intake.summary.validatorCommandCount}

## Command Coverage Summary

- Command scripts: ${intake.summary.commandScriptCount}
- Validator commands: ${intake.summary.validatorCommandCount}

${intake.summary.commandScripts.map((script) => `- \`pnpm ${script}\``).join("\n")}

${intakeItems.map((item) => `## ${item.id}: ${item.phase} - ${item.title}

Owner role: ${item.ownerRole}
Status: ${item.status}
Intake folder: \`${item.intakeDir}\`

Deployment bundle evidence keys:
${item.evidenceKeys.map((key) => `- \`${key}\``).join("\n")}

Expected files:
${item.expectedFiles.map((file) => `- \`${file.targetPath}\` from \`${file.templatePath}\`${file.evidenceKey ? ` for \`${file.evidenceKey}\`` : ""} (${file.coverage})`).join("\n")}

Validation commands:
${item.validationCommands.map((command) => `- \`${command}\``).join("\n")}

Command scripts:
${item.commandScripts.map((script) => `- \`${script}\``).join("\n")}

Redaction checks:
${item.redactionChecks.map((check) => `- [ ] ${check}`).join("\n")}

Acceptance criteria:
${item.acceptanceCriteria.map((criterion) => `- [ ] ${criterion}`).join("\n")}`).join("\n\n")}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(intake, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-phase-evidence-intake-result-v1",
  outputPath,
  markdownPath,
  intakeCount: intake.summary.intakeCount,
  expectedFileCount: intake.summary.expectedFileCount,
  blockedIntakeCount: intake.summary.blockedIntakeCount,
  commandScriptCount: intake.summary.commandScriptCount,
  validatorCommandCount: intake.summary.validatorCommandCount
}, null, 2));
