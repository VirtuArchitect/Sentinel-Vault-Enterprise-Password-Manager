import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
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

const intakePath = path.resolve(args.get("--intake") || "artifacts/deployment/pilot/phase-evidence-intake.json");
const markdownPath = args.get("--markdown") ? path.resolve(args.get("--markdown")) : null;
const externalRequestsPath = args.get("--external-requests") ? path.resolve(args.get("--external-requests")) : null;
const gapMatrixPath = args.get("--phase-gaps") ? path.resolve(args.get("--phase-gaps")) : null;
const signoffMatrixPath = args.get("--phase-signoffs") ? path.resolve(args.get("--phase-signoffs")) : null;
const bundleTemplatePath = args.get("--bundle-template") ? path.resolve(args.get("--bundle-template")) : null;

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const slug = (value) => value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const commandScriptsFor = (commands = []) => [...new Set(commands
  .map((command) => command.match(/^pnpm\s+([^\s]+)/)?.[1])
  .filter(Boolean))].sort();

assert.ok(existsSync(intakePath), `Phase evidence intake not found: ${intakePath}`);
const intake = readJson(intakePath);
assert.equal(intake.format, "sentinel-phase-evidence-intake-v1");
assert.ok(!Number.isNaN(Date.parse(intake.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(Array.isArray(intake.intakeItems), "intakeItems must be an array");

const externalRequests = readJson(externalRequestsPath || intake.externalRequestsPath);
const gapMatrix = readJson(gapMatrixPath || intake.gapMatrixPath);
const signoffMatrix = readJson(signoffMatrixPath || intake.signoffMatrixPath);
const bundleTemplate = readJson(bundleTemplatePath || intake.bundleTemplatePath || "docs/templates/deployment-evidence-bundle.json");

assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(gapMatrix.format, "sentinel-phase-gap-matrix-v1");
assert.equal(signoffMatrix.format, "sentinel-phase-signoff-matrix-v1");
assert.equal(bundleTemplate.format, "sentinel-deployment-evidence-bundle-v1");
assert.equal(intake.externalRequestsPath, externalRequestsPath || intake.externalRequestsPath, "external requests path mismatch");
assert.equal(intake.gapMatrixPath, gapMatrixPath || intake.gapMatrixPath, "gap matrix path mismatch");
assert.equal(intake.signoffMatrixPath, signoffMatrixPath || intake.signoffMatrixPath, "signoff matrix path mismatch");
assert.equal(intake.bundleTemplatePath, bundleTemplatePath || intake.bundleTemplatePath, "bundle template path mismatch");
assert.equal(intake.environment, externalRequests.environment, "environment mismatch");
assert.equal(intake.owner, externalRequests.owner, "owner mismatch");
assert.equal(intake.intakeItems.length, externalRequests.requests.length, "intake item count mismatch");

const signoffByOwner = new Map(signoffMatrix.approvals.map((approval) => [approval.ownerRole, approval]));
const evidenceKeyByTemplate = new Map(Object.entries(bundleTemplate.evidence || {}).map(([key, templatePath]) => [templatePath, key]));
assert.equal(intake.summary.intakeCount, intake.intakeItems.length, "summary intake count mismatch");
assert.equal(intake.summary.blockedIntakeCount, intake.intakeItems.filter((item) => item.status !== "ready-for-signoff").length, "summary blocked count mismatch");
assert.equal(intake.summary.expectedFileCount, intake.intakeItems.reduce((total, item) => total + item.expectedFiles.length, 0), "summary expected file count mismatch");
assert.equal(intake.summary.evidenceKeyCount, new Set(intake.intakeItems.flatMap((item) => item.evidenceKeys || [])).size, "summary evidence key count mismatch");
assert.equal(intake.summary.commandCount, intake.intakeItems.reduce((total, item) => total + item.validationCommands.length, 0), "summary command count mismatch");
assert.equal(intake.summary.commandScriptCount, externalRequests.summary.commandScriptCount || 0, "summary command script count mismatch");
assert.equal(intake.summary.validatorCommandCount, gapMatrix.summary.validatorCommandCount || signoffMatrix.summary.validatorCommandCount || 0, "summary validator command count mismatch");
assert.deepEqual(intake.summary.commandScripts, externalRequests.summary.commandScripts || [], "summary command scripts mismatch");
assert.deepEqual(intake.summary.commandScripts, gapMatrix.summary.commandScripts, "gap command scripts mismatch");
assert.deepEqual(intake.summary.commandScripts, signoffMatrix.summary.commandScripts, "signoff command scripts mismatch");

if (markdownPath) {
  assert.ok(existsSync(markdownPath), `Phase evidence intake markdown not found: ${markdownPath}`);
  const markdown = readFileSync(markdownPath, "utf8");
  assert.ok(markdown.includes("## Command Coverage Summary"), "markdown must include command coverage summary");
  assert.ok(markdown.includes(`- Command scripts: ${intake.summary.commandScriptCount}`), "markdown command script count mismatch");
  assert.ok(markdown.includes(`- Validator commands: ${intake.summary.validatorCommandCount}`), "markdown validator command count mismatch");
  for (const script of intake.summary.commandScripts) {
    assert.ok(markdown.includes(`- \`pnpm ${script}\``), `markdown missing command script coverage: ${script}`);
  }
}

intake.intakeItems.forEach((item, index) => {
  const request = externalRequests.requests[index];
  const gap = gapMatrix.phases[index];
  const signoff = signoffByOwner.get(request.ownerRole);
  const expectedIntakeDir = `intake/${slug(`${request.phase}-${request.blockerType}`)}`;

  assert.equal(item.id, `INTAKE-${String(index + 1).padStart(2, "0")}`, `intake ${index + 1} id mismatch`);
  assert.equal(item.phase, request.phase, `intake ${index + 1} phase mismatch`);
  assert.equal(item.title, request.title, `intake ${index + 1} title mismatch`);
  assert.equal(item.ownerRole, request.ownerRole, `intake ${index + 1} owner mismatch`);
  assert.equal(item.blockerType, request.blockerType, `intake ${index + 1} blocker mismatch`);
  assert.equal(item.status, signoff?.status || "blocked-pending-evidence", `intake ${index + 1} status mismatch`);
  assert.equal(item.intakeDir, expectedIntakeDir, `intake ${index + 1} folder mismatch`);
  assert.deepEqual(item.evidenceKeys, request.evidenceKeys || [], `intake ${index + 1} evidence key mismatch`);
  assert.deepEqual(item.validationCommands, request.commands, `intake ${index + 1} command mismatch`);
  assert.deepEqual(item.commandScripts, commandScriptsFor(request.commands), `intake ${index + 1} command script mismatch`);
  assert.deepEqual(item.acceptanceCriteria, request.acceptanceCriteria, `intake ${index + 1} acceptance criteria mismatch`);
  assert.ok(item.redactionChecks.length >= 3, `intake ${index + 1} redaction checks incomplete`);
  assert.equal(item.expectedFiles.length, request.evidenceTemplates.length, `intake ${index + 1} expected file count mismatch`);

  item.expectedFiles.forEach((file, fileIndex) => {
    const templatePath = request.evidenceTemplates[fileIndex];
    const mapping = gap.templateMappings.find((candidate) => candidate.templatePath === templatePath);
    const expectedEvidenceKey = evidenceKeyByTemplate.get(templatePath) || null;
    assert.equal(file.evidenceKey, expectedEvidenceKey, `intake ${index + 1} file ${fileIndex + 1} evidence key mismatch`);
    assert.equal(file.templatePath, templatePath, `intake ${index + 1} file ${fileIndex + 1} template mismatch`);
    assert.equal(file.targetPath, `${expectedIntakeDir}/${path.basename(templatePath)}`, `intake ${index + 1} file ${fileIndex + 1} target mismatch`);
    assert.equal(file.coverage, mapping?.coverage || "supporting-artifact", `intake ${index + 1} file ${fileIndex + 1} coverage mismatch`);
  });
});

console.log(JSON.stringify({
  format: "sentinel-phase-evidence-intake-validation-v1",
  intakePath,
  intakeCount: intake.summary.intakeCount,
  expectedFileCount: intake.summary.expectedFileCount,
  blockedIntakeCount: intake.summary.blockedIntakeCount,
  commandScriptCount: intake.summary.commandScriptCount,
  validatorCommandCount: intake.summary.validatorCommandCount,
  validated: true
}, null, 2));
