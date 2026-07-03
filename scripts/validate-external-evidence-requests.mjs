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

const rootDir = path.resolve(import.meta.dirname, "..");
const requestPath = path.resolve(args.get("--requests") || cliArgs.find((arg) => !arg.startsWith("--")) || "artifacts/deployment/replace-with-environment/external-evidence-requests.json");
const markdownPath = args.get("--markdown") ? path.resolve(args.get("--markdown")) : null;
const bundleTemplatePath = path.resolve(args.get("--bundle-template") || "docs/templates/deployment-evidence-bundle.json");
const packageJsonPath = path.resolve(args.get("--package-json") || "package.json");
const strict = args.has("--strict");
const placeholder = /replace-with|YYYY-MM-DD|TODO|TBD/i;

const requiredRequests = new Map([
  ["Phase 2", "postgres-ha-approval"],
  ["Phase 4", "deployment-evidence"],
  ["Phase 5", "production-connector-evidence"],
  ["Phase 6", "certificate-backed-release"],
  ["Phase 7", "dependency-and-environment-approval"],
  ["Phase 8", "production-extension-identity"],
  ["Phase 8/native", "native-security-approval"]
]);

const requiredValidatorCommands = [
  "pnpm plan:postgres",
  "pnpm validate:storage-migration",
  "pnpm validate:tenant-isolation",
  "pnpm validate:connector-evidence",
  "pnpm validate:siem-rotation",
  "pnpm validate:windows-package",
  "pnpm validate:windows-release",
  "pnpm validate:windows-signing",
  "pnpm validate:kms-hsm-sdk-approval",
  "pnpm validate:kms-hsm-evidence",
  "pnpm validate:browser-identity",
  "pnpm validate:browser-rollout",
  "pnpm validate:credential-provider-approval",
  "pnpm validate:native-companion"
];

const assertArray = (value, name, minLength = 1) => {
  assert.ok(Array.isArray(value), `${name} must be an array`);
  assert.ok(value.length >= minLength, `${name} must include at least ${minLength} item(s)`);
};

const resolveTemplate = (templatePath) => path.resolve(rootDir, templatePath);

assert.ok(existsSync(requestPath), `External evidence request pack not found: ${requestPath}`);
if (markdownPath) {
  assert.ok(existsSync(markdownPath), `External evidence request markdown not found: ${markdownPath}`);
}
assert.ok(existsSync(bundleTemplatePath), `Deployment evidence bundle template not found: ${bundleTemplatePath}`);
assert.ok(existsSync(packageJsonPath), `package.json not found: ${packageJsonPath}`);
const report = JSON.parse(readFileSync(requestPath, "utf8"));
const markdown = markdownPath ? readFileSync(markdownPath, "utf8") : null;
const bundleTemplate = JSON.parse(readFileSync(bundleTemplatePath, "utf8"));
const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
assert.equal(bundleTemplate.format, "sentinel-deployment-evidence-bundle-v1");
assert.ok(bundleTemplate.evidence && typeof bundleTemplate.evidence === "object", "deployment evidence bundle template must include evidence map");
assert.ok(packageJson.scripts && typeof packageJson.scripts === "object", "package.json must include scripts");
const bundleEvidenceKeys = new Set(Object.keys(bundleTemplate.evidence));
const packageScripts = new Set(Object.keys(packageJson.scripts));

assert.equal(report.format, "sentinel-external-evidence-requests-v1");
assert.ok(report.environment && typeof report.environment === "string", "environment is required");
assert.ok(report.owner && typeof report.owner === "string", "owner is required");
assert.ok(!Number.isNaN(Date.parse(report.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assertArray(report.requests, "requests", requiredRequests.size);

if (strict) {
  assert.ok(!placeholder.test(report.environment), "strict mode requires a concrete environment");
  assert.ok(!placeholder.test(report.owner), "strict mode requires a concrete owner");
}

const requestKeys = new Set();
const allCommands = [];
const commandScripts = new Set();
const templatePaths = new Set();
const requestedEvidenceKeys = new Set();

for (const [index, request] of report.requests.entries()) {
  assert.ok(request.phase && typeof request.phase === "string", `requests[${index}].phase is required`);
  assert.ok(request.title && typeof request.title === "string", `requests[${index}].title is required`);
  assert.ok(request.ownerRole && typeof request.ownerRole === "string", `requests[${index}].ownerRole is required`);
  assert.ok(request.blockerType && typeof request.blockerType === "string", `requests[${index}].blockerType is required`);
  assertArray(request.requiredInputs, `requests[${index}].requiredInputs`, 3);
  assertArray(request.evidenceTemplates, `requests[${index}].evidenceTemplates`);
  assertArray(request.evidenceKeys, `requests[${index}].evidenceKeys`);
  assertArray(request.commands, `requests[${index}].commands`, 2);
  assertArray(request.acceptanceCriteria, `requests[${index}].acceptanceCriteria`, 3);

  const requestKey = request.blockerType === "native-security-approval" ? `${request.phase}/native` : request.phase;
  requestKeys.add(requestKey);

  for (const templatePath of request.evidenceTemplates) {
    const absolutePath = resolveTemplate(templatePath);
    assert.ok(existsSync(absolutePath), `evidence template does not exist: ${templatePath}`);
    templatePaths.add(templatePath);
  }

  for (const evidenceKey of request.evidenceKeys) {
    assert.ok(bundleEvidenceKeys.has(evidenceKey), `evidence key is not present in deployment bundle template: ${evidenceKey}`);
    const expectedTemplate = bundleTemplate.evidence[evidenceKey];
    assert.ok(
      request.evidenceTemplates.includes(expectedTemplate),
      `evidence key ${evidenceKey} must reference bundle template path: ${expectedTemplate}`
    );
    requestedEvidenceKeys.add(evidenceKey);
  }

  allCommands.push(...request.commands);
  for (const command of request.commands) {
    const match = command.match(/^pnpm\s+([^\s]+)/);
    assert.ok(match, `request command must start with a pnpm script: ${command}`);
    const scriptName = match[1];
    assert.ok(packageScripts.has(scriptName), `request command references missing package script: ${scriptName}`);
    commandScripts.add(scriptName);
  }
}

const expectedCommandScripts = [...commandScripts].sort();
assert.equal(report.summary.commandScriptCount, expectedCommandScripts.length, "summary command script count mismatch");
assert.deepEqual(report.summary.commandScripts, expectedCommandScripts, "summary command scripts mismatch");

if (markdown) {
  assert.match(markdown, /^# Sentinel Vault External Evidence Requests/m, "markdown title is missing");
  assert.ok(markdown.includes(`Environment: ${report.environment}`), "markdown environment does not match request pack");
  assert.ok(markdown.includes(`Owner: ${report.owner}`), "markdown owner does not match request pack");
  assert.ok(markdown.includes("Command scripts:"), "markdown command script section is missing");

  for (const script of expectedCommandScripts) {
    assert.ok(markdown.includes(`\`pnpm ${script}\``), `markdown is missing command script: ${script}`);
  }

  for (const [index, request] of report.requests.entries()) {
    assert.ok(markdown.includes(`## ${index + 1}. ${request.phase}: ${request.title}`), `markdown is missing request heading: ${request.title}`);
    assert.ok(markdown.includes(`Owner role: ${request.ownerRole}`), `markdown is missing owner role for ${request.title}`);
    assert.ok(markdown.includes(`Blocker type: ${request.blockerType}`), `markdown is missing blocker type for ${request.title}`);

    for (const input of request.requiredInputs) {
      assert.ok(markdown.includes(`- ${input}`), `markdown is missing required input for ${request.title}: ${input}`);
    }
    for (const templatePath of request.evidenceTemplates) {
      assert.ok(markdown.includes(`- \`${templatePath}\``), `markdown is missing evidence template for ${request.title}: ${templatePath}`);
    }
    for (const evidenceKey of request.evidenceKeys) {
      assert.ok(markdown.includes(`- \`${evidenceKey}\``), `markdown is missing evidence key for ${request.title}: ${evidenceKey}`);
    }
    for (const command of request.commands) {
      assert.ok(markdown.includes(`- \`${command}\``), `markdown is missing command for ${request.title}: ${command}`);
    }
    for (const criterion of request.acceptanceCriteria) {
      assert.ok(markdown.includes(`- ${criterion}`), `markdown is missing acceptance criterion for ${request.title}: ${criterion}`);
    }
  }
}

for (const [requestKey, blockerType] of requiredRequests.entries()) {
  assert.ok(requestKeys.has(requestKey), `missing required request: ${requestKey}`);
  assert.ok(report.requests.some((request) => request.blockerType === blockerType), `missing blocker type: ${blockerType}`);
}

for (const command of requiredValidatorCommands) {
  assert.ok(allCommands.some((candidate) => candidate.startsWith(command)), `missing validator command: ${command}`);
}

assert.ok(templatePaths.has("docs/templates/windows-release-evidence.json"), "Windows release evidence template is required");
assert.ok(templatePaths.has("docs/templates/windows-signing-execution-evidence.json"), "Windows signing execution evidence template is required");
assert.ok(templatePaths.has("docs/templates/kms-hsm-sdk-approval-evidence.json"), "KMS/HSM SDK approval evidence template is required");
assert.ok(templatePaths.has("docs/templates/kms-hsm-provider-evidence.json"), "KMS/HSM evidence template is required");
assert.ok(templatePaths.has("docs/templates/browser-extension-identity-evidence.json"), "Browser extension identity evidence template is required");
assert.ok(templatePaths.has("docs/templates/browser-extension-rollout-evidence.json"), "Browser rollout evidence template is required");
assert.ok(templatePaths.has("docs/templates/credential-provider-approval-evidence.json"), "Credential provider approval evidence template is required");
assert.ok(templatePaths.has("docs/templates/native-companion-evidence.json"), "Native companion evidence template is required");

const result = {
  format: "sentinel-external-evidence-requests-validation-v1",
  requestPath,
  markdownPath,
  strict,
  environment: report.environment,
  owner: report.owner,
  requestCount: report.requests.length,
  templateCount: templatePaths.size,
  evidenceKeyCount: requestedEvidenceKeys.size,
  commandScriptCount: expectedCommandScripts.length,
  validatorCommandCount: requiredValidatorCommands.length,
  validated: true
};

console.log(JSON.stringify(result, null, 2));
