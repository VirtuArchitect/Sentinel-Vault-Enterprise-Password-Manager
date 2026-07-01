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
  "pnpm validate:windows-release",
  "pnpm validate:windows-signing",
  "pnpm validate:kms-hsm-sdk-approval",
  "pnpm validate:kms-hsm-evidence",
  "pnpm validate:browser-identity",
  "pnpm validate:browser-rollout",
  "pnpm validate:native-companion"
];

const assertArray = (value, name, minLength = 1) => {
  assert.ok(Array.isArray(value), `${name} must be an array`);
  assert.ok(value.length >= minLength, `${name} must include at least ${minLength} item(s)`);
};

const resolveTemplate = (templatePath) => path.resolve(rootDir, templatePath);

assert.ok(existsSync(requestPath), `External evidence request pack not found: ${requestPath}`);
const report = JSON.parse(readFileSync(requestPath, "utf8"));

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
const templatePaths = new Set();

for (const [index, request] of report.requests.entries()) {
  assert.ok(request.phase && typeof request.phase === "string", `requests[${index}].phase is required`);
  assert.ok(request.title && typeof request.title === "string", `requests[${index}].title is required`);
  assert.ok(request.ownerRole && typeof request.ownerRole === "string", `requests[${index}].ownerRole is required`);
  assert.ok(request.blockerType && typeof request.blockerType === "string", `requests[${index}].blockerType is required`);
  assertArray(request.requiredInputs, `requests[${index}].requiredInputs`, 3);
  assertArray(request.evidenceTemplates, `requests[${index}].evidenceTemplates`);
  assertArray(request.commands, `requests[${index}].commands`, 2);
  assertArray(request.acceptanceCriteria, `requests[${index}].acceptanceCriteria`, 3);

  const requestKey = request.blockerType === "native-security-approval" ? `${request.phase}/native` : request.phase;
  requestKeys.add(requestKey);

  for (const templatePath of request.evidenceTemplates) {
    const absolutePath = resolveTemplate(templatePath);
    assert.ok(existsSync(absolutePath), `evidence template does not exist: ${templatePath}`);
    templatePaths.add(templatePath);
  }

  allCommands.push(...request.commands);
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
assert.ok(templatePaths.has("docs/templates/native-companion-evidence.json"), "Native companion evidence template is required");

const result = {
  format: "sentinel-external-evidence-requests-validation-v1",
  requestPath,
  strict,
  environment: report.environment,
  owner: report.owner,
  requestCount: report.requests.length,
  templateCount: templatePaths.size,
  validatorCommandCount: requiredValidatorCommands.length,
  validated: true
};

console.log(JSON.stringify(result, null, 2));
