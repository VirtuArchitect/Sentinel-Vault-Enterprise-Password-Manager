import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { productionEvidenceRequirementEntries } from "./production-evidence-requirements.mjs";

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

const readinessPath = path.resolve(args.get("--readiness") || "artifacts/deployment/pilot/phase-readiness.json");
const externalRequestsPath = path.resolve(args.get("--external-requests") || "artifacts/deployment/pilot/external-evidence-requests.json");
const outputPath = path.resolve(args.get("--out") || path.join(path.dirname(readinessPath), "phase-handoff-checklist.md"));

assert.ok(existsSync(readinessPath), `Phase readiness report not found: ${readinessPath}`);
assert.ok(existsSync(externalRequestsPath), `External evidence request pack not found: ${externalRequestsPath}`);

const readiness = JSON.parse(readFileSync(readinessPath, "utf8"));
const externalRequests = JSON.parse(readFileSync(externalRequestsPath, "utf8"));

assert.equal(readiness.format, "sentinel-phase-readiness-report-v1");
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");

const blockerSummary = (readiness.blockers || []).reduce((summary, blocker) => {
  const key = blocker.gate.startsWith("evidence.") ? "evidence-items" : blocker.gate;
  summary.set(key, (summary.get(key) || 0) + 1);
  return summary;
}, new Map());
const commandScripts = externalRequests.summary?.commandScripts || [];
const commandScriptCount = externalRequests.summary?.commandScriptCount || commandScripts.length;
const validatorCommandCount = readiness.externalRequests?.validatorCommandCount || 0;
const productionRequirementRows = productionEvidenceRequirementEntries
  .map(([evidenceKey, expectedStatus]) => `- \`${evidenceKey}\`: \`${expectedStatus}\``)
  .join("\n");

assert.equal(readiness.externalRequests?.commandScriptCount || 0, commandScriptCount, "readiness command script count does not match external requests");

const renderRequest = (request, index) => `## ${index + 1}. ${request.phase}: ${request.title}

Owner role: ${request.ownerRole}
Blocker type: ${request.blockerType}

### Required Inputs

${request.requiredInputs.map((input) => `- [ ] ${input}`).join("\n")}

### Evidence Templates

${request.evidenceTemplates.map((template) => `- [ ] \`${template}\``).join("\n")}

### Commands

${request.commands.map((command) => `- [ ] \`${command}\``).join("\n")}

### Acceptance Criteria

${request.acceptanceCriteria.map((criterion) => `- [ ] ${criterion}`).join("\n")}
`;

const markdown = `# Sentinel Vault Phase Handoff Checklist

Environment: ${readiness.bundle.environment}
Target: ${readiness.target}
Bundle status: ${readiness.bundle.status}
Bundle owner: ${readiness.bundle.owner}
Readiness: ${readiness.ready ? "ready" : "blocked"}
Generated from: \`${readinessPath}\`

Use this checklist to collect the deployment-specific evidence needed to clear the remaining Phase 2-8 gates. After completing the checklist, rerun:

\`\`\`powershell
pnpm report:phase-readiness -- --bundle "${readiness.bundle.path}" --external-requests "${readiness.externalRequests.path}" --target "${readiness.target}" --fail-on-blockers
\`\`\`

## Current Blocker Summary

${blockerSummary.size ? [...blockerSummary.entries()].map(([gate, count]) => `- ${gate}: ${count}`).join("\n") : "- None"}

## Current Warnings

${readiness.warnings?.length ? readiness.warnings.map((warning) => `- ${warning.gate}: ${warning.message}`).join("\n") : "- None"}

## Command Coverage Summary

- Command scripts: ${commandScriptCount}
- Validator commands: ${validatorCommandCount}

${commandScripts.map((script) => `- \`pnpm ${script}\``).join("\n")}

## Production Evidence Status Requirements

The final production release gate expects these deployment evidence statuses before the phase handoff can close:

${productionRequirementRows}

${externalRequests.requests.map(renderRequest).join("\n")}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, markdown);

console.log(JSON.stringify({
  format: "sentinel-phase-handoff-checklist-result-v1",
  outputPath,
  readinessPath,
  externalRequestsPath,
  requestCount: externalRequests.requests.length,
  commandScriptCount,
  validatorCommandCount,
  productionRequirementCount: productionEvidenceRequirementEntries.length,
  blockerCount: readiness.blockers?.length || 0,
  ready: readiness.ready
}, null, 2));
