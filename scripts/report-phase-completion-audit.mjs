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

const roadmapPath = path.resolve(args.get("--roadmap") || "docs/architecture/implementation-phases.md");
const externalRequestsPath = path.resolve(args.get("--external-requests") || "artifacts/deployment/pilot/external-evidence-requests.json");
const outputPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const markdownPath = args.get("--markdown-out") ? path.resolve(args.get("--markdown-out")) : null;
const failOnRemaining = args.has("--fail-on-remaining");

assert.ok(existsSync(roadmapPath), `Implementation roadmap not found: ${roadmapPath}`);
assert.ok(existsSync(externalRequestsPath), `External evidence request pack not found: ${externalRequestsPath}`);

const roadmap = readFileSync(roadmapPath, "utf8");
const externalRequests = JSON.parse(readFileSync(externalRequestsPath, "utf8"));
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");

const phaseHeadings = [...roadmap.matchAll(/^## Phase (\d+): ([^\r\n]+)$/gm)];
assert.ok(phaseHeadings.length > 0, "No implementation phases found in roadmap");

const phaseRequests = new Map();
for (const request of externalRequests.requests || []) {
  const phaseNumber = Number.parseInt(request.phase.replace("Phase ", ""), 10);
  if (!Number.isFinite(phaseNumber)) continue;
  const entries = phaseRequests.get(phaseNumber) || [];
  entries.push({
    title: request.title,
    blockerType: request.blockerType,
    ownerRole: request.ownerRole
  });
  phaseRequests.set(phaseNumber, entries);
}

const parseBulletsAfter = (body, heading) => {
  const headingMatch = body.match(new RegExp(`^${heading}:\\s*$`, "m"));
  if (!headingMatch) return [];
  const start = headingMatch.index + headingMatch[0].length;
  const rest = body.slice(start);
  const nextHeading = rest.search(/^##? |\n[A-Z][A-Za-z ]+:\s*$/m);
  const section = nextHeading >= 0 ? rest.slice(0, nextHeading) : rest;
  return [...section.matchAll(/^- (.+)$/gm)].map((match) => match[1].trim());
};

const parseImplicitImplementedBullets = (body) => {
  const statusMatch = body.match(/^Status:\s*.+$/m);
  if (!statusMatch) return [];
  const start = statusMatch.index + statusMatch[0].length;
  const rest = body.slice(start);
  const nextSection = rest.search(/^\w[\w ]+:\s*$/m);
  const section = nextSection >= 0 ? rest.slice(0, nextSection) : rest;
  return [...section.matchAll(/^- (.+)$/gm)].map((match) => match[1].trim());
};

const phases = phaseHeadings.map((match, index) => {
  const number = Number.parseInt(match[1], 10);
  const nextHeading = phaseHeadings[index + 1]?.index ?? roadmap.length;
  const body = roadmap.slice(match.index, nextHeading);
  const status = body.match(/^Status:\s*(.+)$/m)?.[1]?.trim() || "Unknown";
  const explicitImplemented = parseBulletsAfter(body, "Implemented");
  const implemented = explicitImplemented.length > 0 ? explicitImplemented : parseImplicitImplementedBullets(body);
  const explicitRemaining = parseBulletsAfter(body, "Remaining");
  const statusIndicatesRemaining = /\b(pending|partially implemented|started)\b/i.test(status);
  const remaining = explicitRemaining.length > 0 || !statusIndicatesRemaining ? explicitRemaining : [status];
  const requests = phaseRequests.get(number) || [];
  return {
    number,
    title: match[2].trim(),
    status,
    implementedCount: implemented.length,
    remaining,
    externalRequests: requests,
    completeInRepo: remaining.length === 0,
    externallyCovered: remaining.length === 0 || requests.length > 0
  };
});

const uncoveredRemaining = phases
  .filter((phase) => phase.remaining.length > 0 && phase.externalRequests.length === 0)
  .map((phase) => ({
    phase: `Phase ${phase.number}`,
    title: phase.title,
    remaining: phase.remaining
  }));

const remainingPhases = phases.filter((phase) => phase.remaining.length > 0);
const report = {
  format: "sentinel-phase-completion-audit-v1",
  generatedAt: new Date().toISOString(),
  roadmapPath,
  externalRequestsPath,
  phaseCount: phases.length,
  implementedPhaseCount: phases.filter((phase) => phase.completeInRepo).length,
  remainingPhaseCount: remainingPhases.length,
  remainingItemCount: remainingPhases.reduce((total, phase) => total + phase.remaining.length, 0),
  uncoveredRemaining,
  complete: remainingPhases.length === 0,
  externallyCovered: uncoveredRemaining.length === 0,
  phases
};

const renderMarkdown = () => `# Sentinel Vault Phase Completion Audit

Roadmap: \`${roadmapPath}\`
External evidence requests: \`${externalRequestsPath}\`
Complete in repo: ${report.complete ? "yes" : "no"}
Remaining phases: ${report.remainingPhaseCount}
Remaining items: ${report.remainingItemCount}
Remaining items covered by handoff requests: ${report.externallyCovered ? "yes" : "no"}

## Remaining Work

${remainingPhases.length ? remainingPhases.map((phase) => `### Phase ${phase.number}: ${phase.title}

Status: ${phase.status}

Remaining:
${phase.remaining.map((item) => `- ${item}`).join("\n")}

External handoff requests:
${phase.externalRequests.length ? phase.externalRequests.map((request) => `- ${request.blockerType}: ${request.title} (${request.ownerRole})`).join("\n") : "- None"}`).join("\n\n") : "- None"}

## Implemented Phase Summary

${phases.map((phase) => `- Phase ${phase.number}: ${phase.implementedCount} implemented item(s), ${phase.remaining.length} remaining item(s)`).join("\n")}
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

if (failOnRemaining && !report.complete) {
  process.exitCode = 1;
}
