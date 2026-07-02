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
const inventoryPath = path.resolve(args.get("--attachments") || path.join(evidenceDir, "phase-attachment-inventory.json"));
const decisionPath = path.resolve(args.get("--phase-decision") || path.join(evidenceDir, "phase-decision-record.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-waiver-register.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join(evidenceDir, "phase-waiver-register.md"));

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

assert.ok(existsSync(inventoryPath), `Phase attachment inventory not found: ${inventoryPath}`);
assert.ok(existsSync(decisionPath), `Phase decision record not found: ${decisionPath}`);

const inventory = readJson(inventoryPath);
const decision = readJson(decisionPath);

assert.equal(inventory.format, "sentinel-phase-attachment-inventory-v1");
assert.equal(decision.format, "sentinel-phase-decision-record-v1");

const waivers = [];
for (const attachment of inventory.attachments) {
  for (const file of attachment.files) {
    if (file.status === "missing") {
      waivers.push({
        id: `WVR-${String(waivers.length + 1).padStart(2, "0")}`,
        phase: attachment.phase,
        title: attachment.title,
        ownerRole: attachment.ownerRole,
        blockerType: attachment.blockerType,
        evidenceKey: file.evidenceKey || null,
        evidenceKeys: attachment.evidenceKeys || [],
        waiverType: "missing-evidence",
        status: "proposed",
        targetPath: file.targetPath,
        reason: "Required evidence file has not been attached to the intake folder.",
        requiredApproval: "securityOwner",
        expiresAt: "replace-with-expiry-date",
        approvalReference: "replace-with-change-or-risk-reference",
        compensatingControl: "replace-with-compensating-control"
      });
    }

    for (const finding of file.redactionFindings) {
      waivers.push({
        id: `WVR-${String(waivers.length + 1).padStart(2, "0")}`,
        phase: attachment.phase,
        title: attachment.title,
        ownerRole: attachment.ownerRole,
        blockerType: attachment.blockerType,
        evidenceKey: file.evidenceKey || null,
        evidenceKeys: attachment.evidenceKeys || [],
        waiverType: "redaction-finding",
        status: "proposed",
        targetPath: file.targetPath,
        reason: `Attachment triggered redaction rule ${finding.rule} on line ${finding.lineNumber}.`,
        requiredApproval: "securityOwner",
        expiresAt: "replace-with-expiry-date",
        approvalReference: "replace-with-change-or-risk-reference",
        compensatingControl: "replace-with-compensating-control"
      });
    }
  }
}

const register = {
  format: "sentinel-phase-waiver-register-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  inventoryPath,
  decisionPath,
  environment: inventory.environment,
  owner: inventory.owner,
  decision: decision.decision,
  summary: {
    waiverCount: waivers.length,
    proposedCount: waivers.filter((waiver) => waiver.status === "proposed").length,
    approvedCount: waivers.filter((waiver) => waiver.status === "approved").length,
    rejectedCount: waivers.filter((waiver) => waiver.status === "rejected").length,
    missingEvidenceCount: waivers.filter((waiver) => waiver.waiverType === "missing-evidence").length,
    redactionFindingCount: waivers.filter((waiver) => waiver.waiverType === "redaction-finding").length
  },
  waivers
};

const renderMarkdown = () => `# Sentinel Vault Phase Waiver Register

Environment: ${register.environment}
Owner: ${register.owner}
Decision: ${register.decision}
Generated: ${register.generatedAt}

Summary:
- Waivers: ${register.summary.waiverCount}
- Proposed: ${register.summary.proposedCount}
- Missing evidence: ${register.summary.missingEvidenceCount}
- Redaction findings: ${register.summary.redactionFindingCount}

${waivers.length > 0 ? waivers.map((waiver) => `## ${waiver.id}: ${waiver.phase} - ${waiver.waiverType}

Owner role: ${waiver.ownerRole}
Status: ${waiver.status}
Target: \`${waiver.targetPath}\`
Evidence key: ${waiver.evidenceKey ? `\`${waiver.evidenceKey}\`` : "supporting artifact"}
Reason: ${waiver.reason}
Approval reference: ${waiver.approvalReference}
Expires: ${waiver.expiresAt}`).join("\n\n") : "No waivers are required for the current attachment inventory."}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(register, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-phase-waiver-register-result-v1",
  outputPath,
  markdownPath,
  waiverCount: register.summary.waiverCount,
  proposedCount: register.summary.proposedCount
}, null, 2));
