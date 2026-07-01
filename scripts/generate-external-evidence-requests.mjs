import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const environment = args.get("--environment") || args.get("--env") || "replace-with-environment";
const owner = args.get("--owner") || "replace-with-owner";
const outputPath = path.resolve(args.get("--out") || path.join("artifacts", "deployment", environment, "external-evidence-requests.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join("artifacts", "deployment", environment, "external-evidence-requests.md"));

const requests = [
  {
    phase: "Phase 2",
    title: "Postgres HA dependency and environment approval",
    ownerRole: "Platform data owner",
    blockerType: "postgres-ha-approval",
    requiredInputs: [
      "Approved Postgres client dependency, version, license, and supply-chain review",
      "Target HA Postgres environment details, backup policy, network path, and credential ownership",
      "Cutover plan from SQLite or JSON state with restore, rollback, and migration-readiness evidence"
    ],
    evidenceTemplates: [
      "docs/templates/postgres-ha-approval-evidence.json",
      "docs/templates/storage-migration-evidence.json",
      "docs/architecture/postgres-schema.sql"
    ],
    commands: [
      "pnpm plan:postgres -- --state <deployment-state.json> --out <postgres-migration-plan.json>",
      "pnpm release:postgres-ha -- --status approved --migration-plan <postgres-migration-plan.json> --storage-migration-evidence <storage-migration-evidence.json> --out <postgres-ha-approval-evidence.json>",
      "pnpm validate:postgres-ha -- <postgres-ha-approval-evidence.json>",
      "pnpm inspect:storage -- --state <deployment-state.json> --out <storage-readiness.json>",
      "pnpm validate:storage-migration -- <storage-migration-evidence.json>"
    ],
    acceptanceCriteria: [
      "Runtime dependency approval covers provenance, maintenance, license, and threat-model impact",
      "Target database controls cover HA, backup, restore, network isolation, and least-privilege access",
      "Cutover evidence proves migration readiness and rollback before enabling HA production storage"
    ]
  },
  {
    phase: "Phase 4",
    title: "Deployment-specific migration and tenant-isolation evidence",
    ownerRole: "Migration owner",
    blockerType: "deployment-evidence",
    requiredInputs: [
      "Approved proprietary source column map for each imported source system",
      "Redacted source-export conversion output and migration evidence",
      "Completed tenant-isolation evidence for the target tenant hierarchy"
    ],
    evidenceTemplates: [
      "docs/templates/source-export-column-map.json",
      "docs/templates/storage-migration-evidence.json",
      "docs/templates/tenant-isolation-evidence.json"
    ],
    commands: [
      "pnpm convert:source-export -- --csv <source-export.csv> --mapping <column-map.json> --out <normalized-import.json> --evidence <migration-evidence.json>",
      "pnpm inspect:storage -- --state <deployment-state.json> --out <storage-readiness.json>",
      "pnpm release:tenant-isolation -- --report <tenant-isolation-tests.json> --out <tenant-isolation-evidence.json>",
      "pnpm validate:storage-migration -- <storage-migration-evidence.json>",
      "pnpm validate:tenant-isolation -- <tenant-isolation-evidence.json>"
    ],
    acceptanceCriteria: [
      "No source-system credentials, plaintext secrets, or customer-only fields appear in evidence",
      "Every proprietary source column is mapped, intentionally ignored, or escalated",
      "Tenant isolation evidence includes passing cross-tenant negative authorization checks"
    ]
  },
  {
    phase: "Phase 5",
    title: "Production SIEM receiver and ITSM work-note evidence",
    ownerRole: "Integration owner",
    blockerType: "production-connector-evidence",
    requiredInputs: [
      "Production SIEM receiver URL, key ID, rotation window, and signed delivery samples",
      "Approved ITSM base URL, allowed states, ticket prefixes, and change-window policy",
      "Redacted ITSM work-note proof for access request, approval, denial, and revocation events"
    ],
    evidenceTemplates: [
      "docs/templates/connector-certification-evidence.json",
      "docs/templates/siem-receiver-rotation-evidence.json",
      "docs/templates/devops-token-response-evidence.json"
    ],
    commands: [
      "pnpm preflight:connectors -- --siem-url <receiver-url> --ticket-ref <approved-ticket>",
      "pnpm release:connector-evidence -- --preflight <connector-live-preflight.json> --out <connector-certification-evidence.json>",
      "pnpm release:siem-rotation -- --report <siem-receiver-rotation.json> --out <siem-receiver-rotation-evidence.json>",
      "pnpm validate:connector-evidence -- <connector-certification-evidence.json>",
      "pnpm validate:siem-rotation -- <siem-receiver-rotation-evidence.json>"
    ],
    acceptanceCriteria: [
      "Receiver verifies HMAC signature, key ID, nonce, timestamp, and replay rejection",
      "ITSM ticket lookup confirms an active approved state inside the permitted window",
      "Work-note evidence is redacted and tied to approved incident, change, or request references"
    ]
  },
  {
    phase: "Phase 6",
    title: "MSI/MSIX signing evidence from approved release host",
    ownerRole: "Release owner",
    blockerType: "certificate-backed-release",
    requiredInputs: [
      "Approved code-signing certificate or PFX access on the release host",
      "Built MSI/MSIX/EXE artifacts and SHA-256 manifest",
      "Rollback and uninstall drill evidence from the signed build"
    ],
    evidenceTemplates: [
      "docs/templates/windows-release-evidence.json",
      "docs/templates/windows-install-hardening-evidence.json",
      "docs/templates/release-attestation-evidence.json"
    ],
    commands: [
      "pnpm package:windows:msi",
      "pnpm package:windows:msix",
      "pnpm sign:windows -- -ArtifactPath <artifact-path> -CertificateThumbprint <thumbprint>",
      "pnpm verify:windows:signatures -- -ArtifactPath <artifact-path>",
      "pnpm release:windows-evidence -- --artifact <signed-artifact> --out <windows-release-evidence.json>",
      "pnpm validate:windows-release -- <windows-release-evidence.json>"
    ],
    acceptanceCriteria: [
      "All distributable Windows artifacts are signed and signature verification passes",
      "Release evidence records certificate identity, release host metadata, source commit, and artifact hashes",
      "Rollback and uninstall evidence is attached before pilot or production distribution"
    ]
  },
  {
    phase: "Phase 7",
    title: "Provider SDK-backed KMS/HSM approval and implementation evidence",
    ownerRole: "Security architecture owner",
    blockerType: "dependency-and-environment-approval",
    requiredInputs: [
      "Approved provider SDK, version, license, and supply-chain review",
      "Non-production KMS/HSM tenant, key ID, policy, audit sink, and break-glass procedure",
      "Key ceremony, rotation, backup, restore, and rollback evidence"
    ],
    evidenceTemplates: [
      "docs/templates/kms-hsm-provider-evidence.json"
    ],
    commands: [
      "pnpm preflight:kms-hsm -- --endpoint <gateway-url> --key-id <key-id> --out <kms-hsm-gateway-preflight.json>",
      "pnpm release:kms-hsm -- --preflight <kms-hsm-gateway-preflight.json> --out <kms-hsm-provider-evidence.json>",
      "pnpm validate:kms-hsm-evidence -- <kms-hsm-provider-evidence.json>"
    ],
    acceptanceCriteria: [
      "Dependency approval covers SDK provenance, maintenance, license, and threat-model impact",
      "Provider implementation proves signing or unwrap behavior without exporting key material",
      "Key ceremony evidence covers rotation, audit, backup, restore, and emergency access"
    ]
  },
  {
    phase: "Phase 8",
    title: "Production browser extension rollout evidence",
    ownerRole: "Endpoint platform owner",
    blockerType: "production-extension-identity",
    requiredInputs: [
      "Production extension ID for each target browser or private store channel",
      "Enterprise policy assignment, allowlist, and rollback plan",
      "Store/private-channel review result and packaged artifact hash"
    ],
    evidenceTemplates: [
      "docs/templates/browser-extension-rollout-evidence.json"
    ],
    commands: [
      "pnpm package:extension",
      "pnpm release:browser-rollout -- --artifact <sentinel-vault-autofill.zip> --extension-id <production-extension-id> --out <browser-rollout-evidence.json>",
      "pnpm render:browser-policy -- --evidence <browser-rollout-evidence.json> --out <browser-policy.json>",
      "pnpm validate:browser-rollout -- <browser-rollout-evidence.json>"
    ],
    acceptanceCriteria: [
      "Evidence uses production extension IDs instead of placeholders",
      "Enterprise policy only enables the reviewed extension and approved native host",
      "Rollback instructions and store/private-channel review outcomes are recorded"
    ]
  },
  {
    phase: "Phase 8",
    title: "Signed native credential-provider implementation approval",
    ownerRole: "Windows endpoint security owner",
    blockerType: "native-security-approval",
    requiredInputs: [
      "Formal approval to move beyond the proof-of-concept credential-provider boundary",
      "Signed credential-provider DLL or installer artifact from the release host",
      "Offline logon, abuse-case, rollback, uninstall, and recovery evidence"
    ],
    evidenceTemplates: [
      "docs/templates/native-companion-evidence.json",
      "docs/security/autotype-credential-provider-review.md"
    ],
    commands: [
      "pnpm release:native-companion -- --artifact <signed-credential-provider-artifact> --credential-provider-enabled true --out <native-companion-evidence.json>",
      "pnpm validate:native-companion -- <native-companion-evidence.json>"
    ],
    acceptanceCriteria: [
      "Credential-provider behavior is approved before registration on managed endpoints",
      "Signed artifact evidence includes hash, architecture, certificate verification, and rollback proof",
      "Abuse-case and offline-logon behavior are documented and approved"
    ]
  }
];

const report = {
  format: "sentinel-external-evidence-requests-v1",
  environment,
  owner,
  generatedAt: new Date().toISOString(),
  summary: {
    total: requests.length,
    phases: [...new Set(requests.map((request) => request.phase))],
    blockerTypes: [...new Set(requests.map((request) => request.blockerType))]
  },
  requests
};

const renderMarkdown = () => `# Sentinel Vault External Evidence Requests

Environment: ${environment}
Owner: ${owner}
Generated: ${report.generatedAt}

These requests cover the remaining phase work that cannot be completed from repository code alone. Attach the completed evidence to the deployment evidence bundle before marking a deployment pilot or production ready, then run \`pnpm validate:deployment-evidence -- <deployment-evidence-bundle.json>\`.

${requests.map((request, index) => `## ${index + 1}. ${request.phase}: ${request.title}

Owner role: ${request.ownerRole}
Blocker type: ${request.blockerType}

Required inputs:
${request.requiredInputs.map((input) => `- ${input}`).join("\n")}

Evidence templates:
${request.evidenceTemplates.map((template) => `- \`${template}\``).join("\n")}

Commands:
${request.commands.map((command) => `- \`${command}\``).join("\n")}

Acceptance criteria:
${request.acceptanceCriteria.map((criterion) => `- ${criterion}`).join("\n")}`).join("\n\n")}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(report, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-external-evidence-requests-result-v1",
  environment,
  owner,
  outputPath,
  markdownPath,
  requestCount: requests.length
}, null, 2));
