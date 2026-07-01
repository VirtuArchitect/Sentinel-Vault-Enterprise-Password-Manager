import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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

const rootDir = path.resolve(import.meta.dirname, "..");
const bundlePath = path.resolve(args.get("--bundle") || "docs/templates/deployment-evidence-bundle.json");
const externalRequestsPath = path.resolve(args.get("--external-requests") || path.join(path.dirname(bundlePath), "external-evidence-requests.json"));
const outputPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const markdownPath = args.get("--markdown-out") ? path.resolve(args.get("--markdown-out")) : null;
const target = args.get("--target") || "pilot";
const allowedTargets = new Set(["pilot", "production"]);

assert.ok(allowedTargets.has(target), "--target must be pilot or production");
assert.ok(existsSync(bundlePath), `Deployment evidence bundle not found: ${bundlePath}`);

const runJson = (script, scriptArgs) => {
  try {
    const output = execFileSync(process.execPath, [script, ...scriptArgs], {
      cwd: rootDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
    return { ok: true, result: JSON.parse(output), error: null };
  } catch (error) {
    const stderr = error.stderr?.toString().trim();
    const stdout = error.stdout?.toString().trim();
    return { ok: false, result: null, error: stderr || stdout || error.message };
  }
};

const deploymentStatus = runJson("scripts/report-deployment-evidence-status.mjs", ["--bundle", bundlePath]);
const externalValidation = existsSync(externalRequestsPath)
  ? runJson("scripts/validate-external-evidence-requests.mjs", ["--requests", externalRequestsPath, "--strict"])
  : { ok: false, result: null, error: `External evidence request pack not found: ${externalRequestsPath}` };

const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
const blockers = [];
const warnings = [];

if (!deploymentStatus.ok) {
  blockers.push({
    gate: "deployment-evidence-status",
    severity: "blocking",
    message: deploymentStatus.error
  });
} else {
  const report = deploymentStatus.result;
  if (!report.readyForPilotOrProduction) {
    blockers.push({
      gate: "deployment-evidence-status",
      severity: "blocking",
      message: "Deployment evidence bundle is not ready for pilot or production",
      summary: report.summary
    });
  }

  for (const item of report.items || []) {
    if (!item.productionReady) {
      blockers.push({
        gate: `evidence.${item.name}`,
        severity: "blocking",
        message: item.issue || "Evidence item is not production ready",
        placeholderCount: item.placeholderCount,
        blockingStatusCount: item.blockingStatuses?.length || 0
      });
    }
  }
}

if (!externalValidation.ok) {
  blockers.push({
    gate: "external-evidence-requests",
    severity: "blocking",
    message: externalValidation.error
  });
}

if (bundle.status !== target) {
  warnings.push({
    gate: "deployment-target",
    severity: "warning",
    message: `Bundle status is ${bundle.status}; requested readiness target is ${target}`
  });
}

if (target === "production" && bundle.status !== "production") {
  blockers.push({
    gate: "production-status",
    severity: "blocking",
    message: "Production readiness requires a deployment evidence bundle with status production"
  });
}

const report = {
  format: "sentinel-phase-readiness-report-v1",
  target,
  generatedAt: new Date().toISOString(),
  bundle: {
    path: bundlePath,
    environment: bundle.environment,
    status: bundle.status,
    owner: bundle.owner
  },
  externalRequests: {
    path: externalRequestsPath,
    validated: externalValidation.ok,
    requestCount: externalValidation.result?.requestCount || 0
  },
  deploymentEvidence: {
    validated: deploymentStatus.ok,
    readyForPilotOrProduction: deploymentStatus.result?.readyForPilotOrProduction || false,
    summary: deploymentStatus.result?.summary || null
  },
  ready: blockers.length === 0,
  blockers,
  warnings
};

const renderMarkdown = () => `# Sentinel Vault Phase Readiness

Target: ${target}
Environment: ${report.bundle.environment}
Status: ${report.bundle.status}
Owner: ${report.bundle.owner}
Ready: ${report.ready ? "yes" : "no"}

## Deployment Evidence

- Bundle: \`${bundlePath}\`
- Ready for pilot or production: ${report.deploymentEvidence.readyForPilotOrProduction ? "yes" : "no"}
- Evidence items ready: ${report.deploymentEvidence.summary?.productionReady ?? 0}/${report.deploymentEvidence.summary?.total ?? 0}

## External Evidence Requests

- Request pack: \`${externalRequestsPath}\`
- Strict validation: ${report.externalRequests.validated ? "passed" : "failed"}
- Request count: ${report.externalRequests.requestCount}

## Blockers

${blockers.length ? blockers.map((blocker) => `- ${blocker.gate}: ${blocker.message}`).join("\n") : "- None"}

## Warnings

${warnings.length ? warnings.map((warning) => `- ${warning.gate}: ${warning.message}`).join("\n") : "- None"}
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
