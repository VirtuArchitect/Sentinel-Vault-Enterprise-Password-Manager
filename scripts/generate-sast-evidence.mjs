import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "completed", "accepted-risk", "expired"]);
const outputPath = args.get("--out") || "artifacts/security/sast-evidence.json";
const status = args.get("--status") || "planned";
const reportPath = args.get("--report") || "replace-with-report-path";

assert.ok(allowedStatuses.has(status), "status must be planned, completed, accepted-risk, or expired");

const safeGit = (...gitArgs) => {
  try {
    return execFileSync("git", gitArgs, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
};

const parseReport = (candidate) => {
  if (!candidate || !existsSync(candidate)) {
    return {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
      suppressed: 0,
      redaction: {
        secretValuesFound: false,
        tokensFound: false,
        privateKeysFound: false
      }
    };
  }

  const text = readFileSync(candidate, "utf8").replace(/^\uFEFF/, "");
  const json = candidate.toLowerCase().endsWith(".json") ? JSON.parse(text) : null;
  const direct = json?.results || json?.summary || json || {};
  const findings = Array.isArray(json?.findings) ? json.findings : [];
  const countSeverity = (severity) => {
    if (Number.isInteger(direct[severity])) return direct[severity];
    return findings.filter((finding) => String(finding.severity || "").toLowerCase() === severity).length;
  };
  return {
    critical: countSeverity("critical"),
    high: countSeverity("high"),
    medium: countSeverity("medium"),
    low: countSeverity("low"),
    informational: countSeverity("informational"),
    suppressed: Number.isInteger(direct.suppressed) ? direct.suppressed : findings.filter((finding) => finding.suppressed === true).length,
    redaction: {
      secretValuesFound: /secret(Value)?\s*[:=]|VAULT_ROOT_KEY|Passw0rd!/i.test(text),
      tokensFound: /bearer\s+[A-Za-z0-9._-]+|token\s*[:=]\s*["']?[A-Za-z0-9._-]{12,}/i.test(text),
      privateKeysFound: /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)
    }
  };
};

const report = parseReport(reportPath);
const now = new Date();
const startedAt = args.get("--started-at") || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : new Date(now.getTime() - 60_000).toISOString().replace(/\.\d{3}Z$/, "Z"));
const completedAt = args.get("--completed-at") || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : now.toISOString().replace(/\.\d{3}Z$/, "Z"));
const dirty = safeGit("status", "--porcelain")?.length ? true : false;

const evidence = {
  format: "sentinel-sast-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  scan: {
    tool: args.get("--tool") || "replace-with-tool",
    toolVersion: args.get("--tool-version") || "replace-with-version",
    profile: args.get("--profile") || "replace-with-profile",
    startedAt,
    completedAt,
    reportPath
  },
  source: {
    commit: args.get("--source-commit") || safeGit("rev-parse", "HEAD") || "replace-with-git-sha",
    branch: args.get("--branch") || safeGit("branch", "--show-current") || "main",
    dirty: args.get("--dirty") === "true" ? true : args.get("--dirty") === "false" ? false : dirty
  },
  coverage: {
    includedSurfaces: (args.get("--included-surfaces") || "web-console,express-api,windows-packaging,browser-extension,windows-companion,scripts")
      .split(",")
      .map((surface) => surface.trim())
      .filter(Boolean),
    excludedPaths: (args.get("--excluded-paths") || "")
      .split(",")
      .map((surface) => surface.trim())
      .filter(Boolean),
    rulesets: (args.get("--rulesets") || "javascript-security,typescript-security,powershell-security,dependency-manifest")
      .split(",")
      .map((ruleset) => ruleset.trim())
      .filter(Boolean)
  },
  results: {
    critical: Number(args.get("--critical") ?? report.critical),
    high: Number(args.get("--high") ?? report.high),
    medium: Number(args.get("--medium") ?? report.medium),
    low: Number(args.get("--low") ?? report.low),
    informational: Number(args.get("--informational") ?? report.informational),
    suppressed: Number(args.get("--suppressed") ?? report.suppressed)
  },
  remediation: {
    trackingProject: args.get("--tracking-project") || "replace-with-project",
    owner: args.get("--owner") || "replace-with-owner",
    criticalDueDays: Number(args.get("--critical-due-days") || 7),
    highDueDays: Number(args.get("--high-due-days") || 14),
    mediumDueDays: Number(args.get("--medium-due-days") || 30),
    retestStatus: args.get("--retest-status") || "planned"
  },
  redaction: {
    secretValuesFound: args.get("--secret-values-found") === "true" ? true : args.get("--secret-values-found") === "false" ? false : report.redaction.secretValuesFound,
    tokensFound: args.get("--tokens-found") === "true" ? true : args.get("--tokens-found") === "false" ? false : report.redaction.tokensFound,
    privateKeysFound: args.get("--private-keys-found") === "true" ? true : args.get("--private-keys-found") === "false" ? false : report.redaction.privateKeysFound
  },
  approvals: {
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    engineeringOwner: args.get("--engineering-owner") || "replace-with-owner",
    releaseOwner: args.get("--release-owner") || "replace-with-owner"
  }
};

for (const [severity, count] of Object.entries(evidence.results)) {
  assert.ok(Number.isInteger(count) && count >= 0, `${severity} result count must be a non-negative integer`);
}

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`SAST evidence written: ${outputPath}`);
