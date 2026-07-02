import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const readme = readFileSync(path.join(rootDir, "README.md"), "utf8");

const requiredReleaseCommands = [
  "pnpm validate:deployment-workspace",
  "pnpm validate:external-evidence",
  "pnpm validate:deployment-status",
  "pnpm validate:deployment-redaction",
  "pnpm validate:phase-completion",
  "pnpm validate:phase-readiness",
  "pnpm validate:phase-handoff",
  "pnpm validate:phase-evidence",
  "pnpm validate:phase-gate --",
  "pnpm validate:phase-gate-report",
  "pnpm validate:phase-actions",
  "pnpm validate:phase-gaps",
  "pnpm validate:phase-decision",
  "pnpm validate:phase-signoffs",
  "pnpm validate:phase-intake",
  "pnpm validate:phase-attachments",
  "pnpm validate:phase-waivers",
  "pnpm validate:phase-review",
  "pnpm validate:phase-closure",
  "pnpm validate:release-gate",
  "pnpm validate:release-gate-report",
  "pnpm package:release-archive",
  "pnpm validate:release-archive"
];

test("README release sequence documents final gate validation commands", () => {
  const missing = requiredReleaseCommands.filter((command) => !readme.includes(command));
  assert.deepEqual(missing, [], `README release sequence is missing commands: ${missing.join(", ")}`);
  assert.match(readme, /validate:phase-gate-report.+--require-ready/, "phase gate report validation must require readiness");
  assert.match(readme, /validate:release-gate.+--target "production".+--require-clean/, "release gate command must target production and require a clean source tree");
  assert.match(readme, /validate:release-gate-report.+--target "production".+--require-clean.+--require-ready/, "release gate report validation must target production, require a clean source tree, and require readiness");
  assert.match(readme, /validate:release-archive.+--target "production".+--require-clean.+--require-ready.+--require-approved-waivers/, "release archive validation must target production, require clean source, readiness, and approved waivers");
});
