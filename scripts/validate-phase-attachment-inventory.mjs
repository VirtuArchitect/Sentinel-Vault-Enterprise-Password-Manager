import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

const inventoryPath = path.resolve(args.get("--inventory") || "artifacts/deployment/pilot/phase-attachment-inventory.json");
const intakePath = args.get("--intake") ? path.resolve(args.get("--intake")) : null;
const requireComplete = args.get("--require-complete") === true || args.get("--require-complete") === "true";
const requireRedacted = args.get("--require-redacted") === true || args.get("--require-redacted") === "true";

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

assert.ok(existsSync(inventoryPath), `Phase attachment inventory not found: ${inventoryPath}`);
const inventory = readJson(inventoryPath);
assert.equal(inventory.format, "sentinel-phase-attachment-inventory-v1");
assert.ok(!Number.isNaN(Date.parse(inventory.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(Array.isArray(inventory.attachments), "attachments must be an array");

const intake = readJson(intakePath || inventory.intakePath);
assert.equal(intake.format, "sentinel-phase-evidence-intake-v1");
assert.equal(inventory.intakePath, intakePath || inventory.intakePath, "intake path mismatch");
assert.equal(inventory.environment, intake.environment, "environment mismatch");
assert.equal(inventory.owner, intake.owner, "owner mismatch");
assert.equal(inventory.attachments.length, intake.intakeItems.length, "attachment item count mismatch");

assert.equal(inventory.summary.intakeCount, inventory.attachments.length, "summary intake count mismatch");
assert.equal(inventory.summary.expectedFileCount, inventory.attachments.reduce((total, item) => total + item.expectedFileCount, 0), "summary expected file count mismatch");
assert.equal(inventory.summary.attachedFileCount, inventory.attachments.reduce((total, item) => total + item.attachedFileCount, 0), "summary attached file count mismatch");
assert.equal(inventory.summary.missingFileCount, inventory.attachments.reduce((total, item) => total + item.missingFileCount, 0), "summary missing file count mismatch");
assert.equal(inventory.summary.redactionFindingCount, inventory.attachments.reduce((total, item) => total + item.redactionFindingCount, 0), "summary redaction finding count mismatch");
assert.equal(inventory.summary.commandScriptCount, intake.summary.commandScriptCount || 0, "summary command script count mismatch");
assert.equal(inventory.summary.validatorCommandCount, intake.summary.validatorCommandCount || 0, "summary validator command count mismatch");
assert.deepEqual(inventory.summary.commandScripts, intake.summary.commandScripts || [], "summary command scripts mismatch");

inventory.attachments.forEach((attachment, index) => {
  const intakeItem = intake.intakeItems[index];
  assert.equal(attachment.id, intakeItem.id, `attachment ${index + 1} id mismatch`);
  assert.equal(attachment.phase, intakeItem.phase, `attachment ${index + 1} phase mismatch`);
  assert.equal(attachment.title, intakeItem.title, `attachment ${index + 1} title mismatch`);
  assert.equal(attachment.ownerRole, intakeItem.ownerRole, `attachment ${index + 1} owner mismatch`);
  assert.equal(attachment.blockerType, intakeItem.blockerType, `attachment ${index + 1} blocker mismatch`);
  assert.equal(attachment.intakeDir, intakeItem.intakeDir, `attachment ${index + 1} intake folder mismatch`);
  assert.deepEqual(attachment.evidenceKeys, intakeItem.evidenceKeys || [], `attachment ${index + 1} evidence key mismatch`);
  assert.deepEqual(attachment.commandScripts, intakeItem.commandScripts || [], `attachment ${index + 1} command scripts mismatch`);
  assert.equal(attachment.files.length, intakeItem.expectedFiles.length, `attachment ${index + 1} file count mismatch`);
  assert.equal(attachment.expectedFileCount, attachment.files.length, `attachment ${index + 1} expected count mismatch`);
  assert.equal(attachment.attachedFileCount, attachment.files.filter((file) => file.status !== "missing").length, `attachment ${index + 1} attached count mismatch`);
  assert.equal(attachment.missingFileCount, attachment.files.filter((file) => file.status === "missing").length, `attachment ${index + 1} missing count mismatch`);
  assert.equal(attachment.redactionFindingCount, attachment.files.reduce((total, file) => total + file.redactionFindings.length, 0), `attachment ${index + 1} redaction count mismatch`);

  attachment.files.forEach((file, fileIndex) => {
    const expectedFile = intakeItem.expectedFiles[fileIndex];
    const expectedResolvedPath = path.resolve(inventory.evidenceDir, expectedFile.targetPath);
    assert.equal(file.evidenceKey, expectedFile.evidenceKey || null, `attachment ${index + 1} file ${fileIndex + 1} evidence key mismatch`);
    assert.equal(file.templatePath, expectedFile.templatePath, `attachment ${index + 1} file ${fileIndex + 1} template mismatch`);
    assert.equal(file.targetPath, expectedFile.targetPath, `attachment ${index + 1} file ${fileIndex + 1} target mismatch`);
    assert.equal(file.resolvedPath, expectedResolvedPath, `attachment ${index + 1} file ${fileIndex + 1} resolved path mismatch`);
    assert.ok(["attached", "missing", "redaction-review-required"].includes(file.status), `attachment ${index + 1} file ${fileIndex + 1} status invalid`);
    assert.ok(Array.isArray(file.redactionFindings), `attachment ${index + 1} file ${fileIndex + 1} redaction findings must be an array`);

    if (existsSync(file.resolvedPath)) {
      const actual = hashFile(file.resolvedPath);
      assert.notEqual(file.status, "missing", `attachment ${index + 1} file ${fileIndex + 1} status is stale`);
      assert.equal(file.bytes, actual.bytes, `attachment ${index + 1} file ${fileIndex + 1} byte length changed`);
      assert.equal(file.sha256, actual.sha256, `attachment ${index + 1} file ${fileIndex + 1} SHA-256 changed`);
    } else {
      assert.equal(file.status, "missing", `attachment ${index + 1} file ${fileIndex + 1} missing status mismatch`);
      assert.equal(file.bytes, 0, `attachment ${index + 1} file ${fileIndex + 1} missing byte count mismatch`);
      assert.equal(file.sha256, null, `attachment ${index + 1} file ${fileIndex + 1} missing hash mismatch`);
    }
  });
});

if (requireComplete) {
  assert.equal(inventory.summary.missingFileCount, 0, "phase attachment inventory must be complete");
}

if (requireRedacted) {
  assert.equal(inventory.summary.redactionFindingCount, 0, "phase attachment inventory must be redacted");
}

console.log(JSON.stringify({
  format: "sentinel-phase-attachment-inventory-validation-v1",
  inventoryPath,
  expectedFileCount: inventory.summary.expectedFileCount,
  attachedFileCount: inventory.summary.attachedFileCount,
  missingFileCount: inventory.summary.missingFileCount,
  redactionFindingCount: inventory.summary.redactionFindingCount,
  commandScriptCount: inventory.summary.commandScriptCount,
  validatorCommandCount: inventory.summary.validatorCommandCount,
  validated: true
}, null, 2));
