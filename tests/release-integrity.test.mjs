import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

test("release integrity guard keeps version, changelog, docs, demo, and runbooks aligned", () => {
  const output = execFileSync(process.execPath, ["scripts/validate-release-integrity.mjs"], {
    encoding: "utf8"
  });
  assert.match(output, /Release integrity validated/);
});
