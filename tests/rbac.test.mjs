import test from "node:test";
import assert from "node:assert/strict";
import { hasPermission, publicUser } from "../src/server/rbac/roles.mjs";

test("security admins can update policy", () => {
  assert.equal(hasPermission("SECURITY_ADMIN", "policy:write"), true);
});

test("auditors cannot update policy", () => {
  assert.equal(hasPermission("AUDITOR", "policy:write"), false);
});

test("public users do not expose password hashes", () => {
  const user = publicUser({
    id: "u1",
    name: "Avery Stone",
    email: "avery.stone@enterprise.example",
    role: "SECURITY_ADMIN",
    unit: "Strategic Systems",
    mfa: true,
    hash: "secret",
    salt: "salt"
  });
  assert.deepEqual(Object.keys(user).sort(), ["email", "enabled", "id", "mfa", "name", "permissions", "role", "unit"]);
  assert.equal(user.enabled, true);
});
