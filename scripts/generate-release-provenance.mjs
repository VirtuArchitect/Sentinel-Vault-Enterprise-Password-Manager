import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = args.get("--out") || "artifacts/release/release-provenance.json";
const artifactArgs = cliArgs.flatMap((arg, index) => (arg === "--artifact" ? [cliArgs[index + 1]] : [])).filter(Boolean);
const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
const lockfilePath = "pnpm-lock.yaml";

const sha256File = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("base64url");
const git = (...gitArgs) => execFileSync("git", gitArgs, { encoding: "utf8" }).trim();
const safeGit = (...gitArgs) => {
  try {
    return git(...gitArgs);
  } catch {
    return null;
  }
};

const collectDependencies = () => Object.entries({
  ...(packageJson.dependencies || {}),
  ...(packageJson.devDependencies || {})
}).map(([name, range]) => ({ name, range })).sort((a, b) => a.name.localeCompare(b.name));

const collectArtifacts = () => artifactArgs.map((artifactPath) => {
  if (!existsSync(artifactPath)) {
    return {
      path: artifactPath,
      exists: false,
      sha256: null,
      size: 0
    };
  }
  const stats = statSync(artifactPath);
  return {
    path: path.resolve(artifactPath),
    exists: true,
    sha256: sha256File(artifactPath),
    size: stats.size
  };
});

const provenance = {
  format: "sentinel-release-provenance-v1",
  generatedAt: new Date().toISOString(),
  source: {
    commit: safeGit("rev-parse", "HEAD"),
    branch: safeGit("branch", "--show-current"),
    dirty: Boolean(safeGit("status", "--porcelain")),
    remote: safeGit("remote", "get-url", "origin")
  },
  package: {
    name: packageJson.name,
    version: packageJson.version,
    description: packageJson.description,
    packageManager: packageJson.devEngines?.packageManager || null
  },
  lockfile: {
    path: lockfilePath,
    exists: existsSync(lockfilePath),
    sha256: existsSync(lockfilePath) ? sha256File(lockfilePath) : null
  },
  dependencies: collectDependencies(),
  artifacts: collectArtifacts(),
  requiredChecks: [
    "pnpm verify",
    "pnpm scan:secrets",
    "pnpm audit:deps",
    "pnpm verify:windows:signatures for Windows release artifacts"
  ]
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(provenance, null, 2));
console.log(`Release provenance written: ${outputPath}`);
