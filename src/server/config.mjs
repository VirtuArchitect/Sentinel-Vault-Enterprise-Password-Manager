import path from "node:path";
import { fileURLToPath } from "node:url";

export const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

export const config = {
  host: process.env.HOST || "127.0.0.1",
  port: Number(process.env.PORT || 5173),
  isProduction: process.env.NODE_ENV === "production",
  isTest: process.env.NODE_ENV === "test",
  vaultRootKey: process.env.VAULT_ROOT_KEY || "sentinel-demo-root-key",
  sessionMinutes: Number(process.env.SESSION_MINUTES || 15),
  rootDir,
  distDir: path.join(rootDir, "dist")
};
