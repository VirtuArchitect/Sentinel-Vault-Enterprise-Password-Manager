import express from "express";
import cors from "cors";
import path from "node:path";
import { createServer as createViteServer } from "vite";
import { config, validateConfig } from "./config.mjs";
import { authRoutes } from "./routes/authRoutes.mjs";
import { consoleRoutes } from "./routes/consoleRoutes.mjs";
import { devopsRoutes } from "./routes/devopsRoutes.mjs";
import { errorHandler } from "./middleware/errors.mjs";
import { securityHeaders } from "./middleware/securityHeaders.mjs";
import { startIntegrationDeliveryWorker } from "./services/integrationService.mjs";

export const createApp = async () => {
  const configIssues = validateConfig();
  if (configIssues.length) {
    throw new Error(`Invalid Sentinel Vault configuration: ${configIssues.join(" ")}`);
  }

  const app = express();

  app.use(securityHeaders(config));
  app.use(cors({
    origin(origin, callback) {
      if (!origin || config.corsOrigins.includes(origin)) return callback(null, true);
      const error = new Error("Origin not allowed by Sentinel Vault CORS policy");
      error.status = 403;
      callback(error);
    }
  }));
  app.use(express.json({ limit: "1mb" }));
  app.use("/api", authRoutes);
  app.use("/api", consoleRoutes);
  app.use("/api", devopsRoutes);
  app.use(errorHandler);
  app.get("/healthz", (_req, res) => res.json({ ok: true, service: "sentinel-vault" }));

  if (config.isTest) {
    return app;
  } else if (config.isProduction) {
    app.use(express.static(config.distDir));
    app.get("/{*splat}", (_req, res) => res.sendFile(path.join(config.distDir, "index.html")));
  } else {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
    app.use(vite.middlewares);
  }

  startIntegrationDeliveryWorker();
  return app;
};
