import express from "express";
import cors from "cors";
import path from "node:path";
import { createServer as createViteServer } from "vite";
import { config } from "./config.mjs";
import { authRoutes } from "./routes/authRoutes.mjs";
import { consoleRoutes } from "./routes/consoleRoutes.mjs";
import { errorHandler } from "./middleware/errors.mjs";

export const createApp = async () => {
  const app = express();

  app.use(cors());
  app.use(express.json({ limit: "1mb" }));
  app.use("/api", authRoutes);
  app.use("/api", consoleRoutes);
  app.use(errorHandler);

  if (config.isTest) {
    app.get("/healthz", (_req, res) => res.json({ ok: true }));
  } else if (config.isProduction) {
    app.use(express.static(config.distDir));
    app.get("*", (_req, res) => res.sendFile(path.join(config.distDir, "index.html")));
  } else {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
    app.use(vite.middlewares);
  }

  return app;
};
