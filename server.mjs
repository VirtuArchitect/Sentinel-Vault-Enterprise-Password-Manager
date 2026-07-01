import { createApp } from "./src/server/app.mjs";
import { config } from "./src/server/config.mjs";
import { logger } from "./src/server/logging/logger.mjs";

const app = await createApp();

app.listen(config.port, config.host, () => {
  logger.info("server.started", {
    url: `http://${config.host}:${config.port}`,
    host: config.host,
    port: config.port,
    environment: process.env.NODE_ENV || "development"
  });
});
