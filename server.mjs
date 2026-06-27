import { createApp } from "./src/server/app.mjs";
import { config } from "./src/server/config.mjs";

const app = await createApp();

app.listen(config.port, config.host, () => {
  console.log(`Sentinel Vault Console running at http://${config.host}:${config.port}`);
});
