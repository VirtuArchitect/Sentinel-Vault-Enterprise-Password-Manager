# Docker Deployment

Build and run locally:

```bash
docker compose up --build
```

The container runs the production Express server and serves the Vite build from `dist/`.

Set a real `VAULT_ROOT_KEY` through a secret manager or environment injection mechanism before using this outside a local demo.
