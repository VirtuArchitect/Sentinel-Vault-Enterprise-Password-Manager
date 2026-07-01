-- Sentinel Vault PostgreSQL schema target.
-- This file is dependency-free migration planning material; runtime Postgres
-- access still requires an approved database driver and deployment target.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sentinel_state (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  data JSONB NOT NULL,
  saved_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT GENERATED ALWAYS AS (lower(data->>'email')) STORED,
  role TEXT GENERATED ALWAYS AS (data->>'role') STORED,
  enabled BOOLEAN GENERATED ALWAYS AS (COALESCE((data->>'enabled')::boolean, true)) STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS device_inventory (
  id TEXT PRIMARY KEY,
  user_id TEXT GENERATED ALWAYS AS (data->>'userId') STORED,
  last_seen_at TIMESTAMPTZ GENERATED ALWAYS AS (NULLIF(data->>'lastSeenAt', '')::timestamptz) STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  parent_id TEXT GENERATED ALWAYS AS (NULLIF(data->>'parentId', '')) STORED,
  classification TEXT GENERATED ALWAYS AS (data->>'classification') STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  classification TEXT GENERATED ALWAYS AS (data->>'classification') STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL,
  risk TEXT,
  deleted_at TIMESTAMPTZ,
  fingerprint TEXT GENERATED ALWAYS AS (data->>'fingerprint') STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS service_tokens (
  id TEXT PRIMARY KEY,
  revoked_at TIMESTAMPTZ,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_imports (
  id TEXT PRIMARY KEY,
  status TEXT,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS access_requests (
  id TEXT PRIMARY KEY,
  secret_id TEXT NOT NULL,
  requester_id TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at TIMESTAMPTZ GENERATED ALWAYS AS (NULLIF(data->>'expiresAt', '')::timestamptz) STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS integration_outbox (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  next_attempt_at TIMESTAMPTZ GENERATED ALWAYS AS (NULLIF(data->>'nextAttemptAt', '')::timestamptz) STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  action TEXT NOT NULL,
  actor TEXT,
  hash TEXT GENERATED ALWAYS AS (data->>'hash') STORED,
  previous_hash TEXT GENERATED ALWAYS AS (data->>'previousHash') STORED,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_vaults_tenant_id ON vaults(tenant_id);
CREATE INDEX IF NOT EXISTS idx_secrets_vault_id ON secrets(vault_id);
CREATE INDEX IF NOT EXISTS idx_secrets_active ON secrets(vault_id, risk) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_access_requests_secret_status ON access_requests(secret_id, status);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester_status ON access_requests(requester_id, status);
CREATE INDEX IF NOT EXISTS idx_integration_outbox_target_status ON integration_outbox(target, status);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);

INSERT INTO schema_migrations (version, description)
VALUES (1, 'initial sentinel vault jsonb mirror schema')
ON CONFLICT (version) DO NOTHING;

COMMIT;
