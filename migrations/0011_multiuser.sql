-- Multi-user support: per-user Apple Music tokens, personal API keys, invites.
-- The existing deployment's data belongs to the built-in "primary" user.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY NOT NULL,
  display_name TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO users (id, display_name) VALUES ('primary', 'Owner');

CREATE TABLE IF NOT EXISTS auth_tokens_new (
  provider TEXT NOT NULL,
  user_id TEXT NOT NULL DEFAULT 'primary',
  encrypted_token_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (provider, user_id)
);

INSERT INTO auth_tokens_new (provider, user_id, encrypted_token_json, updated_at)
  SELECT provider, 'primary', encrypted_token_json, updated_at FROM auth_tokens;

DROP TABLE auth_tokens;
ALTER TABLE auth_tokens_new RENAME TO auth_tokens;

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  label TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS invites (
  token_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  display_name TEXT,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
