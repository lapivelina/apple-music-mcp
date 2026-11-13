import { base64UrlEncode, decryptJson, encryptJson, randomToken } from "./crypto";
import type { AppleTokenSet, Env } from "./types";

export const PRIMARY_USER_ID = "primary";

export async function hashSecret(value: string): Promise<string> {
  return base64UrlEncode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

export async function saveAppleToken(env: Env, musicUserToken: string, userId: string = PRIMARY_USER_ID): Promise<void> {
  const encrypted = await encryptJson(
    { musicUserToken, capturedAt: new Date().toISOString() } satisfies AppleTokenSet,
    env.TOKEN_ENCRYPTION_KEY
  );
  await env.DB.prepare(
    "INSERT INTO auth_tokens (provider, user_id, encrypted_token_json, updated_at) VALUES ('apple', ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(provider, user_id) DO UPDATE SET encrypted_token_json = excluded.encrypted_token_json, updated_at = CURRENT_TIMESTAMP"
  )
    .bind(userId, encrypted)
    .run();
}

export async function loadAppleToken(env: Env, userId: string = PRIMARY_USER_ID): Promise<AppleTokenSet | null> {
  const row = await env.DB.prepare("SELECT encrypted_token_json FROM auth_tokens WHERE provider = 'apple' AND user_id = ?")
    .bind(userId)
    .first<{ encrypted_token_json: string }>();
  if (!row) return null;
  return decryptJson<AppleTokenSet>(row.encrypted_token_json, env.TOKEN_ENCRYPTION_KEY);
}

export async function appleTokenStatus(env: Env, userId: string = PRIMARY_USER_ID): Promise<{ connected: boolean; updatedAt?: string }> {
  const row = await env.DB.prepare("SELECT updated_at FROM auth_tokens WHERE provider = 'apple' AND user_id = ?")
    .bind(userId)
    .first<{ updated_at: string }>();
  return { connected: Boolean(row), updatedAt: row?.updated_at };
}

export async function listConnectedUserIds(env: Env): Promise<string[]> {
  const result = await env.DB.prepare("SELECT user_id FROM auth_tokens WHERE provider = 'apple' ORDER BY user_id")
    .all<{ user_id: string }>();
  return (result.results ?? []).map((row) => row.user_id);
}

export async function createUser(env: Env, userId: string, displayName?: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO users (id, display_name) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET display_name = COALESCE(excluded.display_name, users.display_name)"
  )
    .bind(userId, displayName ?? null)
    .run();
}

export async function createApiKey(env: Env, userId: string, label?: string): Promise<string> {
  const rawKey = `amk_${await randomToken()}`;
  await env.DB.prepare("INSERT INTO api_keys (key_hash, user_id, label) VALUES (?, ?, ?)")
    .bind(await hashSecret(rawKey), userId, label ?? null)
    .run();
  return rawKey;
}

export async function resolveApiKey(env: Env, rawKey: string): Promise<string | undefined> {
  if (!rawKey.startsWith("amk_")) return undefined;
  const row = await env.DB.prepare("SELECT user_id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL")
    .bind(await hashSecret(rawKey))
    .first<{ user_id: string }>();
  return row?.user_id;
}

export interface InviteRecord {
  userId: string;
  displayName?: string;
  expiresAt: string;
}

export async function createInvite(
  env: Env,
  userId: string,
  displayName: string | undefined,
  ttlMs: number
): Promise<{ rawToken: string; expiresAt: string }> {
  const rawToken = await randomToken();
  const expiresAt = new Date(Date.now() + ttlMs).toISOString();
  await env.DB.prepare(
    "INSERT INTO invites (token_hash, user_id, display_name, expires_at) VALUES (?, ?, ?, ?)"
  )
    .bind(await hashSecret(rawToken), userId, displayName ?? null, expiresAt)
    .run();
  return { rawToken, expiresAt };
}

export async function findInvite(env: Env, rawToken: string): Promise<InviteRecord | undefined> {
  const row = await env.DB.prepare(
    "SELECT user_id, display_name, expires_at FROM invites WHERE token_hash = ? AND used_at IS NULL"
  )
    .bind(await hashSecret(rawToken))
    .first<{ user_id: string; display_name: string | null; expires_at: string }>();
  if (!row) return undefined;
  if (Date.parse(row.expires_at) < Date.now()) return undefined;
  return { userId: row.user_id, displayName: row.display_name ?? undefined, expiresAt: row.expires_at };
}

export async function consumeInvite(env: Env, rawToken: string): Promise<boolean> {
  return consumeInviteByHash(env, await hashSecret(rawToken));
}

export async function consumeInviteByHash(env: Env, tokenHash: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE invites SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND used_at IS NULL"
  )
    .bind(tokenHash)
    .run();
  return result.meta.changes === 1;
}

export async function setConfig(env: Env, key: string, value: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP"
  )
    .bind(key, value)
    .run();
}

export async function getConfig(env: Env, key: string): Promise<string | undefined> {
  const row = await env.DB.prepare("SELECT value FROM config WHERE key = ?").bind(key).first<{ value: string }>();
  return row?.value;
}

export async function consumeConfigValue(env: Env, key: string, expectedValue: string): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM config WHERE key = ? AND value = ?")
    .bind(key, expectedValue)
    .run();
  return result.meta.changes === 1;
}

export async function audit(
  env: Env,
  clientId: string,
  toolName: string,
  action: string,
  detail: unknown
): Promise<void> {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_log (client_id, tool_name, action, detail_json) VALUES (?, ?, ?, ?)"
    )
      .bind(clientId, toolName, action, JSON.stringify(detail ?? null))
      .run();
  } catch (error) {
    console.error("Audit insert failed", error instanceof Error ? error.message : String(error));
  }
}

export async function purgeAuditLog(env: Env): Promise<void> {
  const configured = Number(env.AUDIT_RETENTION_DAYS ?? "90");
  const retentionDays = Number.isInteger(configured) && configured >= 1 && configured <= 3650 ? configured : 90;
  await env.DB.prepare("DELETE FROM audit_log WHERE created_at < datetime('now', ?)")
    .bind(`-${retentionDays} days`)
    .run();
}
