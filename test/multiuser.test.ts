import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks } from "node:module";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

// Production uses Worker bundler resolution for extensionless TS imports.
registerHooks({
  resolve(specifier, context, nextResolve) {
    try { return nextResolve(specifier, context); }
    catch (error) {
      if (specifier.startsWith(".") && !/\.[a-z]+$/i.test(specifier)) {
        return nextResolve(`${specifier}.ts`, context);
      }
      throw error;
    }
  }
});
const storage = await import("../src/storage.ts");

const ALL_MIGRATIONS = [
  "0001_init", "0002_listening_analytics", "0003_indefinite_history", "0004_resource_versions",
  "0005_generic_audit_log", "0006_collector_diagnostics", "0007_collector_control",
  "0008_efficient_maintenance", "0009_migration_archive", "0010_catalog_cache", "0011_multiuser"
];

function database(migrations: string[] = ALL_MIGRATIONS) {
  const sqlite = new DatabaseSync(":memory:");
  for (const migration of migrations) {
    sqlite.exec(readFileSync(new URL(`../migrations/${migration}.sql`, import.meta.url), "utf8"));
  }
  const db = {
    prepare(sql: string) {
      const statement = {
        sql, values: [] as any[],
        bind(...values: any[]) { this.values = values; return this; },
        async first() { return sqlite.prepare(sql).get(...this.values) ?? null; },
        async all() { return { results: sqlite.prepare(sql).all(...this.values) }; },
        async run() {
          const prepared = sqlite.prepare(sql);
          if (/^SELECT/i.test(sql)) return { results: prepared.all(...this.values), meta: { changes: 0 } };
          const result = prepared.run(...this.values);
          return { results: [], meta: { changes: result.changes } };
        }
      };
      return statement;
    }
  };
  return { sqlite, env: { DB: db, TOKEN_ENCRYPTION_KEY: "test-encryption-secret-with-32-plus-bytes-of-material" } as any };
}

test("multiuser migration carries the legacy token row to the primary user", async (t) => {
  const { sqlite, env } = database(["0001_init"]);
  t.after(() => sqlite.close());
  sqlite.prepare("INSERT INTO auth_tokens (provider, encrypted_token_json) VALUES ('apple', 'legacy-ciphertext')").run();
  sqlite.exec(readFileSync(new URL("../migrations/0011_multiuser.sql", import.meta.url), "utf8"));
  const row = sqlite.prepare("SELECT user_id, encrypted_token_json FROM auth_tokens WHERE provider = 'apple'").get() as any;
  assert.equal(row.user_id, "primary");
  assert.equal(row.encrypted_token_json, "legacy-ciphertext");
  const user = sqlite.prepare("SELECT display_name FROM users WHERE id = 'primary'").get() as any;
  assert.equal(user.display_name, "Owner");
  void env;
});

test("apple tokens are stored per user and stay isolated", async (t) => {
  const { sqlite, env } = database();
  t.after(() => sqlite.close());
  await storage.saveAppleToken(env, "primary-token");
  await storage.saveAppleToken(env, "friend-token", "friend1");
  assert.equal((await storage.loadAppleToken(env))?.musicUserToken, "primary-token");
  assert.equal((await storage.loadAppleToken(env, "friend1"))?.musicUserToken, "friend-token");
  assert.equal(await storage.loadAppleToken(env, "nobody"), null);
  assert.equal((await storage.appleTokenStatus(env)).connected, true);
  assert.equal((await storage.appleTokenStatus(env, "friend1")).connected, true);
  assert.equal((await storage.appleTokenStatus(env, "nobody")).connected, false);
  assert.deepEqual(await storage.listConnectedUserIds(env), ["friend1", "primary"]);
  // Overwriting one user never touches the other.
  await storage.saveAppleToken(env, "friend-token-2", "friend1");
  assert.equal((await storage.loadAppleToken(env))?.musicUserToken, "primary-token");
  assert.equal((await storage.loadAppleToken(env, "friend1"))?.musicUserToken, "friend-token-2");
});

test("personal API keys resolve to their user and can be revoked", async (t) => {
  const { sqlite, env } = database();
  t.after(() => sqlite.close());
  await storage.createUser(env, "friend1", "Friend One");
  const key = await storage.createApiKey(env, "friend1", "invite");
  assert.match(key, /^amk_/);
  assert.equal(await storage.resolveApiKey(env, key), "friend1");
  assert.equal(await storage.resolveApiKey(env, "amk_not-a-real-key"), undefined);
  assert.equal(await storage.resolveApiKey(env, "some-other-token"), undefined);
  sqlite.prepare("UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = 'friend1'").run();
  assert.equal(await storage.resolveApiKey(env, key), undefined);
  // The raw key is never stored.
  const row = sqlite.prepare("SELECT key_hash FROM api_keys").get() as any;
  assert.notEqual(row.key_hash, key);
});

test("invites are single-use and expire", async (t) => {
  const { sqlite, env } = database();
  t.after(() => sqlite.close());
  await storage.createUser(env, "friend1", "Friend One");
  const { rawToken } = await storage.createInvite(env, "friend1", "Friend One", 60_000);
  const found = await storage.findInvite(env, rawToken);
  assert.equal(found?.userId, "friend1");
  assert.equal(found?.displayName, "Friend One");
  assert.equal(await storage.consumeInvite(env, rawToken), true);
  assert.equal(await storage.consumeInvite(env, rawToken), false);
  assert.equal(await storage.findInvite(env, rawToken), undefined);

  const expired = await storage.createInvite(env, "friend1", undefined, 60_000);
  sqlite.prepare("UPDATE invites SET expires_at = '2000-01-01T00:00:00.000Z' WHERE user_id = 'friend1' AND used_at IS NULL").run();
  assert.equal(await storage.findInvite(env, expired.rawToken), undefined);
});
