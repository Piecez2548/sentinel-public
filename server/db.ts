import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export const DATA_DIR = resolve(process.env.DATA_DIR ?? 'data');
export const DB_PATH = resolve(process.env.DB_PATH ?? `${DATA_DIR}/sentinel.db`);
mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');

type Param = string | number | null;

export function all<T>(sql: string, ...params: Param[]): T[] {
  return db.prepare(sql).all(...params) as unknown as T[];
}
export function get<T>(sql: string, ...params: Param[]): T | undefined {
  return db.prepare(sql).get(...params) as unknown as T | undefined;
}
export function run(sql: string, ...params: Param[]) {
  return db.prepare(sql).run(...params);
}
export function tx<T>(fn: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

export function getSetting(key: string): string | undefined {
  return get<{ value: string }>('SELECT value FROM settings WHERE key = ?', key)?.value;
}
export function setSetting(key: string, value: string) {
  run('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, value);
}
export function getJsonSetting<T>(key: string, fallback: T): T {
  const v = getSetting(key);
  if (!v) return fallback;
  try {
    return JSON.parse(v) as T;
  } catch {
    return fallback;
  }
}

/* ------------------------------------------------------------------ */
/* Schema                                                              */
/* ------------------------------------------------------------------ */

const SCHEMA_VERSION = 2;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS admin_account (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,
  totp_secret_enc TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_step INTEGER,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  created_at INTEGER NOT NULL,
  password_changed_at INTEGER NOT NULL,
  pin_hash TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  mfa_pending INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  ip TEXT,
  user_agent TEXT,
  pin_ok INTEGER NOT NULL DEFAULT 1,
  away_at INTEGER,
  pin_failures INTEGER NOT NULL DEFAULT 0,
  vis_seq INTEGER NOT NULL DEFAULT 0
);

-- Fingerprint / Windows Hello (WebAuthn) keys that can unlock the app PIN screen. One row per device.
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  rp_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  label TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('host', 'website')),
  environment TEXT NOT NULL DEFAULT 'production',
  target TEXT,
  tags TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'unknown',
  status_since INTEGER,
  slo_target REAL NOT NULL DEFAULT 99.5,
  notes TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);

CREATE TABLE IF NOT EXISTS http_checks (
  asset_id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
  interval_sec INTEGER NOT NULL DEFAULT 60,
  keyword TEXT,
  expected_status TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_checked_at INTEGER,
  last_latency_ms INTEGER,
  last_status_code INTEGER,
  last_error TEXT,
  tls_expires_at INTEGER,
  tls_checked_at INTEGER,
  headers TEXT,
  headers_checked_at INTEGER
);

CREATE TABLE IF NOT EXISTS check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  status_code INTEGER,
  latency_ms INTEGER,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_check_results_asset_ts ON check_results(asset_id, ts);

CREATE TABLE IF NOT EXISTS host_info (
  asset_id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
  hostname TEXT,
  os TEXT,
  cpu_model TEXT,
  cores INTEGER,
  mem_total INTEGER,
  collector TEXT NOT NULL DEFAULT 'local',
  boot_at INTEGER,
  last_seen_at INTEGER
);

CREATE TABLE IF NOT EXISTS host_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  cpu_pct REAL,
  mem_pct REAL,
  mem_used INTEGER,
  mem_total INTEGER,
  disks TEXT,
  net_rx_bps REAL,
  net_tx_bps REAL,
  battery_pct REAL,
  on_ac INTEGER
);
CREATE INDEX IF NOT EXISTS idx_host_metrics_asset_ts ON host_metrics(asset_id, ts);

CREATE TABLE IF NOT EXISTS log_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  channel TEXT NOT NULL,
  event_id INTEGER NOT NULL,
  record_id INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL DEFAULT 'info',
  category TEXT NOT NULL,
  summary TEXT NOT NULL,
  fields TEXT NOT NULL DEFAULT '{}',
  UNIQUE (asset_id, channel, record_id)
);
CREATE INDEX IF NOT EXISTS idx_log_events_ts ON log_events(ts);
CREATE INDEX IF NOT EXISTS idx_log_events_event_ts ON log_events(event_id, ts);

CREATE TABLE IF NOT EXISTS detection_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  params TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS security_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL REFERENCES detection_rules(id),
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  evidence TEXT NOT NULL DEFAULT '{}',
  resolved_at INTEGER,
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_status_seen ON security_findings(status, last_seen);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON security_findings(fingerprint);

CREATE TABLE IF NOT EXISTS alert_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  params TEXT NOT NULL DEFAULT '{}',
  severity TEXT NOT NULL DEFAULT 'high',
  for_sec INTEGER NOT NULL DEFAULT 0,
  cooldown_sec INTEGER NOT NULL DEFAULT 3600,
  enabled INTEGER NOT NULL DEFAULT 1,
  builtin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'firing',
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT,
  value REAL,
  triggered_at INTEGER NOT NULL,
  acknowledged_at INTEGER,
  resolved_at INTEGER,
  last_notified_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_open_fp ON alert_events(fingerprint) WHERE status != 'resolved';
CREATE INDEX IF NOT EXISTS idx_alert_events_status ON alert_events(status, triggered_at);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  summary TEXT,
  assignee TEXT,
  source TEXT NOT NULL DEFAULT 'manual',
  asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
  opened_at INTEGER NOT NULL,
  acknowledged_at INTEGER,
  resolved_at INTEGER,
  closed_at INTEGER,
  resolution TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, opened_at);

CREATE TABLE IF NOT EXISTS incident_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT,
  message TEXT,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_events ON incident_events(incident_id, ts);

CREATE TABLE IF NOT EXISTS incident_links (
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('alert', 'finding')),
  ref_id INTEGER NOT NULL,
  reason TEXT,
  linked_at INTEGER NOT NULL,
  PRIMARY KEY (incident_id, kind, ref_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_links_ref ON incident_links(kind, ref_id);

CREATE TABLE IF NOT EXISTS notification_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  config_enc TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  ref TEXT,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  sent_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_deliveries_status ON notification_deliveries(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS daily_stats (
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  day TEXT NOT NULL,
  checks_total INTEGER NOT NULL DEFAULT 0,
  checks_ok INTEGER NOT NULL DEFAULT 0,
  latency_avg REAL,
  latency_p95 REAL,
  host_samples INTEGER NOT NULL DEFAULT 0,
  host_expected INTEGER NOT NULL DEFAULT 0,
  cpu_avg REAL,
  cpu_max REAL,
  mem_avg REAL,
  PRIMARY KEY (asset_id, day)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  detail TEXT,
  ip TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs
  BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_logs
  BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;
`;

function tableExists(name: string): boolean {
  return !!get("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", name);
}

/** Prototype (v1) had `sites`, `checks`, `incidents` tables. Move them aside before creating v2. */
function migrateFromPrototype(): boolean {
  if (!tableExists('sites')) return false;
  // Keep an untouched copy of the prototype database before changing anything.
  const copy = resolve(dirname(DB_PATH), `pre-migration-v1-${Date.now()}.db`);
  db.exec(`VACUUM INTO '${copy.replace(/'/g, "''")}'`);
  console.log(`[db] prototype database copied to ${copy}`);
  console.log('[db] migrating prototype data (sites → assets)…');
  db.exec('PRAGMA foreign_keys = OFF');
  tx(() => {
    db.exec('ALTER TABLE sites RENAME TO legacy_sites');
    if (tableExists('checks')) db.exec('ALTER TABLE checks RENAME TO legacy_checks');
    if (tableExists('incidents')) db.exec('ALTER TABLE incidents RENAME TO legacy_incidents');
  });
  db.exec('PRAGMA foreign_keys = ON');
  return true;
}

function importPrototype() {
  type LegacySite = { id: number; name: string; url: string; interval_sec: number; enabled: number; created_at: number; status: string; status_since: number | null; keyword?: string | null };
  const sites = all<LegacySite>('SELECT * FROM legacy_sites');
  tx(() => {
    for (const s of sites) {
      const r = run(
        `INSERT INTO assets (name, type, target, enabled, status, status_since, created_at, updated_at)
         VALUES (?, 'website', ?, ?, ?, ?, ?, ?)`,
        s.name, s.url, s.enabled, s.status === 'up' || s.status === 'down' ? s.status : 'unknown', s.status_since, s.created_at, Date.now(),
      );
      const assetId = Number(r.lastInsertRowid);
      run('INSERT INTO http_checks (asset_id, interval_sec, keyword) VALUES (?, ?, ?)', assetId, s.interval_sec, s.keyword ?? null);
      if (tableExists('legacy_checks')) {
        run(
          `INSERT INTO check_results (asset_id, ts, ok, status_code, latency_ms, error)
           SELECT ?, ts, ok, status_code, latency_ms, error FROM legacy_checks WHERE site_id = ?`,
          assetId, s.id,
        );
      }
    }
  });
  db.exec('DROP TABLE IF EXISTS legacy_checks; DROP TABLE IF EXISTS legacy_incidents; DROP TABLE IF EXISTS legacy_sites;');
  // Old prototype session secret / password env are no longer used.
  run("DELETE FROM settings WHERE key = 'session_secret'");
  console.log(`[db] migrated ${sites.length} website(s) from prototype`);
}

/** Additive column changes for databases created before the column existed. */
function addColumns() {
  const cols = (table: string) => new Set(all<{ name: string }>(`PRAGMA table_info(${table})`).map((c) => c.name));
  const hm = cols('host_metrics');
  if (!hm.has('battery_pct')) db.exec('ALTER TABLE host_metrics ADD COLUMN battery_pct REAL');
  if (!hm.has('on_ac')) db.exec('ALTER TABLE host_metrics ADD COLUMN on_ac INTEGER');
  if (!cols('http_checks').has('expected_status')) db.exec('ALTER TABLE http_checks ADD COLUMN expected_status TEXT');
  // App PIN (2026-11-16): the PIN hash, and per session whether the PIN was entered / when the app was left.
  if (!cols('admin_account').has('pin_hash')) db.exec('ALTER TABLE admin_account ADD COLUMN pin_hash TEXT');
  const se = cols('sessions');
  if (!se.has('pin_ok')) db.exec('ALTER TABLE sessions ADD COLUMN pin_ok INTEGER NOT NULL DEFAULT 1');
  if (!se.has('away_at')) db.exec('ALTER TABLE sessions ADD COLUMN away_at INTEGER');
  if (!se.has('pin_failures')) db.exec('ALTER TABLE sessions ADD COLUMN pin_failures INTEGER NOT NULL DEFAULT 0');
  // Order of "left the app" / "came back" messages (they can arrive out of order).
  if (!se.has('vis_seq')) db.exec('ALTER TABLE sessions ADD COLUMN vis_seq INTEGER NOT NULL DEFAULT 0');
}

export function migrate() {
  const version = (get<{ user_version: number }>('PRAGMA user_version')?.user_version ?? 0) as number;
  if (version >= SCHEMA_VERSION) {
    db.exec(SCHEMA); // idempotent: picks up new indexes/tables
    addColumns();
    return;
  }
  const hadPrototype = migrateFromPrototype();
  db.exec(SCHEMA);
  if (hadPrototype) importPrototype();
  addColumns();
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
}
