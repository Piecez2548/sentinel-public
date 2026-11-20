import { Router } from 'express';
import { all, get, run, tx } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { body, clientIp, HttpError, idParam, num, str } from '../lib/http.js';
import { stepUp } from './auth.js';
import { securityNotice } from './notify.js';
import { parseStatusSpec } from '../lib/checker.js';
import { assertUrlAllowed } from '../lib/ssrf.js';
import { DAY, HOUR, parseJson } from '../lib/util.js';
import { runHttpCheck } from './http-monitor.js';
import type { DiskSample } from './host-collector.js';

/** Asset inventory (FR-02) + per-asset telemetry series. */

export const assetsRouter = Router();

type AssetRow = {
  id: number; name: string; type: 'host' | 'website'; environment: string; target: string | null; tags: string; enabled: number;
  status: string; status_since: number | null; slo_target: number; notes: string | null; created_at: number; updated_at: number;
};

function uptime(assetId: number, sinceMs: number): number | null {
  const r = get<{ total: number; ok: number }>('SELECT COUNT(*) AS total, SUM(ok) AS ok FROM check_results WHERE asset_id = ? AND ts > ?', assetId, Date.now() - sinceMs);
  return r && r.total ? (r.ok / r.total) * 100 : null;
}

function assetDto(a: AssetRow) {
  const base = {
    id: a.id,
    name: a.name,
    type: a.type,
    environment: a.environment,
    target: a.target,
    tags: parseJson<string[]>(a.tags, []),
    enabled: !!a.enabled,
    status: a.enabled ? a.status : 'paused',
    statusSince: a.status_since,
    sloTarget: a.slo_target,
    notes: a.notes,
    createdAt: a.created_at,
    activeAlerts: get<{ n: number }>("SELECT COUNT(*) AS n FROM alert_events WHERE asset_id = ? AND status != 'resolved'", a.id)?.n ?? 0,
    openFindings: get<{ n: number }>("SELECT COUNT(*) AS n FROM security_findings WHERE asset_id = ? AND status IN ('open','acknowledged')", a.id)?.n ?? 0,
  };
  if (a.type === 'website') {
    const h = get<{ interval_sec: number; keyword: string | null; expected_status: string | null; last_checked_at: number | null; last_latency_ms: number | null; last_status_code: number | null; last_error: string | null; tls_expires_at: number | null; headers: string | null }>(
      'SELECT * FROM http_checks WHERE asset_id = ?', a.id,
    );
    const lat = get<{ avg: number | null }>('SELECT AVG(latency_ms) AS avg FROM check_results WHERE asset_id = ? AND ok = 1 AND ts > ?', a.id, Date.now() - DAY)?.avg;
    return {
      ...base,
      website: {
        intervalSec: h?.interval_sec ?? 60,
        keyword: h?.keyword ?? null,
        expectedStatus: h?.expected_status ?? null,
        lastCheckedAt: h?.last_checked_at ?? null,
        lastLatencyMs: h?.last_latency_ms ?? null,
        lastStatusCode: h?.last_status_code ?? null,
        lastError: h?.last_error ?? null,
        tlsExpiresAt: h?.tls_expires_at ?? null,
        headers: parseJson<Record<string, string | null> | null>(h?.headers, null),
        uptime24h: uptime(a.id, DAY),
        uptime30d: uptime(a.id, 30 * DAY),
        avgLatency24h: lat != null ? Math.round(lat) : null,
      },
    };
  }
  const info = get<{ hostname: string | null; os: string | null; cpu_model: string | null; cores: number | null; mem_total: number | null; collector: string; boot_at: number | null; last_seen_at: number | null }>(
    'SELECT * FROM host_info WHERE asset_id = ?', a.id,
  );
  const m = get<{ ts: number; cpu_pct: number | null; mem_pct: number | null; mem_used: number | null; mem_total: number | null; disks: string; net_rx_bps: number | null; net_tx_bps: number | null; battery_pct: number | null; on_ac: number | null }>(
    'SELECT * FROM host_metrics WHERE asset_id = ? ORDER BY ts DESC LIMIT 1', a.id,
  );
  return {
    ...base,
    host: {
      hostname: info?.hostname ?? null,
      os: info?.os ?? null,
      cpuModel: info?.cpu_model ?? null,
      cores: info?.cores ?? null,
      memTotal: info?.mem_total ?? null,
      collector: info?.collector ?? 'local',
      bootAt: info?.boot_at ?? null,
      lastSeenAt: info?.last_seen_at ?? null,
      latest: m
        ? { ts: m.ts, cpuPct: m.cpu_pct, memPct: m.mem_pct, memUsed: m.mem_used, memTotal: m.mem_total, disks: parseJson<DiskSample[]>(m.disks, []), netRxBps: m.net_rx_bps, netTxBps: m.net_tx_bps, batteryPct: m.battery_pct, onAc: m.on_ac == null ? null : m.on_ac === 1 }
        : null,
      securityEvents24h: get<{ n: number }>('SELECT COUNT(*) AS n FROM log_events WHERE asset_id = ? AND ts > ?', a.id, Date.now() - DAY)?.n ?? 0,
    },
  };
}

assetsRouter.get('/', (req, res) => {
  const type = req.query.type === 'host' || req.query.type === 'website' ? String(req.query.type) : null;
  const rows = all<AssetRow>(`SELECT * FROM assets ${type ? 'WHERE type = ?' : ''} ORDER BY type, name COLLATE NOCASE`, ...(type ? [type] : []));
  res.json({ assets: rows.map(assetDto) });
});

assetsRouter.get('/:id', (req, res) => {
  const a = get<AssetRow>('SELECT * FROM assets WHERE id = ?', idParam(req));
  if (!a) throw new HttpError(404, 'Not found');
  res.json({ asset: assetDto(a) });
});

function parseTags(v: unknown): string[] {
  if (v === undefined) return [];
  const list = Array.isArray(v) ? v : String(v).split(',');
  return [...new Set(list.map((t) => String(t).trim().toLowerCase()).filter((t) => /^[a-z0-9_.-]{1,30}$/.test(t)))].slice(0, 10);
}

function parseUrl(v: unknown): string {
  const raw = str(v, 'URL', { max: 2000 })!;
  try {
    return assertUrlAllowed(raw).toString();
  } catch (e) {
    throw new HttpError(400, e instanceof Error && !/Invalid URL/.test(e.message) ? e.message : 'Invalid URL');
  }
}

function parseExpected(v: unknown): string | null {
  const s = str(v, 'Expected HTTP status', { optional: true, max: 60 });
  if (!s) return null;
  if (!parseStatusSpec(s)) throw new HttpError(400, 'Expected HTTP status must look like "200" or "200-299,401"');
  return s.replace(/\s+/g, '');
}

assetsRouter.post('/', (req, res) => {
  const b = body(req);
  if (b.type !== 'website') throw new HttpError(400, 'Only website assets can be added here; this PC is registered automatically');
  const name = str(b.name, 'Name', { min: 1, max: 80 })!;
  const url = parseUrl(b.url);
  const interval = num(b.intervalSec ?? 60, 'Interval', { min: 30, max: 3600, int: true })!;
  const keyword = str(b.keyword, 'Keyword', { optional: true, max: 200 }) ?? null;
  const expectedStatus = parseExpected(b.expectedStatus);
  const env = str(b.environment, 'Environment', { optional: true, max: 30 }) ?? 'production';
  const slo = num(b.sloTarget ?? 99.5, 'SLO target', { min: 50, max: 100 })!;
  const now = Date.now();
  const id = tx(() => {
    const r = run(
      "INSERT INTO assets (name, type, environment, target, tags, slo_target, notes, created_at, updated_at) VALUES (?, 'website', ?, ?, ?, ?, ?, ?, ?)",
      name, env, url, JSON.stringify(parseTags(b.tags)), slo, str(b.notes, 'Notes', { optional: true, max: 1000 }) ?? null, now, now,
    );
    const assetId = Number(r.lastInsertRowid);
    run('INSERT INTO http_checks (asset_id, interval_sec, keyword, expected_status) VALUES (?, ?, ?, ?)', assetId, interval, keyword, expectedStatus);
    return assetId;
  });
  audit('asset.created', { ip: clientIp(req), resourceType: 'asset', resourceId: id, detail: { name, url } });
  publish('assets');
  void runHttpCheck(id).catch(() => {});
  res.status(201).json({ id });
});

assetsRouter.put('/:id', (req, res) => {
  const id = idParam(req);
  const a = get<AssetRow>('SELECT * FROM assets WHERE id = ?', id);
  if (!a) throw new HttpError(404, 'Not found');
  const b = body(req);
  const name = str(b.name, 'Name', { optional: true, min: 1, max: 80 }) ?? a.name;
  const env = str(b.environment, 'Environment', { optional: true, max: 30 }) ?? a.environment;
  const slo = b.sloTarget !== undefined ? num(b.sloTarget, 'SLO target', { min: 50, max: 100 })! : a.slo_target;
  const enabled = b.enabled !== undefined ? (b.enabled ? 1 : 0) : a.enabled;
  const tags = b.tags !== undefined ? JSON.stringify(parseTags(b.tags)) : a.tags;
  const notes = b.notes !== undefined ? (str(b.notes, 'Notes', { optional: true, max: 1000 }) ?? null) : a.notes;
  let target = a.target;
  tx(() => {
    if (a.type === 'website') {
      if (b.url !== undefined) target = parseUrl(b.url);
      const h = get<{ interval_sec: number; keyword: string | null; expected_status: string | null }>('SELECT interval_sec, keyword, expected_status FROM http_checks WHERE asset_id = ?', id);
      const interval = b.intervalSec !== undefined ? num(b.intervalSec, 'Interval', { min: 30, max: 3600, int: true })! : (h?.interval_sec ?? 60);
      const keyword = b.keyword !== undefined ? (str(b.keyword, 'Keyword', { optional: true, max: 200 }) ?? null) : (h?.keyword ?? null);
      const expectedStatus = b.expectedStatus !== undefined ? parseExpected(b.expectedStatus) : (h?.expected_status ?? null);
      run('UPDATE http_checks SET interval_sec = ?, keyword = ?, expected_status = ? WHERE asset_id = ?', interval, keyword, expectedStatus, id);
      if (target !== a.target) run('UPDATE http_checks SET tls_expires_at = NULL, tls_checked_at = NULL, headers = NULL, headers_checked_at = NULL, consecutive_failures = 0 WHERE asset_id = ?', id);
    }
    run('UPDATE assets SET name = ?, environment = ?, target = ?, tags = ?, slo_target = ?, enabled = ?, notes = ?, updated_at = ? WHERE id = ?', name, env, target, tags, slo, enabled, notes, Date.now(), id);
    if (!enabled && a.enabled) run("UPDATE assets SET status = 'unknown', status_since = NULL WHERE id = ?", id);
  });
  audit('asset.updated', { ip: clientIp(req), resourceType: 'asset', resourceId: id, detail: { name, target, enabled: !!enabled } });
  publish('assets');
  if (a.type === 'website' && enabled) void runHttpCheck(id).catch(() => {});
  res.json({ ok: true });
});

assetsRouter.delete('/:id', stepUp, (req, res) => {
  const id = idParam(req);
  const a = get<AssetRow>('SELECT * FROM assets WHERE id = ?', id);
  if (!a) throw new HttpError(404, 'Not found');
  if (a.type === 'host' && a.target === 'local') throw new HttpError(400, 'This PC is monitored by the built-in collector. Pause it instead, or disable the collector in Settings.');
  run('DELETE FROM assets WHERE id = ?', id);
  audit('asset.deleted', { ip: clientIp(req), resourceType: 'asset', resourceId: id, detail: { name: a.name } });
  securityNotice(`stopped monitoring "${a.name}"`, `เลิกเฝ้าระวัง "${a.name}"`, req);
  publish('assets', 'alerts', 'findings');
  res.json({ ok: true });
});

assetsRouter.post('/:id/check', async (req, res) => {
  const id = idParam(req);
  if (!get("SELECT id FROM assets WHERE id = ? AND type = 'website'", id)) throw new HttpError(404, 'Not found');
  await runHttpCheck(id);
  res.json({ ok: true });
});

/* ---------- series ---------- */

const hoursParam = (v: unknown) => Math.min(Math.max(Number(v) || 24, 1), 24 * 15);

assetsRouter.get('/:id/checks', (req, res) => {
  const id = idParam(req);
  const hours = hoursParam(req.query.hours);
  const bucket = Math.max(60_000, Math.round((hours * HOUR) / 240));
  const rows = all<{ t: number; latency: number | null; ok: number; n: number }>(
    `SELECT (ts / ?) * ? AS t, AVG(CASE WHEN ok = 1 THEN latency_ms END) AS latency, MIN(ok) AS ok, COUNT(*) AS n
     FROM check_results WHERE asset_id = ? AND ts >= ? GROUP BY t ORDER BY t`,
    bucket, bucket, id, Date.now() - hours * HOUR,
  );
  res.json({ bucketMs: bucket, points: rows.map((p) => ({ t: p.t, latency: p.latency == null ? null : Math.round(p.latency), ok: !!p.ok })) });
});

assetsRouter.get('/:id/recent', (req, res) => {
  const rows = all<{ ts: number; ok: number; status_code: number | null; latency_ms: number | null; error: string | null }>(
    'SELECT ts, ok, status_code, latency_ms, error FROM check_results WHERE asset_id = ? ORDER BY ts DESC LIMIT ?',
    idParam(req), Math.min(Number(req.query.limit) || 15, 100),
  );
  res.json({ checks: rows.map((r) => ({ ts: r.ts, ok: !!r.ok, statusCode: r.status_code, latencyMs: r.latency_ms, error: r.error })) });
});

assetsRouter.get('/:id/metrics', (req, res) => {
  const id = idParam(req);
  const hours = hoursParam(req.query.hours);
  const bucket = Math.max(60_000, Math.round((hours * HOUR) / 240));
  const rows = all<{ t: number; cpu: number | null; cpu_max: number | null; mem: number | null; rx: number | null; tx: number | null; disks: string | null }>(
    `SELECT (ts / ?) * ? AS t, AVG(cpu_pct) AS cpu, MAX(cpu_pct) AS cpu_max, AVG(mem_pct) AS mem, AVG(net_rx_bps) AS rx, AVG(net_tx_bps) AS tx, MAX(disks) AS disks
     FROM host_metrics WHERE asset_id = ? AND ts >= ? GROUP BY t ORDER BY t`,
    bucket, bucket, id, Date.now() - hours * HOUR,
  );
  const r1 = (v: number | null) => (v == null ? null : Math.round(v * 10) / 10);
  res.json({
    bucketMs: bucket,
    points: rows.map((p) => ({
      t: p.t,
      cpu: r1(p.cpu),
      cpuMax: r1(p.cpu_max),
      mem: r1(p.mem),
      rxBps: p.rx == null ? null : Math.round(p.rx),
      txBps: p.tx == null ? null : Math.round(p.tx),
      diskMaxPct: Math.max(0, ...parseJson<DiskSample[]>(p.disks, []).map((d) => d.usedPct)),
    })),
  });
});
