import { Router } from 'express';
import { all, get, getSetting, run, setSetting } from '../db.js';
import { audit, verifyAuditChain } from '../lib/audit.js';
import { publish, subscribe } from '../lib/bus.js';
import { getHealth } from '../lib/health.js';
import { componentText, notifyLang, sevText } from '../lib/i18n.js';
import { body, clientIp, HttpError, num, oneOf } from '../lib/http.js';
import { stepUp } from './auth.js';
import { securityNotice } from './notify.js';
import { DAY, escHtml, HOUR, parseJson, SEVERITIES } from '../lib/util.js';
import { ALERT_SELECT, alertDto } from './alerts.js';
import { lastEventlogIngest } from './eventlog.js';

import { plainFinding } from '../lib/finding-plain.js';
/** Overview, Log Explorer, settings, health, audit log, SSE stream, retention, digest. */

export const systemRouter = Router();

/* ---------- overview ---------- */

systemRouter.get('/overview', (_req, res) => {
  const now = Date.now();
  const assets = all<{ type: string; status: string; enabled: number }>('SELECT type, status, enabled FROM assets');
  const count = (pred: (a: (typeof assets)[number]) => boolean) => assets.filter(pred).length;

  const activeAlerts = all<Parameters<typeof alertDto>[0]>(`${ALERT_SELECT} WHERE e.status != 'resolved' ORDER BY e.triggered_at DESC LIMIT 20`).map(alertDto);
  const findingsOpen = all<{ severity: string; n: number }>("SELECT severity, COUNT(*) AS n FROM security_findings WHERE status IN ('open','acknowledged') GROUP BY severity");
  const recentFindings = all<{ id: number; rule_id: string; title: string; summary: string; evidence: string; severity: string; last_seen: number; asset_name: string | null; status: string }>(
    "SELECT f.id, f.rule_id, f.title, f.summary, f.evidence, f.severity, f.last_seen, f.status, a.name AS asset_name FROM security_findings f LEFT JOIN assets a ON a.id = f.asset_id WHERE f.status IN ('open','acknowledged') ORDER BY f.last_seen DESC LIMIT 8",
  );
  const incidents = all<{ id: number; title: string; severity: string; status: string; opened_at: number }>(
    'SELECT id, title, severity, status, opened_at FROM incidents ORDER BY opened_at DESC LIMIT 8',
  );
  const eventsByCategory = all<{ category: string; n: number }>('SELECT category, COUNT(*) AS n FROM log_events WHERE ts > ? GROUP BY category ORDER BY n DESC', now - DAY);
  const eventsHourly = all<{ h: number; category: string; n: number }>(
    'SELECT (ts / 3600000) * 3600000 AS h, category, COUNT(*) AS n FROM log_events WHERE ts > ? GROUP BY h, category ORDER BY h',
    now - DAY,
  );
  const up24 = get<{ total: number; ok: number; lat: number | null }>(
    'SELECT COUNT(*) AS total, SUM(ok) AS ok, AVG(CASE WHEN ok=1 THEN latency_ms END) AS lat FROM check_results WHERE ts > ?', now - DAY,
  );

  res.json({
    assets: {
      total: assets.length,
      hosts: count((a) => a.type === 'host'),
      websites: count((a) => a.type === 'website'),
      up: count((a) => !!a.enabled && a.status === 'up'),
      down: count((a) => !!a.enabled && a.status === 'down'),
      unknown: count((a) => !!a.enabled && a.status === 'unknown'),
      paused: count((a) => !a.enabled),
    },
    websites24h: { uptime: up24?.total ? (up24.ok / up24.total) * 100 : null, avgLatency: up24?.lat != null ? Math.round(up24.lat) : null },
    alerts: { active: activeAlerts, bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, activeAlerts.filter((a) => a.severity === s).length])) },
    findings: {
      openBySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, findingsOpen.find((f) => f.severity === s)?.n ?? 0])),
      recent: recentFindings.map((f) => ({ id: f.id, title: f.title, plainTh: plainFinding({ ruleId: f.rule_id, severity: f.severity, title: f.title, summary: f.summary, evidence: parseJson(f.evidence, {}) }), severity: f.severity, lastSeen: f.last_seen, assetName: f.asset_name, status: f.status })),
    },
    incidents: {
      open: get<{ n: number }>("SELECT COUNT(*) AS n FROM incidents WHERE status IN ('open','acknowledged','investigating')")?.n ?? 0,
      recent: incidents.map((i) => ({ id: i.id, title: i.title, severity: i.severity, status: i.status, openedAt: i.opened_at })),
    },
    security24h: {
      byCategory: eventsByCategory.map((e) => ({ category: e.category, count: e.n })),
      hourly: eventsHourly.map((e) => ({ t: e.h, category: e.category, count: e.n })),
      failedLogons: get<{ n: number }>('SELECT COUNT(*) AS n FROM log_events WHERE event_id = 4625 AND ts > ?', now - DAY)?.n ?? 0,
    },
    health: getHealth(),
  });
});

/* ---------- Log Explorer (with query limits) ---------- */

const MAX_SPAN = 14 * DAY;
const MAX_LIMIT = 500;

systemRouter.get('/logs', (req, res) => {
  const q = req.query;
  const to = q.to ? Number(q.to) : Date.now();
  const from = q.from ? Number(q.from) : to - DAY;
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to) throw new HttpError(400, 'Invalid time range');
  if (to - from > MAX_SPAN) throw new HttpError(400, 'Time range is limited to 14 days');
  const limit = Math.min(Number(q.limit) || 200, MAX_LIMIT);
  const where = ['ts >= ?', 'ts <= ?'];
  const params: (string | number)[] = [from, to];
  if (q.eventId) {
    const ids = String(q.eventId).split(',').map(Number).filter(Number.isInteger).slice(0, 20);
    if (ids.length) where.push(`event_id IN (${ids.map(() => '?').join(',')})`), params.push(...ids);
  }
  if (q.category) where.push('category = ?'), params.push(String(q.category));
  if (q.level) where.push('level = ?'), params.push(String(q.level));
  if (q.channel) where.push('channel = ?'), params.push(String(q.channel));
  if (q.assetId) where.push('asset_id = ?'), params.push(Number(q.assetId));
  if (q.q) {
    const text = String(q.q).slice(0, 100).replace(/[\\%_]/g, (c) => `\\${c}`);
    where.push("(summary LIKE ? ESCAPE '\\' OR fields LIKE ? ESCAPE '\\')");
    params.push(`%${text}%`, `%${text}%`);
  }
  const total = get<{ n: number }>(`SELECT COUNT(*) AS n FROM log_events WHERE ${where.join(' AND ')}`, ...params)?.n ?? 0;
  // Keyset pagination: rows older than the last one shown (ordered by ts, id).
  const pageWhere = [...where];
  const pageParams = [...params];
  if (q.before) {
    const cur = get<{ ts: number }>('SELECT ts FROM log_events WHERE id = ?', Number(q.before));
    if (cur) pageWhere.push('(ts < ? OR (ts = ? AND id < ?))'), pageParams.push(cur.ts, cur.ts, Number(q.before));
  }
  const rows = all<{ id: number; asset_id: number; channel: string; event_id: number; record_id: number; ts: number; level: string; category: string; summary: string; fields: string }>(
    `SELECT * FROM log_events WHERE ${pageWhere.join(' AND ')} ORDER BY ts DESC, id DESC LIMIT ?`,
    ...pageParams, limit + 1,
  );
  const more = rows.length > limit;
  const page = rows.slice(0, limit);
  res.json({
    events: page.map((e) => ({ id: e.id, assetId: e.asset_id, channel: e.channel, eventId: e.event_id, recordId: e.record_id, ts: e.ts, level: e.level, category: e.category, summary: e.summary, fields: parseJson(e.fields, {}) })),
    nextBefore: more ? page[page.length - 1].id : null,
    total,
    limits: { maxSpanDays: 14, maxLimit: MAX_LIMIT },
  });
});

systemRouter.get('/logs/facets', (_req, res) => {
  res.json({
    categories: all<{ category: string; n: number }>('SELECT category, COUNT(*) AS n FROM log_events GROUP BY category ORDER BY n DESC').map((r) => ({ value: r.category, count: r.n })),
    eventIds: all<{ event_id: number; n: number }>('SELECT event_id, COUNT(*) AS n FROM log_events GROUP BY event_id ORDER BY n DESC').map((r) => ({ value: r.event_id, count: r.n })),
    channels: all<{ channel: string; n: number }>('SELECT channel, COUNT(*) AS n FROM log_events GROUP BY channel ORDER BY n DESC').map((r) => ({ value: r.channel, count: r.n })),
  });
});

/* ---------- settings ---------- */

const SETTING_KEYS = {
  digest_enabled: 'bool',
  digest_hour: 'hour',
  backup_hour: 'hour',
  notify_finding_min_severity: 'severity',
  local_collector_enabled: 'bool',
  eventlog_enabled: 'bool',
  language: 'lang',
} as const;

function readSettings() {
  return {
    digestEnabled: getSetting('digest_enabled') !== 'false',
    digestHour: Number(getSetting('digest_hour') ?? 8),
    backupHour: Number(getSetting('backup_hour') ?? 3),
    notifyFindingMinSeverity: getSetting('notify_finding_min_severity') ?? 'medium',
    localCollectorEnabled: getSetting('local_collector_enabled') !== 'false',
    eventlogEnabled: getSetting('eventlog_enabled') !== 'false',
    language: notifyLang(),
    platform: process.platform,
  };
}

systemRouter.get('/settings', (_req, res) => res.json(readSettings()));

systemRouter.put('/settings', stepUp, (req, res) => {
  const b = body(req);
  const map: Record<string, keyof typeof SETTING_KEYS> = {
    digestEnabled: 'digest_enabled', digestHour: 'digest_hour', backupHour: 'backup_hour',
    notifyFindingMinSeverity: 'notify_finding_min_severity', localCollectorEnabled: 'local_collector_enabled', eventlogEnabled: 'eventlog_enabled', language: 'language',
  };
  const changed: Record<string, unknown> = {};
  for (const [k, key] of Object.entries(map)) {
    if (b[k] === undefined) continue;
    const kind = SETTING_KEYS[key];
    const v = kind === 'bool' ? String(!!b[k]) : kind === 'hour' ? String(num(b[k], k, { min: 0, max: 23, int: true })) : kind === 'lang' ? oneOf(b[k], k, ['th', 'en'] as const)! : oneOf(b[k], k, SEVERITIES)!;
    setSetting(key, v);
    changed[k] = v;
  }
  audit('settings.updated', { ip: clientIp(req), detail: changed });
  const off = (['localCollectorEnabled', 'eventlogEnabled'] as const).filter((k) => changed[k] === 'false');
  if (off.length) securityNotice(`monitoring turned off (${off.join(', ')})`, `ปิดการเฝ้าระวัง (${off.map((k) => (k === 'eventlogEnabled' ? 'Event Log' : 'ข้อมูลเครื่อง')).join(', ')})`, req);
  publish('settings');
  res.json(readSettings());
});

/* ---------- health, audit ---------- */

systemRouter.get('/health', (_req, res) => {
  const pendingDeliveries = get<{ n: number }>("SELECT COUNT(*) AS n FROM notification_deliveries WHERE status = 'pending'")?.n ?? 0;
  const failedDeliveries24h = get<{ n: number }>("SELECT COUNT(*) AS n FROM notification_deliveries WHERE status = 'failed' AND created_at > ?", Date.now() - DAY)?.n ?? 0;
  const channels = get<{ n: number }>('SELECT COUNT(*) AS n FROM notification_channels WHERE enabled = 1')?.n ?? 0;
  res.json({
    components: getHealth(),
    notifications: { channels, pendingDeliveries, failedDeliveries24h },
    eventlog: lastEventlogIngest(),
    uptimeSec: Math.round(process.uptime()),
    memoryMb: Math.round(process.memoryUsage().rss / 1e6),
  });
});

systemRouter.get('/audit', (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const before = req.query.before ? Number(req.query.before) : null;
  const rows = all<{ seq: number; ts: number; action: string; resource_type: string | null; resource_id: string | null; detail: string | null; ip: string | null; hash: string }>(
    `SELECT seq, ts, action, resource_type, resource_id, detail, ip, hash FROM audit_logs ${before ? 'WHERE seq < ?' : ''} ORDER BY seq DESC LIMIT ?`,
    ...(before ? [before, limit] : [limit]),
  );
  res.json({
    entries: rows.map((r) => ({ seq: r.seq, ts: r.ts, action: r.action, resourceType: r.resource_type, resourceId: r.resource_id, detail: parseJson(r.detail, null), ip: r.ip, hash: r.hash.slice(0, 12) })),
    nextBefore: rows.length === limit ? rows[rows.length - 1].seq : null,
  });
});

systemRouter.get('/audit/verify', (_req, res) => res.json(verifyAuditChain()));

/* ---------- SSE ---------- */

systemRouter.get('/stream', (req, res) => {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', 'x-accel-buffering': 'no' });
  res.write('retry: 5000\n\n');
  const unsub = subscribe((topics) => res.write(`data: ${JSON.stringify({ topics })}\n\n`));
  const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
  req.on('close', () => {
    unsub();
    clearInterval(ping);
  });
});

/* ---------- retention (NFR-05) ---------- */

export function runRetention() {
  const now = Date.now();
  run('DELETE FROM host_metrics WHERE ts < ?', now - 15 * DAY);
  run('DELETE FROM check_results WHERE ts < ?', now - 15 * DAY);
  run('DELETE FROM log_events WHERE ts < ?', now - 14 * DAY);
  run("DELETE FROM alert_events WHERE status = 'resolved' AND resolved_at < ?", now - 90 * DAY);
  run("DELETE FROM security_findings WHERE status IN ('resolved','false_positive') AND last_seen < ?", now - 90 * DAY);
  run("DELETE FROM notification_deliveries WHERE created_at < ? AND status != 'pending'", now - 90 * DAY);
  run("DELETE FROM incidents WHERE status = 'closed' AND closed_at < ?", now - 365 * DAY);
  run('DELETE FROM daily_stats WHERE day < ?', new Date(now - 400 * DAY).toISOString().slice(0, 10));
}

/* ---------- daily digest ---------- */

export function buildDigest(): string {
  const now = Date.now();
  const assets = all<{ name: string; status: string; type: string }>('SELECT name, status, type FROM assets WHERE enabled = 1');
  const down = assets.filter((a) => a.status === 'down');
  const alerts24 = get<{ n: number }>('SELECT COUNT(*) AS n FROM alert_events WHERE triggered_at > ?', now - DAY)?.n ?? 0;
  const active = get<{ n: number }>("SELECT COUNT(*) AS n FROM alert_events WHERE status != 'resolved'")?.n ?? 0;
  const findings24 = all<{ severity: string; n: number }>('SELECT severity, COUNT(*) AS n FROM security_findings WHERE first_seen > ? GROUP BY severity', now - DAY);
  const failed = get<{ n: number }>('SELECT COUNT(*) AS n FROM log_events WHERE event_id = 4625 AND ts > ?', now - DAY)?.n ?? 0;
  const incidentsOpen = get<{ n: number }>("SELECT COUNT(*) AS n FROM incidents WHERE status IN ('open','acknowledged','investigating')")?.n ?? 0;
  const unhealthy = getHealth().filter((c) => !c.ok);
  if (notifyLang() === 'th') {
    return [
      '📋 <b>SENTINEL สรุปประจำวัน</b>',
      `สิ่งที่เฝ้าดู: ปกติ ${assets.length - down.length}/${assets.length}${down.length ? ` — ล่ม: ${escHtml(down.map((d) => d.name).join(', '))}` : ''}`,
      `การแจ้งเตือน (24 ชม.): ${alerts24} · กำลังเกิดอยู่: ${active}`,
      `สิ่งที่ตรวจพบด้านความปลอดภัย (24 ชม.): ${findings24.length ? findings24.map((f) => `${sevText(f.severity)} ${f.n}`).join(', ') : 'ไม่มี'}`,
      `ล็อกอิน Windows ล้มเหลว (24 ชม.): ${failed}`,
      `เหตุการณ์ที่ยังเปิด: ${incidentsOpen}`,
      unhealthy.length ? `⚠️ ระบบเฝ้าระวังมีปัญหา: ${escHtml(unhealthy.map((c) => `${componentText(c.label)}: ${c.message}`).join('; '))}` : '✅ ระบบเฝ้าระวังทุกส่วนทำงานปกติ',
      '<i>ถ้าวันไหนไม่ได้รับข้อความนี้ แปลว่า SENTINEL หยุดทำงาน</i>',
    ].join('\n');
  }
  const lines = [
    '📋 <b>SENTINEL daily summary</b>',
    `Assets: ${assets.length - down.length}/${assets.length} up${down.length ? ` — DOWN: ${escHtml(down.map((d) => d.name).join(', '))}` : ''}`,
    `Alerts (24h): ${alerts24} · active now: ${active}`,
    `Security findings (24h): ${findings24.length ? findings24.map((f) => `${f.n} ${f.severity}`).join(', ') : 'none'}`,
    `Failed Windows logons (24h): ${failed}`,
    `Open incidents: ${incidentsOpen}`,
    unhealthy.length ? `⚠️ Monitoring problems: ${escHtml(unhealthy.map((c) => `${c.label}: ${c.message}`).join('; '))}` : '✅ All monitoring components healthy',
    '<i>If this daily message stops arriving, SENTINEL itself is not running.</i>',
  ];
  return lines.join('\n');
}

export const HOURLY = HOUR;
