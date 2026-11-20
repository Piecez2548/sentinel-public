import { Router } from 'express';
import { all, get, run } from '../db.js';
import { dayBounds, DAY, localDay, percentile } from '../lib/util.js';

/** Daily rollups (kept 1 year) + reports: availability, SLO, MTTA/MTTR, trends (FR-16). */

const HOST_SAMPLE_SEC = 60;

function rollupAsset(asset: { id: number; type: string; created_at: number }, day: string) {
  const [start, end] = dayBounds(day);
  const from = Math.max(start, asset.created_at);
  const to = Math.min(end, Date.now());
  if (to <= from) return;

  if (asset.type === 'website') {
    const rows = all<{ ok: number; latency_ms: number | null }>('SELECT ok, latency_ms FROM check_results WHERE asset_id = ? AND ts >= ? AND ts < ?', asset.id, start, end);
    if (!rows.length) return;
    const lat = rows.filter((r) => r.ok && r.latency_ms != null).map((r) => r.latency_ms!).sort((a, b) => a - b);
    run(
      `INSERT INTO daily_stats (asset_id, day, checks_total, checks_ok, latency_avg, latency_p95) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(asset_id, day) DO UPDATE SET checks_total = excluded.checks_total, checks_ok = excluded.checks_ok, latency_avg = excluded.latency_avg, latency_p95 = excluded.latency_p95`,
      asset.id, day, rows.length, rows.filter((r) => r.ok).length, lat.length ? lat.reduce((s, v) => s + v, 0) / lat.length : null, percentile(lat, 95),
    );
  } else {
    const r = get<{ n: number; cpu_avg: number | null; cpu_max: number | null; mem_avg: number | null; first: number | null }>(
      'SELECT COUNT(*) AS n, AVG(cpu_pct) AS cpu_avg, MAX(cpu_pct) AS cpu_max, AVG(mem_pct) AS mem_avg, MIN(ts) AS first FROM host_metrics WHERE asset_id = ? AND ts >= ? AND ts < ?',
      asset.id, start, end,
    );
    if (!r || !r.n) return;
    // Expected samples: from when monitoring of this asset started (first sample ever) or start of day.
    const firstEver = get<{ t: number | null }>('SELECT MIN(ts) AS t FROM host_metrics WHERE asset_id = ?', asset.id)?.t ?? r.first!;
    const expectedFrom = Math.max(from, firstEver);
    const expected = Math.max(r.n, Math.floor((to - expectedFrom) / (HOST_SAMPLE_SEC * 1000)));
    run(
      `INSERT INTO daily_stats (asset_id, day, host_samples, host_expected, cpu_avg, cpu_max, mem_avg) VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(asset_id, day) DO UPDATE SET host_samples = excluded.host_samples, host_expected = excluded.host_expected, cpu_avg = excluded.cpu_avg, cpu_max = excluded.cpu_max, mem_avg = excluded.mem_avg`,
      asset.id, day, r.n, expected, r.cpu_avg, r.cpu_max, r.mem_avg,
    );
  }
}

/** Recompute today + yesterday always; older days (within raw retention) only if missing. */
export function runRollups() {
  const assets = all<{ id: number; type: string; created_at: number }>('SELECT id, type, created_at FROM assets');
  for (let i = 0; i < 15; i++) {
    const day = localDay(Date.now() - i * DAY);
    for (const a of assets) {
      if (i <= 1 || !get('SELECT 1 FROM daily_stats WHERE asset_id = ? AND day = ?', a.id, day)) rollupAsset(a, day);
    }
  }
}

export const reportsRouter = Router();

const daysOf = (q: unknown) => Math.min(Math.max(Number(q) || 30, 1), 365);

export function buildReport(days: number) {
  runRollups(); // make "today" current
  const now = Date.now();
  const since = now - days * DAY;
  const fromDay = localDay(since);

  const assets = all<{ id: number; name: string; type: string; slo_target: number; enabled: number; collector: string | null }>(
    'SELECT a.id, a.name, a.type, a.slo_target, a.enabled, h.collector FROM assets a LEFT JOIN host_info h ON h.asset_id = a.id ORDER BY a.type, a.name',
  );
  const stats = all<{ asset_id: number; day: string; checks_total: number; checks_ok: number; latency_avg: number | null; latency_p95: number | null; host_samples: number; host_expected: number; cpu_avg: number | null; cpu_max: number | null; mem_avg: number | null }>(
    'SELECT * FROM daily_stats WHERE day >= ? ORDER BY day', fromDay,
  );

  const perAsset = assets.map((a) => {
    const s = stats.filter((x) => x.asset_id === a.id);
    let availability: number | null = null;
    let latencyAvg: number | null = null;
    let latencyP95: number | null = null;
    let cpuAvg: number | null = null;
    let cpuMax: number | null = null;
    let memAvg: number | null = null;
    if (a.type === 'website') {
      const total = s.reduce((t, x) => t + x.checks_total, 0);
      const ok = s.reduce((t, x) => t + x.checks_ok, 0);
      availability = total ? (ok / total) * 100 : null;
      const lat = s.filter((x) => x.latency_avg != null);
      latencyAvg = lat.length ? lat.reduce((t, x) => t + x.latency_avg! * x.checks_ok, 0) / Math.max(1, lat.reduce((t, x) => t + x.checks_ok, 0)) : null;
      latencyP95 = lat.length ? Math.max(...lat.map((x) => x.latency_p95 ?? 0)) : null;
    } else {
      const got = s.reduce((t, x) => t + x.host_samples, 0);
      const exp = s.reduce((t, x) => t + x.host_expected, 0);
      availability = exp ? Math.min(100, (got / exp) * 100) : null;
      const c = s.filter((x) => x.cpu_avg != null);
      cpuAvg = c.length ? c.reduce((t, x) => t + x.cpu_avg!, 0) / c.length : null;
      cpuMax = c.length ? Math.max(...c.map((x) => x.cpu_max ?? 0)) : null;
      const m = s.filter((x) => x.mem_avg != null);
      memAvg = m.length ? m.reduce((t, x) => t + x.mem_avg!, 0) / m.length : null;
    }
    const covered = s.length;
    // The PC that runs SENTINEL is switched off normally; its "availability" is really
    // monitoring coverage, so no SLO / error budget is judged for it.
    const isLocalPc = a.type === 'host' && a.collector === 'local';
    const budgetMin = ((100 - a.slo_target) / 100) * covered * 1440;
    const downMin = availability != null && !isLocalPc ? ((100 - availability) / 100) * covered * 1440 : null;
    return {
      id: a.id,
      name: a.name,
      type: a.type,
      isLocalPc,
      sloTarget: a.slo_target,
      daysCovered: covered,
      availability,
      sloMet: availability != null && !isLocalPc ? availability >= a.slo_target : null,
      downtimeMin: downMin,
      errorBudgetMin: budgetMin,
      errorBudgetLeftPct: downMin != null && budgetMin > 0 ? Math.max(0, ((budgetMin - downMin) / budgetMin) * 100) : null,
      latencyAvg,
      latencyP95,
      cpuAvg,
      cpuMax,
      memAvg,
      daily: s.map((x) => ({
        day: x.day,
        availability: a.type === 'website' ? (x.checks_total ? (x.checks_ok / x.checks_total) * 100 : null) : x.host_expected ? Math.min(100, (x.host_samples / x.host_expected) * 100) : null,
        latencyAvg: x.latency_avg,
        cpuAvg: x.cpu_avg,
      })),
    };
  });

  const inc = all<{ severity: string; status: string; opened_at: number; acknowledged_at: number | null; resolved_at: number | null }>(
    'SELECT severity, status, opened_at, acknowledged_at, resolved_at FROM incidents WHERE opened_at > ?', since,
  );
  const acked = inc.filter((i) => i.acknowledged_at);
  const resolved = inc.filter((i) => i.resolved_at);
  const avg = (xs: number[]) => (xs.length ? xs.reduce((s, v) => s + v, 0) / xs.length : null);

  const alertsBySeverity = all<{ severity: string; n: number }>('SELECT severity, COUNT(*) AS n FROM alert_events WHERE triggered_at > ? GROUP BY severity', since);
  const alertsByRule = all<{ name: string | null; n: number }>(
    'SELECT r.name, COUNT(*) AS n FROM alert_events e LEFT JOIN alert_rules r ON r.id = e.rule_id WHERE e.triggered_at > ? GROUP BY r.name ORDER BY n DESC', since,
  );
  const findingsByRule = all<{ name: string; severity: string; n: number }>(
    'SELECT r.name, f.severity, COUNT(*) AS n FROM security_findings f JOIN detection_rules r ON r.id = f.rule_id WHERE f.first_seen > ? GROUP BY r.name, f.severity ORDER BY n DESC', since,
  );
  const findingsDaily = all<{ day: string; n: number }>(
    "SELECT strftime('%Y-%m-%d', first_seen / 1000, 'unixepoch', 'localtime') AS day, COUNT(*) AS n FROM security_findings WHERE first_seen > ? GROUP BY day ORDER BY day", since,
  );
  const failedLogonsDaily = all<{ day: string; n: number }>(
    "SELECT strftime('%Y-%m-%d', ts / 1000, 'unixepoch', 'localtime') AS day, COUNT(*) AS n FROM log_events WHERE event_id = 4625 AND ts > ? GROUP BY day ORDER BY day", since,
  );

  return {
    days,
    generatedAt: now,
    assets: perAsset,
    incidents: {
      total: inc.length,
      open: inc.filter((i) => !['resolved', 'closed'].includes(i.status)).length,
      bySeverity: Object.fromEntries(['low', 'medium', 'high', 'critical'].map((s) => [s, inc.filter((i) => i.severity === s).length])),
      mttaMs: avg(acked.map((i) => i.acknowledged_at! - i.opened_at)),
      mttrMs: avg(resolved.map((i) => i.resolved_at! - i.opened_at)),
    },
    alerts: { bySeverity: Object.fromEntries(alertsBySeverity.map((r) => [r.severity, r.n])), byRule: alertsByRule.map((r) => ({ name: r.name ?? '(deleted rule)', count: r.n })) },
    security: {
      findingsByRule: findingsByRule.map((r) => ({ name: r.name, severity: r.severity, count: r.n })),
      findingsDaily,
      failedLogonsDaily,
      note: 'Raw security events are kept 14 days; failed-logon trend beyond that is unavailable.',
    },
  };
}

reportsRouter.get('/', (req, res) => {
  res.json(buildReport(daysOf(req.query.days)));
});

/* ---------- CSV export ---------- */

/** One CSV cell: quoted when needed; a leading = + - @ is defused so spreadsheets never run it as a formula. */
export function csvCell(v: unknown): string {
  if (v == null) return '';
  let s = typeof v === 'number' ? (Number.isFinite(v) ? String(Math.round(v * 100) / 100) : '') : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(header: string[], rows: unknown[][]): string {
  // BOM so Excel opens Thai text as UTF-8.
  return '﻿' + [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

// Local time (this PC's zone) as "2026-11-14 20:12:09": spreadsheets read it as a date.
const iso = (ts: number | null | undefined) => (ts ? new Date(ts).toLocaleString('sv-SE') : '');
const minutes = (ms: number | null | undefined) => (ms == null ? null : Math.round(ms / 60_000));

export const CSV_KINDS = ['summary', 'alerts', 'incidents', 'findings'] as const;
type CsvKind = (typeof CSV_KINDS)[number];

export function reportCsv(kind: CsvKind, days: number): string {
  const since = Date.now() - days * DAY;
  if (kind === 'alerts') {
    const rows = all<{ id: number; triggered_at: number; resolved_at: number | null; acknowledged_at: number | null; status: string; severity: string; rule: string | null; type: string | null; asset: string | null; title: string; detail: string | null; value: number | null }>(
      `SELECT e.id, e.triggered_at, e.resolved_at, e.acknowledged_at, e.status, e.severity, r.name AS rule, r.type, a.name AS asset, e.title, e.detail, e.value
         FROM alert_events e LEFT JOIN alert_rules r ON r.id = e.rule_id LEFT JOIN assets a ON a.id = e.asset_id
        WHERE e.triggered_at > ? ORDER BY e.triggered_at`,
      since,
    );
    return toCsv(
      ['id', 'triggered_at', 'resolved_at', 'duration_min', 'status', 'severity', 'rule', 'rule_type', 'asset', 'title', 'detail', 'value'],
      rows.map((r) => [r.id, iso(r.triggered_at), iso(r.resolved_at), minutes((r.resolved_at ?? Date.now()) - r.triggered_at), r.status, r.severity, r.rule, r.type, r.asset, r.title, r.detail, r.value]),
    );
  }
  if (kind === 'incidents') {
    const rows = all<{ id: number; opened_at: number; acknowledged_at: number | null; resolved_at: number | null; closed_at: number | null; status: string; severity: string; source: string; asset: string | null; title: string; resolution: string | null; links: number }>(
      `SELECT i.id, i.opened_at, i.acknowledged_at, i.resolved_at, i.closed_at, i.status, i.severity, i.source, a.name AS asset, i.title, i.resolution,
              (SELECT COUNT(*) FROM incident_links l WHERE l.incident_id = i.id) AS links
         FROM incidents i LEFT JOIN assets a ON a.id = i.asset_id WHERE i.opened_at > ? ORDER BY i.opened_at`,
      since,
    );
    return toCsv(
      ['id', 'opened_at', 'acknowledged_at', 'resolved_at', 'closed_at', 'time_to_ack_min', 'time_to_resolve_min', 'status', 'severity', 'source', 'asset', 'title', 'evidence_count', 'resolution'],
      rows.map((r) => [r.id, iso(r.opened_at), iso(r.acknowledged_at), iso(r.resolved_at), iso(r.closed_at), minutes(r.acknowledged_at && r.acknowledged_at - r.opened_at), minutes(r.resolved_at && r.resolved_at - r.opened_at), r.status, r.severity, r.source, r.asset, r.title, r.links, r.resolution]),
    );
  }
  if (kind === 'findings') {
    const rows = all<{ id: number; first_seen: number; last_seen: number; status: string; severity: string; rule_id: string; asset: string | null; title: string; summary: string; count: number; note: string | null }>(
      `SELECT f.id, f.first_seen, f.last_seen, f.status, f.severity, f.rule_id, a.name AS asset, f.title, f.summary, f.count, f.note
         FROM security_findings f LEFT JOIN assets a ON a.id = f.asset_id WHERE f.last_seen > ? ORDER BY f.first_seen`,
      since,
    );
    return toCsv(
      ['id', 'first_seen', 'last_seen', 'status', 'severity', 'rule', 'asset', 'title', 'summary', 'count', 'note'],
      rows.map((r) => [r.id, iso(r.first_seen), iso(r.last_seen), r.status, r.severity, r.rule_id, r.asset, r.title, r.summary, r.count, r.note]),
    );
  }
  // summary: one row per asset + one row per headline number, so it reads well in a spreadsheet.
  const r = buildReport(days);
  const rows: unknown[][] = r.assets.map((a) => [
    'asset', a.name, a.type, a.availability, a.sloTarget, a.sloMet == null ? '' : a.sloMet ? 'yes' : 'no', a.downtimeMin, a.errorBudgetLeftPct, a.latencyAvg, a.latencyP95, a.cpuAvg, a.cpuMax, a.memAvg,
  ]);
  const totalAlerts = Object.values(r.alerts.bySeverity).reduce((s, n) => s + n, 0);
  rows.push(
    ['total', 'incidents', '', r.incidents.total],
    ['total', 'incidents_open', '', r.incidents.open],
    ['total', 'mtta_min', '', minutes(r.incidents.mttaMs)],
    ['total', 'mttr_min', '', minutes(r.incidents.mttrMs)],
    ['total', 'alerts_fired', '', totalAlerts],
    ...Object.entries(r.alerts.bySeverity).map(([sev, n]) => ['alerts_by_severity', sev, '', n]),
    ...r.alerts.byRule.map((x) => ['alerts_by_rule', x.name, '', x.count]),
    ...r.security.findingsByRule.map((x) => ['findings_by_rule', x.name, x.severity, x.count]),
  );
  return toCsv(
    ['section', 'name', 'type_or_severity', 'availability_or_value', 'slo_target', 'slo_met', 'downtime_min', 'error_budget_left_pct', 'latency_avg_ms', 'latency_p95_ms', 'cpu_avg', 'cpu_max', 'mem_avg'],
    rows,
  );
}

reportsRouter.get('/export.csv', (req, res) => {
  const days = daysOf(req.query.days);
  const kind = (CSV_KINDS as readonly string[]).includes(String(req.query.kind)) ? (req.query.kind as CsvKind) : 'summary';
  const csv = reportCsv(kind, days);
  const stamp = localDay(Date.now());
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="sentinel-${kind}-${days}d-${stamp}.csv"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(csv);
});

