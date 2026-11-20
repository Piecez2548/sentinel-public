import { Router } from 'express';
import { all, get, run } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { getHealth } from '../lib/health.js';
import { checkErrorTh, componentText, durText, L, sevText } from '../lib/i18n.js';
import { localOverload, localTrouble } from '../lib/local-load.js';
import { culpritText, latestSnapshot, runningGame } from './processes.js';
import { body, clientIp, HttpError, idParam, num, oneOf, str } from '../lib/http.js';
import { stepUp } from './auth.js';
import { DAY, escHtml, fmtDuration, MIN, parseJson, SEVERITIES } from '../lib/util.js';
import { enqueue } from './notify.js';
import type { DiskSample } from './host-collector.js';

/**
 * Threshold alerting (FR-06/07). Each rule yields candidates (asset + key).
 * A candidate that is "active" opens one alert_event (unique fingerprint = dedup);
 * while it stays active we only send a reminder after `cooldown_sec`;
 * when it clears the event auto-resolves. Windows are evaluated from stored
 * data, so restarts do not reset "for N minutes" conditions.
 */

export const ALERT_TYPES = ['host_offline', 'host_cpu', 'host_memory', 'host_disk', 'host_battery', 'site_down', 'site_latency', 'tls_expiry', 'pipeline'] as const;
type AlertType = (typeof ALERT_TYPES)[number];

const TYPE_INFO: Record<AlertType, { label: string; params: Record<string, number>; usesFor: boolean; assetType: 'host' | 'website' | null }> = {
  host_offline: { label: 'Host offline (no metrics)', params: { minutes: 3 }, usesFor: false, assetType: 'host' },
  host_cpu: { label: 'CPU usage above threshold', params: { threshold: 90 }, usesFor: true, assetType: 'host' },
  host_memory: { label: 'Memory usage above threshold', params: { threshold: 90 }, usesFor: true, assetType: 'host' },
  host_disk: { label: 'Disk usage above threshold', params: { threshold: 90 }, usesFor: false, assetType: 'host' },
  host_battery: { label: 'Battery low while unplugged', params: { threshold: 20 }, usesFor: false, assetType: 'host' },
  site_down: { label: 'Website down', params: {}, usesFor: false, assetType: 'website' },
  site_latency: { label: 'Website slow (avg latency)', params: { thresholdMs: 3000, samples: 5 }, usesFor: false, assetType: 'website' },
  tls_expiry: { label: 'TLS certificate expiring', params: { days: 14 }, usesFor: false, assetType: 'website' },
  pipeline: { label: 'SENTINEL pipeline problem (self-monitoring)', params: { minutes: 5 }, usesFor: false, assetType: null },
};

const BUILTIN: { name: string; type: AlertType; severity: string; forSec: number; cooldownSec: number }[] = [
  { name: 'Host offline', type: 'host_offline', severity: 'critical', forSec: 0, cooldownSec: 3600 },
  { name: 'High CPU', type: 'host_cpu', severity: 'high', forSec: 900, cooldownSec: 3600 },
  { name: 'High memory', type: 'host_memory', severity: 'high', forSec: 900, cooldownSec: 3600 },
  { name: 'Disk almost full', type: 'host_disk', severity: 'medium', forSec: 0, cooldownSec: 6 * 3600 },
  { name: 'Battery low', type: 'host_battery', severity: 'high', forSec: 0, cooldownSec: 15 * 60 },
  { name: 'Website down', type: 'site_down', severity: 'critical', forSec: 0, cooldownSec: 3600 },
  { name: 'Slow website', type: 'site_latency', severity: 'medium', forSec: 0, cooldownSec: 3 * 3600 },
  { name: 'TLS certificate expiring', type: 'tls_expiry', severity: 'high', forSec: 0, cooldownSec: DAY / 1000 },
  { name: 'Monitoring pipeline problem', type: 'pipeline', severity: 'high', forSec: 0, cooldownSec: 3 * 3600 },
];

export function seedAlertRules() {
  // Adds any built-in rule that is missing (new built-ins reach existing installs too).
  for (const b of BUILTIN) {
    if (get('SELECT id FROM alert_rules WHERE builtin = 1 AND type = ?', b.type)) continue;
    run(
      'INSERT INTO alert_rules (name, type, params, severity, for_sec, cooldown_sec, enabled, builtin) VALUES (?, ?, ?, ?, ?, ?, 1, 1)',
      b.name, b.type, JSON.stringify(TYPE_INFO[b.type].params), b.severity, b.forSec, b.cooldownSec,
    );
  }
  // 5 minutes was too twitchy (a game or a test run easily averages 90%): move untouched built-ins to 15.
  run("UPDATE alert_rules SET for_sec = 900 WHERE builtin = 1 AND type IN ('host_cpu','host_memory') AND for_sec = 300");
}

type Rule = { id: number; name: string; type: AlertType; asset_id: number | null; params: string; severity: string; for_sec: number; cooldown_sec: number; enabled: number; builtin: number };
/** title/detail are stored (English); msg is the localized text for Telegram. */
type Candidate = { assetId: number | null; key: string; active: boolean | null; value: number | null; title: string; detail: string; msg?: { title: string; detail: string } };

function assetsOf(rule: Rule, type: 'host' | 'website') {
  return all<{ id: number; name: string; status: string; target: string | null }>(
    `SELECT id, name, status, target FROM assets WHERE type = ? AND enabled = 1 ${rule.asset_id ? 'AND id = ?' : ''}`,
    ...(rule.asset_id ? [type, rule.asset_id] : [type]),
  );
}

function evaluate(rule: Rule): Candidate[] {
  const p = { ...TYPE_INFO[rule.type].params, ...parseJson<Record<string, number>>(rule.params, {}) };
  const now = Date.now();
  const out: Candidate[] = [];

  switch (rule.type) {
    case 'host_offline': {
      // Grace period after SENTINEL starts: data is naturally stale while it was not running,
      // so during it we may resolve but never fire.
      const grace = process.uptime() * 1000 < p.minutes * MIN;
      for (const a of assetsOf(rule, 'host')) {
        const info = get<{ last_seen_at: number | null; collector: string }>('SELECT last_seen_at, collector FROM host_info WHERE asset_id = ?', a.id);
        // The PC SENTINEL runs on cannot be "offline" while SENTINEL is running; late metrics there only mean
        // it is very busy. A PC that is really off is caught by the external heartbeat instead.
        if (info?.last_seen_at == null || info.collector === 'local') continue;
        const seen = info.last_seen_at;
        const age = now - seen;
        const active = age > p.minutes * MIN;
        out.push({ assetId: a.id, key: '', active: grace && active ? null : active, value: Math.round(age / 1000), title: `${a.name} is offline`, detail: `No metrics for ${fmtDuration(age)}`, msg: { title: L(`${a.name} is offline`, `${a.name} ออฟไลน์`), detail: L(`No metrics for ${durText(age)}`, `ไม่มีข้อมูลเข้ามา ${durText(age)}`) } });
      }
      break;
    }

    case 'host_cpu':
    case 'host_memory': {
      const col = rule.type === 'host_cpu' ? 'cpu_pct' : 'mem_pct';
      const label = rule.type === 'host_cpu' ? 'CPU' : 'Memory';
      const windowMs = Math.max(rule.for_sec, 60) * 1000;
      for (const a of assetsOf(rule, 'host')) {
        const r = get<{ avg: number | null; n: number; first: number | null }>(
          `SELECT AVG(${col}) AS avg, COUNT(*) AS n, MIN(ts) AS first FROM host_metrics WHERE asset_id = ? AND ts > ?`,
          // Look back one extra sample interval (60 s) so a short window always holds a sample
          // old enough to judge; otherwise a 1-minute window could never be satisfied reliably.
          a.id, now - windowMs - 60_000,
        );
        // Need samples spanning most of the window before judging.
        if (!r || r.avg == null || !r.first || now - r.first < windowMs * 0.7) {
          out.push({ assetId: a.id, key: '', active: r?.avg != null && r.avg < p.threshold ? false : null, value: r?.avg ?? null, title: '', detail: '' });
          continue;
        }
        const avg = Math.round(r.avg * 10) / 10;
        const thLabel = rule.type === 'host_cpu' ? 'CPU' : 'หน่วยความจำ';
        const isFiring = firing(rule.id, a.id);
        // Hysteresis: once firing, it clears only when the average drops 10 points below the threshold,
        // so a load hovering around 90% does not flip fired/resolved every minute.
        let active: boolean | null = avg >= (isFiring ? p.threshold - 10 : p.threshold);
        // Game mode: a heavy load while a listed game runs is expected — do not raise a new alert for it.
        if (active && !isFiring && runningGame()) active = null;
        // Name the programs behind the load (snapshot taken while the PC was busy).
        const snap = latestSnapshot();
        const culprits = snap ? culpritText(snap.groups, rule.type === 'host_cpu' ? 'cpu' : 'mem') : '';
        out.push({
          assetId: a.id, key: '', active, value: avg,
          title: `${label} high on ${a.name}`,
          detail: `${label} averaged ${avg}% over ${fmtDuration(windowMs)} (threshold ${p.threshold}%)${culprits ? ` — top: ${culprits}` : ''}`,
          msg: {
            title: L(`${label} high on ${a.name}`, `${thLabel} สูงบน ${a.name}`),
            detail:
              L(`${label} averaged ${avg}% over ${durText(windowMs)} (threshold ${p.threshold}%)`, `${thLabel} เฉลี่ย ${avg}% ตลอด ${durText(windowMs)} (เกณฑ์ ${p.threshold}%)`) +
              (culprits ? L(`
Using the most: ${culprits}`, `
โปรแกรมที่ใช้มากสุด: ${culprits}`) : '') +
              L(`
To close one: SENTINEL → Power control`, `
จะปิดโปรแกรม: SENTINEL → ควบคุมเครื่อง`),
          },
        });
      }
      break;
    }

    case 'host_disk':
      for (const a of assetsOf(rule, 'host')) {
        const r = get<{ disks: string; ts: number }>('SELECT disks, ts FROM host_metrics WHERE asset_id = ? ORDER BY ts DESC LIMIT 1', a.id);
        if (!r || now - r.ts > 10 * MIN) continue;
        for (const d of parseJson<DiskSample[]>(r.disks, [])) {
          out.push({ assetId: a.id, key: d.mount, active: d.usedPct >= p.threshold, value: d.usedPct, title: `Disk ${d.mount} almost full on ${a.name}`, detail: `${d.usedPct}% used, ${(d.free / 1e9).toFixed(1)} GB free (threshold ${p.threshold}%)`, msg: { title: L(`Disk ${d.mount} almost full on ${a.name}`, `ดิสก์ ${d.mount} ใกล้เต็มบน ${a.name}`), detail: L(`${d.usedPct}% used, ${(d.free / 1e9).toFixed(1)} GB free (threshold ${p.threshold}%)`, `ใช้ไป ${d.usedPct}% เหลือ ${(d.free / 1e9).toFixed(1)} GB (เกณฑ์ ${p.threshold}%)`) } });
        }
      }
      break;

    case 'host_battery':
      for (const a of assetsOf(rule, 'host')) {
        const r = get<{ battery_pct: number | null; on_ac: number | null; ts: number }>(
          'SELECT battery_pct, on_ac, ts FROM host_metrics WHERE asset_id = ? AND battery_pct IS NOT NULL ORDER BY ts DESC LIMIT 1', a.id,
        );
        if (!r || r.battery_pct == null || now - r.ts > 10 * MIN) continue; // no battery, or no fresh sample
        const low = r.on_ac === 0 && r.battery_pct <= p.threshold;
        out.push({
          assetId: a.id, key: '', active: low, value: r.battery_pct,
          title: `Battery low on ${a.name}`,
          detail: `${r.battery_pct}% left and not charging (threshold ${p.threshold}%) — plug in the charger`,
          msg: {
            title: L(`Battery low on ${a.name}`, `แบตเตอรี่ใกล้หมดบน ${a.name}`),
            detail: L(`${r.battery_pct}% left and not charging (threshold ${p.threshold}%) — plug in the charger`, `เหลือ ${r.battery_pct}% และไม่ได้เสียบชาร์จ (เกณฑ์ ${p.threshold}%) — เสียบสายชาร์จก่อนเครื่องดับ`),
          },
        });
      }
      break;

    case 'site_down':
      for (const a of assetsOf(rule, 'website')) {
        if (a.status !== 'up' && a.status !== 'down') continue;
        const h = get<{ last_error: string | null; last_status_code: number | null }>('SELECT last_error, last_status_code FROM http_checks WHERE asset_id = ?', a.id);
        const err = h?.last_error ?? null;
        // Still failing after the hold while this PC is choking: say so, the site may be fine.
        const trouble = a.status === 'down' && h?.last_status_code == null ? localTrouble(a.id, now) : null;
        const load = trouble === 'busy' ? localOverload(now) : null;
        const whyEn = load ? `This PC is very busy right now (CPU ${load.cpu}%, memory ${load.mem}%)` : 'Other sites are not answering this PC either';
        const whyTh = load ? `ตอนนี้เครื่องนี้ทำงานหนักมาก (CPU ${load.cpu}% หน่วยความจำ ${load.mem}%)` : 'เว็บอื่นก็ไม่ตอบเครื่องนี้เหมือนกัน';
        const noteEn = trouble ? `\n⚠ ${whyEn} — it may be the PC or its internet, not the site. Open the site on your phone to check.` : '';
        const noteTh = trouble ? `\n⚠ ${whyTh} — อาจเป็นที่เครื่องหรือเน็ต ไม่ใช่เว็บล่มจริง ลองเปิดเว็บจากมือถือดู` : '';
        out.push({ assetId: a.id, key: '', active: a.status === 'down', value: h?.last_status_code ?? null, title: `${a.name} is DOWN`, detail: `${a.target} — ${err ?? 'check failed'}`, msg: { title: L(`${a.name} is DOWN`, `เว็บ ${a.name} ล่ม`), detail: `${a.target} — ${L(err ?? 'check failed', checkErrorTh(err))}${L(noteEn, noteTh)}` } });
      }
      break;

    case 'site_latency':
      for (const a of assetsOf(rule, 'website')) {
        const rows = all<{ latency_ms: number }>('SELECT latency_ms FROM check_results WHERE asset_id = ? AND ok = 1 ORDER BY ts DESC LIMIT ?', a.id, p.samples);
        if (rows.length < p.samples) continue;
        const avg = Math.round(rows.reduce((s, r) => s + r.latency_ms, 0) / rows.length);
        out.push({ assetId: a.id, key: '', active: avg >= p.thresholdMs, value: avg, title: `${a.name} is slow`, detail: `Average latency ${avg} ms over the last ${p.samples} checks (threshold ${p.thresholdMs} ms)`, msg: { title: L(`${a.name} is slow`, `เว็บ ${a.name} ช้า`), detail: L(`Average latency ${avg} ms over the last ${p.samples} checks (threshold ${p.thresholdMs} ms)`, `เวลาตอบสนองเฉลี่ย ${avg} ms จาก ${p.samples} ครั้งล่าสุด (เกณฑ์ ${p.thresholdMs} ms)`) } });
      }
      break;

    case 'tls_expiry':
      for (const a of assetsOf(rule, 'website')) {
        const exp = get<{ tls_expires_at: number | null }>('SELECT tls_expires_at FROM http_checks WHERE asset_id = ?', a.id)?.tls_expires_at;
        if (!exp) continue;
        const days = Math.floor((exp - now) / DAY);
        out.push({ assetId: a.id, key: '', active: days <= p.days, value: days, title: `TLS certificate of ${a.name} expires ${days < 0 ? 'has EXPIRED' : `in ${days} day(s)`}`, detail: `Expires ${new Date(exp).toUTCString()}`, msg: { title: L(`TLS certificate of ${a.name} ${days < 0 ? 'has EXPIRED' : `expires in ${days} day(s)`}`, `ใบรับรอง TLS ของ ${a.name} ${days < 0 ? 'หมดอายุแล้ว' : `จะหมดอายุในอีก ${days} วัน`}`), detail: L(`Expires ${new Date(exp).toUTCString()}`, `หมดอายุ ${new Date(exp).toLocaleString('th-TH')}`) } });
      }
      break;

    case 'pipeline':
      for (const c of getHealth()) {
        const failingFor = c.errorSince ? now - c.errorSince : 0;
        out.push({ assetId: null, key: c.name, active: !c.ok && failingFor >= p.minutes * MIN, value: Math.round(failingFor / 1000), title: `SENTINEL: ${c.label} is failing`, detail: c.message, msg: { title: L(`SENTINEL: ${c.label} is failing`, `SENTINEL: ${componentText(c.label)} มีปัญหา`), detail: c.message } });
      }
      break;
  }
  return out;
}

/** Is this rule's alert for the asset currently open (fired, not resolved)? */
function firing(ruleId: number, assetId: number): boolean {
  return !!get("SELECT 1 FROM alert_events WHERE fingerprint = ? AND status != 'resolved'", `${ruleId}:${assetId}:`);
}

type OpenEvent = { id: number; status: string; last_notified_at: number | null; triggered_at: number };

function sevIcon(sev: string) {
  return sev === 'critical' ? '🔴' : sev === 'high' ? '🟠' : sev === 'medium' ? '🟡' : '🔵';
}

export function evaluateAlerts() {
  const rules = all<Rule>('SELECT * FROM alert_rules WHERE enabled = 1');
  const now = Date.now();
  let changed = false;

  for (const rule of rules) {
    for (const c of evaluate(rule)) {
      if (c.active === null) continue;
      const fp = `${rule.id}:${c.assetId ?? 'global'}:${c.key}`;
      const open = get<OpenEvent>("SELECT id, status, last_notified_at, triggered_at FROM alert_events WHERE fingerprint = ? AND status != 'resolved'", fp);

      if (c.active && !open) {
        const r = run(
          `INSERT INTO alert_events (rule_id, asset_id, fingerprint, status, severity, title, detail, value, triggered_at, last_notified_at)
           VALUES (?, ?, ?, 'firing', ?, ?, ?, ?, ?, ?)`,
          rule.id, c.assetId, fp, rule.severity, c.title, c.detail, c.value, now, now,
        );
        const m = c.msg ?? c;
        enqueue('alert_fired', `alert:${r.lastInsertRowid}`, `${sevIcon(rule.severity)} <b>[${sevText(rule.severity)}] ${escHtml(m.title)}</b>\n${escHtml(m.detail)}`);
        changed = true;
      } else if (c.active && open) {
        run('UPDATE alert_events SET value = ?, detail = ? WHERE id = ?', c.value, c.detail, open.id);
        if (open.status === 'firing' && now - (open.last_notified_at ?? open.triggered_at) >= rule.cooldown_sec * 1000) {
          run('UPDATE alert_events SET last_notified_at = ? WHERE id = ?', now, open.id);
          const m = c.msg ?? c;
          enqueue('alert_reminder', `alert:${open.id}`, `⏰ ${L('Still active for', 'ยังเกิดอยู่มา')} ${durText(now - open.triggered_at)}: <b>${escHtml(m.title)}</b>\n${escHtml(m.detail)}`);
        }
      } else if (!c.active && open) {
        run("UPDATE alert_events SET status = 'resolved', resolved_at = ? WHERE id = ?", now, open.id);
        const t = c.msg?.title || get<{ title: string }>('SELECT title FROM alert_events WHERE id = ?', open.id)?.title || c.title;
        enqueue('alert_resolved', `alert:${open.id}`, `🟢 <b>${L('RESOLVED', 'กลับมาปกติ')}</b> ${escHtml(t)}\n${L('Was active for', 'เกิดอยู่นาน')} ${durText(now - open.triggered_at)}`);
        changed = true;
      }
    }
  }
  // Rules that were disabled/deleted: resolve their open events so nothing stays stuck.
  const orphan = run(
    "UPDATE alert_events SET status = 'resolved', resolved_at = ? WHERE status != 'resolved' AND (rule_id IS NULL OR rule_id IN (SELECT id FROM alert_rules WHERE enabled = 0))",
    now,
  );
  if (changed || orphan.changes) publish('alerts');
}

/* ---------- API ---------- */

export const alertsRouter = Router();

type EventRow = { id: number; rule_id: number | null; asset_id: number | null; status: string; severity: string; title: string; detail: string | null; value: number | null; triggered_at: number; acknowledged_at: number | null; resolved_at: number | null; asset_name: string | null; rule_name: string | null; rule_type: string | null };

export const alertDto = (e: EventRow) => ({
  id: e.id,
  ruleId: e.rule_id,
  ruleName: e.rule_name,
  ruleType: e.rule_type,
  assetId: e.asset_id,
  assetName: e.asset_name,
  status: e.status,
  severity: e.severity,
  title: e.title,
  detail: e.detail,
  value: e.value,
  triggeredAt: e.triggered_at,
  acknowledgedAt: e.acknowledged_at,
  resolvedAt: e.resolved_at,
});

export const ALERT_SELECT = `SELECT e.*, a.name AS asset_name, r.name AS rule_name, r.type AS rule_type FROM alert_events e
  LEFT JOIN assets a ON a.id = e.asset_id LEFT JOIN alert_rules r ON r.id = e.rule_id`;

alertsRouter.get('/events', (req, res) => {
  const status = String(req.query.status ?? 'active');
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const where = status === 'active' ? "WHERE e.status != 'resolved'" : status === 'resolved' ? "WHERE e.status = 'resolved'" : '';
  const rows = all<EventRow>(`${ALERT_SELECT} ${where} ORDER BY e.triggered_at DESC LIMIT ?`, limit);
  res.json({ events: rows.map(alertDto) });
});

alertsRouter.post('/events/:id/ack', (req, res) => {
  const id = idParam(req);
  const r = run("UPDATE alert_events SET status = 'acknowledged', acknowledged_at = ? WHERE id = ? AND status = 'firing'", Date.now(), id);
  if (!r.changes) throw new HttpError(409, 'Alert is not firing');
  audit('alert.acknowledged', { ip: clientIp(req), resourceType: 'alert', resourceId: id });
  publish('alerts');
  res.json({ ok: true });
});

alertsRouter.get('/rules', (_req, res) => {
  const rows = all<Rule & { asset_name: string | null }>('SELECT r.*, a.name AS asset_name FROM alert_rules r LEFT JOIN assets a ON a.id = r.asset_id ORDER BY r.id');
  const firing = new Map(all<{ rule_id: number; n: number }>("SELECT rule_id, COUNT(*) AS n FROM alert_events WHERE status != 'resolved' GROUP BY rule_id").map((r) => [r.rule_id, r.n]));
  res.json({
    types: Object.entries(TYPE_INFO).map(([type, t]) => ({ type, label: t.label, params: t.params, usesFor: t.usesFor, assetType: t.assetType })),
    rules: rows.map((r) => ({
      id: r.id,
      name: r.name,
      type: r.type,
      typeLabel: TYPE_INFO[r.type]?.label ?? r.type,
      assetId: r.asset_id,
      assetName: r.asset_name,
      params: { ...TYPE_INFO[r.type]?.params, ...parseJson<Record<string, number>>(r.params, {}) },
      severity: r.severity,
      forSec: r.for_sec,
      cooldownSec: r.cooldown_sec,
      enabled: !!r.enabled,
      builtin: !!r.builtin,
      active: firing.get(r.id) ?? 0,
    })),
  });
});

function parseRule(b: Record<string, unknown>, existing?: Rule) {
  const type = existing ? existing.type : oneOf(b.type, 'Type', ALERT_TYPES)!;
  const info = TYPE_INFO[type];
  const params = { ...info.params, ...(existing ? parseJson<Record<string, number>>(existing.params, {}) : {}) };
  if (b.params && typeof b.params === 'object') {
    for (const k of Object.keys(info.params)) {
      const v = (b.params as Record<string, unknown>)[k];
      if (v !== undefined) params[k] = num(v, k, { min: 1, max: 1_000_000 })!;
    }
  }
  let assetId: number | null = existing?.asset_id ?? null;
  if (b.assetId !== undefined) {
    assetId = b.assetId === null || b.assetId === '' ? null : num(b.assetId, 'Asset', { int: true })!;
    if (assetId != null) {
      const a = get<{ type: string }>('SELECT type FROM assets WHERE id = ?', assetId);
      if (!a) throw new HttpError(400, 'Asset not found');
      if (info.assetType && a.type !== info.assetType) throw new HttpError(400, `This rule type applies to ${info.assetType} assets`);
    }
  }
  return {
    type,
    name: str(b.name, 'Name', { optional: !!existing, max: 80 }) ?? existing!.name,
    severity: b.severity !== undefined ? oneOf(b.severity, 'Severity', SEVERITIES)! : (existing?.severity ?? 'high'),
    forSec: b.forSec !== undefined ? num(b.forSec, 'Duration', { min: 0, max: 86400, int: true })! : (existing?.for_sec ?? 0),
    cooldownSec: b.cooldownSec !== undefined ? num(b.cooldownSec, 'Reminder interval', { min: 300, max: 7 * 86400, int: true })! : (existing?.cooldown_sec ?? 3600),
    enabled: b.enabled !== undefined ? (b.enabled ? 1 : 0) : (existing?.enabled ?? 1),
    assetId,
    params,
  };
}

alertsRouter.post('/rules', stepUp, (req, res) => {
  const r = parseRule(body(req));
  const out = run(
    'INSERT INTO alert_rules (name, type, asset_id, params, severity, for_sec, cooldown_sec, enabled, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
    r.name, r.type, r.assetId, JSON.stringify(r.params), r.severity, r.forSec, r.cooldownSec, r.enabled,
  );
  audit('alert_rule.created', { ip: clientIp(req), resourceType: 'alert_rule', resourceId: Number(out.lastInsertRowid), detail: r });
  publish('alerts');
  res.status(201).json({ id: Number(out.lastInsertRowid) });
});

alertsRouter.put('/rules/:id', stepUp, (req, res) => {
  const id = idParam(req);
  const existing = get<Rule>('SELECT * FROM alert_rules WHERE id = ?', id);
  if (!existing) throw new HttpError(404, 'Not found');
  const r = parseRule(body(req), existing);
  run(
    'UPDATE alert_rules SET name = ?, asset_id = ?, params = ?, severity = ?, for_sec = ?, cooldown_sec = ?, enabled = ? WHERE id = ?',
    r.name, r.assetId, JSON.stringify(r.params), r.severity, r.forSec, r.cooldownSec, r.enabled, id,
  );
  audit('alert_rule.updated', { ip: clientIp(req), resourceType: 'alert_rule', resourceId: id, detail: r });
  publish('alerts');
  res.json({ ok: true });
});

alertsRouter.delete('/rules/:id', stepUp, (req, res) => {
  const id = idParam(req);
  const r = get<Rule>('SELECT * FROM alert_rules WHERE id = ?', id);
  if (!r) throw new HttpError(404, 'Not found');
  if (r.builtin) throw new HttpError(400, 'Built-in rules can be disabled but not deleted');
  run("UPDATE alert_events SET status = 'resolved', resolved_at = ? WHERE rule_id = ? AND status != 'resolved'", Date.now(), id);
  run('DELETE FROM alert_rules WHERE id = ?', id);
  audit('alert_rule.deleted', { ip: clientIp(req), resourceType: 'alert_rule', resourceId: id, detail: { name: r.name } });
  publish('alerts');
  res.json({ ok: true });
});
