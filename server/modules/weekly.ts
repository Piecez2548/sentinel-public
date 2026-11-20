import { existsSync, readdirSync } from 'node:fs';
import { all, getJsonSetting, getSetting, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { checkParts } from '../lib/device-messages.js';
import { notifyLang } from '../lib/i18n.js';
import { needsAttention, THREAT_EVENT_IDS, threatHistory } from '../lib/threats.js';
import { DAY, parseJson } from '../lib/util.js';
import { AUTO_SCAN_DEFAULT, autoScanDecision, lastSlot, weekKey, weeklySummary, type AutoScan, type WeeklyData } from '../lib/weekly.js';
import { BACKUP_COPY_DIR, lastDrill, listBackups, PASS_CHECKED } from './backup.js';
import { programEvents, type Check } from './device-health.js';
import { dryRun } from './power.js';
import { runningGame } from './processes.js';
import { scanRunsSince, scanStatus, startScan } from './scan.js';

/**
 * Weekly routine (owner asked 2026-11-17): a Defender quick scan every week, and a weekly section in
 * the first daily summary of each week. See lib/weekly.ts for the rules.
 */

export const AUTO_SCAN_KEY = 'auto_scan';
const AUTO_LAST_KEY = 'auto_scan_last';
const WEEK_KEY = 'weekly_summary_week';
const DEFENDER = 'Microsoft-Windows-Windows Defender/Operational';

export const autoScanConfig = (): AutoScan => ({ ...AUTO_SCAN_DEFAULT, ...getJsonSetting<Partial<AutoScan>>(AUTO_SCAN_KEY, {}) });

export function autoScanInfo(now = Date.now()) {
  const cfg = autoScanConfig();
  const lastAuto = Number(getSetting(AUTO_LAST_KEY)) || null;
  const slot = lastSlot(now, cfg.day, cfg.hour);
  return { ...cfg, lastAt: lastAuto, nextAt: slot + 7 * DAY };
}

/** Ticks every 5 minutes. */
export function maybeAutoScan(now = Date.now()) {
  const cfg = autoScanConfig();
  const st = scanStatus(now);
  const ends = [st.lastQuick?.endedAt, st.lastFull?.endedAt].filter((n): n is number => n != null);
  const d = autoScanDecision({
    cfg, now,
    lastAuto: Number(getSetting(AUTO_LAST_KEY)) || 0,
    lastScanEnd: ends.length ? Math.max(...ends) : null,
    scanBusy: !!(st.running || st.starting),
    gameRunning: !!runningGame(),
  });
  if (d === 'covered') setSetting(AUTO_LAST_KEY, String(now));
  if (d !== 'run') return;
  startScan('quick', 'SENTINEL (weekly)', true);
  setSetting(AUTO_LAST_KEY, String(now));
  audit('defender.scan_auto', { detail: { type: 'quick', dryRun: dryRun() } });
}

/* ---------- weekly summary ---------- */

export function weeklyData(now: number, th: boolean): WeeklyData {
  const from = now - 7 * DAY;
  const rows = all<{ event_id: number; ts: number; fields: string }>(
    `SELECT event_id, ts, fields FROM log_events WHERE channel = ? AND event_id IN (${THREAT_EVENT_IDS.join(',')}) AND ts >= ? ORDER BY ts`,
    DEFENDER, from,
  );
  const threats = threatHistory(rows.map((r) => ({ ...r, fields: parseJson<Record<string, string>>(r.fields, {}) })));
  const runs = scanRunsSince(from, now).filter((r) => r.param === 'Quick Scan' || r.param === 'Full Scan' || r.param === 'Offline Scan');
  const st = scanStatus(now);
  const prog = programEvents().filter((e) => e.at >= from);
  const findings = Object.fromEntries(
    all<{ severity: string; n: number }>("SELECT severity, COUNT(*) AS n FROM security_findings WHERE status IN ('open','acknowledged') GROUP BY severity").map((r) => [r.severity, r.n]),
  );
  let sealed: number | null = null;
  if (BACKUP_COPY_DIR && existsSync(BACKUP_COPY_DIR)) {
    try {
      sealed = readdirSync(BACKUP_COPY_DIR).filter((n) => n.endsWith('.sbk')).length;
    } catch {
      sealed = null;
    }
  }
  const latest = parseJson<{ checks?: Check[] } | null>(getSetting('device_health_latest'), null);
  const upd = latest?.checks?.find((c) => c.id === 'updates' && c.status !== 'ok' && c.status !== 'unknown');
  const lastAuto = Number(getSetting(AUTO_LAST_KEY)) || 0;
  return {
    from,
    to: now,
    threats: { total: threats.length, attention: threats.filter((t) => needsAttention(t, now)).length, names: threats.map((t) => t.name) },
    scans: {
      done: runs.filter((r) => r.outcome === 'done').length,
      failed: runs.filter((r) => r.outcome === 'failed' || r.outcome === 'stopped').length,
      lastQuick: st.lastQuick?.endedAt ?? null,
      lastFull: st.lastFull?.endedAt ?? null,
      autoRan: lastAuto >= from,
    },
    programs: { added: prog.filter((e) => e.kind === 'added').map((e) => ({ name: e.name, severity: e.severity })), removed: prog.filter((e) => e.kind === 'removed').length },
    findings,
    backup: { lastAt: listBackups()[0]?.createdAt ?? null, sealed, drill: ((d) => (d && !d.skipped ? { ok: d.ok, at: d.at } : null))(lastDrill()), passCheckDue: !!getSetting('backup_seal') && now - (Number(getSetting(PASS_CHECKED)) || 0) > 90 * DAY },
    updates: upd ? checkParts(upd, th).head : null,
  };
}

/** Adds the weekly section to the first daily summary of each week (Monday, or the first day the PC is on). */
export function withWeekly(digest: string, now = Date.now()): string {
  if (getSetting('weekly_summary_enabled') === 'false') return digest;
  const key = weekKey(now);
  if (getSetting(WEEK_KEY) === key) return digest;
  setSetting(WEEK_KEY, key);
  const th = notifyLang() === 'th';
  try {
    return `${digest}\n\n${weeklySummary(weeklyData(now, th), th)}`;
  } catch (e) {
    console.error('[weekly] summary failed:', e instanceof Error ? e.message : e);
    return digest;
  }
}
