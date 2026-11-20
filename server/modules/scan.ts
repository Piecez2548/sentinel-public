import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Router } from 'express';
import { all, get, getJsonSetting, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { body, clientIp, HttpError, num, oneOf } from '../lib/http.js';
import { L } from '../lib/i18n.js';
import { needsAttention, THREAT_EVENT_IDS, threatHistory } from '../lib/threats.js';
import { escHtml, HOUR, MIN, parseJson } from '../lib/util.js';
import { requireStepUp, stepUp, userAgentOf } from './auth.js';
import { AUTO_SCAN_KEY, autoScanConfig, autoScanInfo } from './weekly.js';
import { deviceLabel } from './login-watch.js';
import { enqueue } from './notify.js';
import { dryRun } from './power.js';

/**
 * Microsoft Defender scans from the phone: start a quick, full or offline scan, see what is running,
 * and get the result on Telegram when a scan ends. Defender does the scanning; SENTINEL only starts it
 * (MpCmdRun / Start-MpWDOScan) and reads Defender's own scan events (1000 start, 1001 done, 1002 stopped,
 * 1005 failed, 1116/1117 threats) that the event log collector stores.
 */

export const SCAN_TYPES = ['quick', 'full', 'offline'] as const;
export type ScanType = (typeof SCAN_TYPES)[number];

const PARAM_OF: Record<ScanType, string> = { quick: 'Quick Scan', full: 'Full Scan', offline: 'Offline Scan' };
const TH_OF: Record<string, string> = { 'Quick Scan': 'สแกนด่วน', 'Full Scan': 'สแกนเต็ม', 'Custom Scan': 'สแกนเฉพาะจุด', 'Offline Scan': 'สแกนแบบ Offline' };

type Requested = { type: ScanType; at: number; device: string; auto?: boolean };
const REQUEST_KEY = 'defender_scan_requested';

/* ---------- reading scan events ---------- */

type Row = { id: number; event_id: number; ts: number; fields: string };
export type ScanEvent = { id: number; eventId: number; ts: number; scanId: string; param: string; trigger: string; stopReason: string; stopIndex: string; durationSec: number | null };

const toEvent = (r: Row): ScanEvent => {
  const f = parseJson<Record<string, string>>(r.fields, {});
  const h = Number(f['Scan Time Hours']);
  const m = Number(f['Scan Time Minutes']);
  const s = Number(f['Scan Time Seconds']);
  return {
    id: r.id,
    eventId: r.event_id,
    ts: r.ts,
    scanId: f['Scan ID'] ?? '',
    param: f['Scan Parameters'] ?? '?',
    trigger: f['Scan Trigger'] ?? '',
    stopReason: f['Stop Reason'] ?? '',
    stopIndex: f['Stop Reason Index'] ?? '',
    durationSec: Number.isFinite(h + m + s) && f['Scan Time Seconds'] != null ? h * 3600 + m * 60 + s : null,
  };
};

const DEFENDER = 'Microsoft-Windows-Windows Defender/Operational';
const scanRows = (sinceTs: number) =>
  all<Row>(`SELECT id, event_id, ts, fields FROM log_events WHERE channel = ? AND event_id IN (1000,1001,1002,1005) AND ts >= ? ORDER BY ts`, DEFENDER, sinceTs).map(toEvent);

/** A scheduled scan Defender skipped on purpose (1002, "last scan within 7 days") is not a real stop. */
export const isSkip = (e: ScanEvent) => e.eventId === 1002 && /skipped/i.test(e.stopReason);

export type ScanRun = { scanId: string; param: string; trigger: string; startedAt: number | null; endedAt: number | null; outcome: 'running' | 'done' | 'stopped' | 'failed'; durationSec: number | null; stopReason: string };

/** Pairs start and end events by Scan ID. Pure; exported for tests. */
export function pairScans(events: ScanEvent[], now = Date.now()): ScanRun[] {
  const runs = new Map<string, ScanRun>();
  for (const e of events) {
    if (isSkip(e)) {
      runs.delete(e.scanId);
      continue;
    }
    const r = runs.get(e.scanId) ?? { scanId: e.scanId, param: e.param, trigger: e.trigger, startedAt: null, endedAt: null, outcome: 'running' as const, durationSec: null, stopReason: '' };
    if (e.eventId === 1000) {
      r.startedAt = e.ts;
      r.trigger ||= e.trigger;
    } else {
      r.endedAt = e.ts;
      r.outcome = e.eventId === 1001 ? 'done' : e.eventId === 1002 ? 'stopped' : 'failed';
      r.durationSec = e.durationSec ?? (r.startedAt ? Math.round((e.ts - r.startedAt) / 1000) : null);
      r.stopReason = e.stopReason;
    }
    runs.set(e.scanId, r);
  }
  // A start with no end for over a day is a scan Windows never reported back on (e.g. PC turned off mid-scan).
  return [...runs.values()].filter((r) => r.outcome !== 'running' || (r.startedAt ?? 0) > now - 24 * HOUR);
}

const threatsBetween = (from: number, to: number) =>
  all<{ fields: string }>(`SELECT fields FROM log_events WHERE channel = ? AND event_id = 1116 AND ts BETWEEN ? AND ?`, DEFENDER, from, to).map((r) => {
    const f = parseJson<Record<string, string>>(r.fields, {});
    return f['Threat Name'] || 'threat';
  });

export function scanStatus(now = Date.now()) {
  const runs = pairScans(scanRows(now - 60 * 24 * HOUR), now);
  const running = runs.filter((r) => r.outcome === 'running').at(-1) ?? null;
  const req = getJsonSetting<Requested | null>(REQUEST_KEY, null);
  // Clicked a moment ago but Defender has not logged the start yet (the collector reads every 30 s).
  const starting = req && now - req.at < 3 * MIN && !(running && (running.startedAt ?? 0) >= req.at - MIN) ? req : null;
  const lastOf = (param: string) => runs.filter((r) => r.param === param && r.outcome === 'done').at(-1) ?? null;
  const history = runs
    .filter((r) => r.outcome !== 'running')
    .slice(-8)
    .reverse()
    .map((r) => ({ ...r, threats: r.startedAt && r.endedAt ? threatsBetween(r.startedAt, r.endedAt).length : 0 }));
  return { running, starting, lastQuick: lastOf('Quick Scan'), lastFull: lastOf('Full Scan'), history, dryRun: dryRun() };
}

/* ---------- Telegram when a scan ends ---------- */

const fmtDur = (sec: number | null, th: boolean) => {
  if (sec == null) return '';
  const h = Math.floor(sec / 3600);
  const m = Math.round((sec % 3600) / 60);
  return th ? (h ? `${h} ชม. ${m} นาที` : `${m} นาที`) : h ? `${h} h ${m} min` : `${m} min`;
};

/** Message for a finished scan, or null when it is not worth a notification. Pure; exported for tests. */
export function scanResultMessage(r: ScanRun, threats: string[], requested: boolean): { en: string; th: string } | null {
  // Defender runs a quick scan by itself most days: only report those when asked for, or when something was found.
  if (r.param === 'Quick Scan' && !requested && !threats.length && r.outcome === 'done') return null;
  if (r.outcome === 'running') return null;
  const nameTh = TH_OF[r.param] ?? r.param;
  const dur = { th: fmtDur(r.durationSec, true), en: fmtDur(r.durationSec, false) };
  const list = [...new Set(threats)].slice(0, 5);
  if (threats.length)
    return {
      th: `🔴 <b>${escHtml(nameTh)}เสร็จแล้ว — พบภัยคุกคาม ${threats.length} รายการ</b>\n${list.map((t) => `• ${escHtml(t)}`).join('\n')}\n\nDefender จัดการให้แล้วหรือยัง ดูได้ที่ Windows Security → ประวัติการป้องกัน\n👉 แนะนำ: สแกนแบบ Offline อีกรอบ แล้วเปลี่ยนรหัสผ่านสำคัญ`,
      en: `🔴 <b>${escHtml(r.param)} finished — ${threats.length} threat(s) found</b>\n${list.map((t) => `• ${escHtml(t)}`).join('\n')}\n\nCheck Windows Security → Protection history for what Defender did.\n👉 Suggested: run an Offline scan, then change important passwords`,
    };
  if (r.outcome === 'done')
    return {
      th: `✅ <b>${escHtml(nameTh)}เสร็จแล้ว — ไม่พบภัยคุกคาม</b>${dur.th ? `\nใช้เวลา ${dur.th}` : ''}`,
      en: `✅ <b>${escHtml(r.param)} finished — no threats found</b>${dur.en ? `\nTook ${dur.en}` : ''}`,
    };
  return {
    th: `⚠️ <b>${escHtml(nameTh)}${r.outcome === 'failed' ? 'ล้มเหลว' : 'หยุดกลางคัน'}</b>${r.stopReason ? `\n${escHtml(r.stopReason)}` : ''}\nสแกนใหม่ได้จากหน้า สุขภาพเครื่อง`,
    en: `⚠️ <b>${escHtml(r.param)} ${r.outcome === 'failed' ? 'failed' : 'was stopped'}</b>${r.stopReason ? `\n${escHtml(r.stopReason)}` : ''}\nStart it again from Device health`,
  };
}

/** Called by detection with each batch of new log events. */
export function notifyFinishedScans(batch: { channel?: string; event_id: number; ts: number; id: number }[], now = Date.now()) {
  const ends = batch.filter((e) => [1001, 1002, 1005].includes(e.event_id) && now - e.ts < 6 * HOUR);
  if (!ends.length) return;
  const runs = pairScans(scanRows(now - 3 * 24 * HOUR), now);
  const req = getJsonSetting<Requested | null>(REQUEST_KEY, null);
  for (const end of ends) {
    const row = get<Row>('SELECT id, event_id, ts, fields FROM log_events WHERE id = ?', end.id);
    if (!row) continue;
    const ev = toEvent(row);
    if (isSkip(ev)) continue;
    const r = runs.find((x) => x.scanId === ev.scanId);
    if (!r) continue;
    const start = r.startedAt ?? ev.ts - (ev.durationSec ?? 0) * 1000;
    // The weekly automatic scan stays quiet when clean (it is in the weekly summary); threats are always sent.
    const requested = !!req && !req.auto && req.type !== 'offline' && r.param === PARAM_OF[req.type] && start >= req.at - MIN && start <= req.at + 10 * MIN;
    const msg = scanResultMessage(r, threatsBetween(start, ev.ts + 5 * MIN), requested);
    if (msg) enqueue('system', `scan:${ev.scanId}`, L(msg.en, msg.th));
  }
  publish('device');
}

/** Scan runs (start/end paired) since a time. */
export const scanRunsSince = (ts: number, now = Date.now()) => pairScans(scanRows(ts), now);

/* ---------- starting / cancelling ---------- */

function mpCmdRun(): string {
  const fixed = join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Windows Defender', 'MpCmdRun.exe');
  if (existsSync(fixed)) return fixed;
  throw new HttpError(500, 'Microsoft Defender command-line tool not found');
}

function launch(file: string, args: string[]) {
  if (dryRun()) {
    console.log(`[scan] dry run: would run ${file} ${args.join(' ')}`);
    return;
  }
  // Detached: a full scan runs for hours, long after this request has been answered.
  const child = spawn(file, args, { detached: true, stdio: 'ignore', windowsHide: true });
  child.on('error', (e) => console.error('[scan] could not start:', e.message));
  child.unref();
}

/** Starts a Defender scan (nothing runs under LOCAL_TEST / POWER_DRY_RUN). Callers check that none is running. */
export function startScan(type: ScanType, device: string, auto = false) {
  if (type === 'offline') launch('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Start-MpWDOScan']);
  else launch(mpCmdRun(), ['-Scan', '-ScanType', type === 'quick' ? '1' : '2']);
  setSetting(REQUEST_KEY, JSON.stringify({ type, at: Date.now(), device, ...(auto ? { auto } : {}) } satisfies Requested));
}

export const scanRouter = Router();

scanRouter.get('/', (_req, res) => {
  res.json({ ...scanStatus(), auto: autoScanInfo() });
});

/** Weekly automatic quick scan on/off and when (owner's choice). */
scanRouter.post('/auto', stepUp, (req, res) => {
  const b = body(req);
  const cfg = { ...autoScanConfig() };
  if (b.enabled !== undefined) cfg.enabled = !!b.enabled;
  if (b.day !== undefined) cfg.day = num(b.day, 'day', { min: 0, max: 6, int: true })!;
  if (b.hour !== undefined) cfg.hour = num(b.hour, 'hour', { min: 0, max: 23, int: true })!;
  setSetting(AUTO_SCAN_KEY, JSON.stringify(cfg));
  audit('defender.auto_scan_changed', { ip: clientIp(req), detail: cfg });
  publish('device');
  res.json({ ok: true, auto: autoScanInfo() });
});

/** Threat history: what Defender found in the last 90 days and whether it dealt with it (server/lib/threats.ts). */
scanRouter.get('/threats', (_req, res) => {
  const now = Date.now();
  const rows = all<{ event_id: number; ts: number; fields: string }>(
    `SELECT event_id, ts, fields FROM log_events WHERE channel = ? AND event_id IN (${THREAT_EVENT_IDS.join(',')}) AND ts >= ? ORDER BY ts`,
    DEFENDER,
    now - 90 * 24 * HOUR,
  );
  const threats = threatHistory(rows.map((r) => ({ ...r, fields: parseJson<Record<string, string>>(r.fields, {}) })));
  res.json({ threats: threats.map((t) => ({ ...t, attention: needsAttention(t, now) })), days: 90 });
});

scanRouter.post('/', (req, res) => {
  const b = body(req);
  const type = oneOf(b.type, 'type', SCAN_TYPES)!;
  requireStepUp(req, b.code);
  const st = scanStatus();
  if (st.running || st.starting) throw new HttpError(409, 'A scan is already running');
  const device = deviceLabel(userAgentOf(req));
  startScan(type, device);
  audit('defender.scan_started', { ip: clientIp(req), detail: { type, device, dryRun: dryRun() } });
  const th = TH_OF[PARAM_OF[type]];
  enqueue('system', 'scan', `🔍 <b>${escHtml(L(`${PARAM_OF[type]} started from ${device}`, `เริ่ม${th}จาก ${device}`))}</b>${type === 'offline' ? `\n${escHtml(L('The PC restarts now and scans before Windows starts (~15 min).', 'เครื่องจะรีสตาร์ทและสแกนก่อนเข้า Windows (~15 นาที)'))}` : ''}`);
  publish('device');
  res.json({ ok: true, type, dryRun: dryRun() });
});

scanRouter.post('/cancel', (req, res) => {
  requireStepUp(req, body(req).code);
  launch(mpCmdRun(), ['-Scan', '-Cancel']);
  setSetting(REQUEST_KEY, 'null');
  audit('defender.scan_cancelled', { ip: clientIp(req), detail: { dryRun: dryRun() } });
  publish('device');
  res.json({ ok: true, dryRun: dryRun() });
});
