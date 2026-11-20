import { escHtml } from './util.js';

/**
 * Weekly routine (added 2026-11-17, owner asked): SENTINEL starts a Defender quick scan once a week by
 * itself, and the first daily summary of each week carries a weekly section (threats, scans, new
 * programs, open findings, backups). Pure helpers; I/O is in modules/weekly.ts.
 */

export type AutoScan = { enabled: boolean; day: number; hour: number };
export const AUTO_SCAN_DEFAULT: AutoScan = { enabled: true, day: 0, hour: 20 }; // Sunday 20:00
/** A slot missed because the PC was off is caught up within this time; after that, wait for next week. */
export const CATCH_UP_MS = 3 * 86_400_000;

/** The most recent scheduled time at or before `now` (local time). */
export function lastSlot(now: number, day: number, hour: number): number {
  const d = new Date(now);
  d.setHours(hour, 0, 0, 0);
  d.setDate(d.getDate() - ((d.getDay() - day + 7) % 7));
  if (d.getTime() > now) d.setDate(d.getDate() - 7);
  return d.getTime();
}

export type AutoDecision = 'run' | 'wait' | 'done' | 'covered' | 'off';

/**
 * run: start the quick scan now. wait: not now, try on the next tick (game running, a scan in progress).
 * done: nothing to do for this slot. covered: a scan finished in the last 24 h anyway, so mark this
 * week's slot as handled without scanning again. off: disabled.
 */
export function autoScanDecision(o: { cfg: AutoScan; now: number; lastAuto: number; lastScanEnd: number | null; scanBusy: boolean; gameRunning: boolean }): AutoDecision {
  if (!o.cfg.enabled) return 'off';
  const slot = lastSlot(o.now, o.cfg.day, o.cfg.hour);
  if (o.lastAuto >= slot || o.now - slot > CATCH_UP_MS) return 'done';
  // A quick or full scan already finished in the last 24 h (Defender's own, or one started by hand): enough.
  if (o.lastScanEnd != null && o.now - o.lastScanEnd < 86_400_000) return 'covered';
  if (o.scanBusy || o.gameRunning) return 'wait';
  return 'run';
}

/** "2026-W47": the first digest in a new week carries the weekly section. Weeks start on Monday. */
export function weekKey(ts: number): string {
  const d = new Date(ts);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() + 3 - ((d.getDay() + 6) % 7));
  const y = d.getFullYear();
  const jan4 = new Date(y, 0, 4);
  const w = 1 + Math.round(((d.getTime() - jan4.getTime()) / 86_400_000 - 3 + ((jan4.getDay() + 6) % 7)) / 7);
  return `${y}-W${String(w).padStart(2, '0')}`;
}

export type WeeklyData = {
  from: number;
  to: number;
  threats: { total: number; attention: number; names: string[] };
  scans: { done: number; failed: number /* failed or stopped */; lastQuick: number | null; lastFull: number | null; autoRan: boolean };
  programs: { added: { name: string; severity?: string }[]; removed: number };
  findings: Record<string, number>; // open findings by severity
  backup: { lastAt: number | null; sealed: number | null; drill?: { ok: boolean; at: number } | null; passCheckDue?: boolean };
  updates: string | null; // device-health "updates" check text when it is not ok
};

const SEV_TH: Record<string, string> = { critical: 'วิกฤต', high: 'สูง', medium: 'กลาง', low: 'ต่ำ' };
const ICON: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' };
const ORDER = ['critical', 'high', 'medium', 'low'];

const dm = (ts: number) => {
  const d = new Date(ts);
  return `${d.getDate()}/${d.getMonth() + 1}`;
};
const daysAgo = (ts: number | null, now: number) => (ts == null ? null : Math.floor((now - ts) / 86_400_000));

export function weeklySummary(w: WeeklyData, th: boolean): string {
  const lines: string[] = [];
  const now = w.to;
  lines.push(th ? `📅 <b>สรุปประจำสัปดาห์ (${dm(w.from)} – ${dm(w.to)})</b>` : `📅 <b>Weekly summary (${dm(w.from)} – ${dm(w.to)})</b>`);

  if (!w.threats.total) lines.push(th ? '🛡️ ภัยคุกคาม: ไม่พบ' : '🛡️ Threats: none');
  else {
    const names = escHtml(w.threats.names.slice(0, 3).join(', '));
    lines.push(
      w.threats.attention
        ? th ? `🛡️ ภัยคุกคาม: พบ ${w.threats.total} — ⚠️ ต้องดู ${w.threats.attention} รายการ (${names})` : `🛡️ Threats: ${w.threats.total} — ⚠️ ${w.threats.attention} need a look (${names})`
        : th ? `🛡️ ภัยคุกคาม: พบ ${w.threats.total} — Defender จัดการครบแล้ว (${names})` : `🛡️ Threats: ${w.threats.total} — Defender dealt with all (${names})`,
    );
  }

  const q = daysAgo(w.scans.lastQuick, now);
  const f = daysAgo(w.scans.lastFull, now);
  const scanBits = th
    ? [`สแกนเสร็จ ${w.scans.done} ครั้ง`, q != null ? `ด่วนล่าสุด ${q === 0 ? 'วันนี้' : `${q} วันก่อน`}` : 'ยังไม่มีสแกนด่วน', f != null ? `เต็มล่าสุด ${f === 0 ? 'วันนี้' : `${f} วันก่อน`}` : null, w.scans.failed ? `⚠️ ไม่จบ ${w.scans.failed} ครั้ง` : null]
    : [`${w.scans.done} scan(s) finished`, q != null ? `last quick ${q === 0 ? 'today' : `${q} day(s) ago`}` : 'no quick scan', f != null ? `last full ${f === 0 ? 'today' : `${f} day(s) ago`}` : null, w.scans.failed ? `⚠️ ${w.scans.failed} did not finish` : null];
  lines.push(`🔍 ${th ? 'สแกน' : 'Scans'}: ${scanBits.filter(Boolean).join(' · ')}`);

  const add = w.programs.added;
  if (!add.length && !w.programs.removed) lines.push(th ? '📦 โปรแกรม: ไม่มีติดตั้งหรือถอนใหม่' : '📦 Programs: nothing installed or removed');
  else {
    const list = add.slice(0, 5).map((p) => `${p.severity && p.severity !== 'low' ? `${ICON[p.severity]} ` : ''}${escHtml(p.name)}`).join(', ');
    lines.push(
      th
        ? `📦 โปรแกรม: ติดตั้งใหม่ ${add.length}${add.length ? ` (${list}${add.length > 5 ? ', …' : ''})` : ''} · ถอนออก ${w.programs.removed}`
        : `📦 Programs: ${add.length} installed${add.length ? ` (${list}${add.length > 5 ? ', …' : ''})` : ''} · ${w.programs.removed} removed`,
    );
  }

  const open = ORDER.filter((s) => w.findings[s]);
  lines.push(
    open.length
      ? `${th ? '📋 เรื่องที่ยังเปิดอยู่' : '📋 Open findings'}: ${open.map((s) => `${ICON[s]} ${th ? SEV_TH[s] : s} ${w.findings[s]}`).join(' · ')}`
      : th ? '📋 เรื่องที่ยังเปิดอยู่: ไม่มี' : '📋 Open findings: none',
  );

  const b = daysAgo(w.backup.lastAt, now);
  const sealed = w.backup.sealed == null ? '' : th ? ` · สำเนาเข้ารหัสบนคลาวด์ ${w.backup.sealed} ชุด` : ` · ${w.backup.sealed} encrypted cloud copies`;
  lines.push(b == null ? (th ? '💾 แบ็กอัป: ⚠️ ยังไม่มี' : '💾 Backups: ⚠️ none yet') : b > 2 ? (th ? `💾 แบ็กอัป: ⚠️ ล่าสุด ${b} วันก่อน${sealed}` : `💾 Backups: ⚠️ last ${b} day(s) ago${sealed}`) : th ? `💾 แบ็กอัป: ปกติ${sealed}` : `💾 Backups: OK${sealed}`);

  const dr = w.backup.drill;
  if (dr && !dr.ok) lines.push(th ? `🧪 ทดสอบกู้คืน: ⚠️ ไม่ผ่าน (${dm(dr.at)})` : `🧪 Restore test: ⚠️ failed (${dm(dr.at)})`);
  else if (dr) lines.push(th ? `🧪 ทดสอบกู้คืนล่าสุด: ผ่าน (${dm(dr.at)})` : `🧪 Last restore test: passed (${dm(dr.at)})`);
  if (w.backup.passCheckDue) lines.push(th ? '🔑 ลองเช็คว่ายังจำรหัสผ่านแบ็กอัปได้: ตั้งค่า → สำรองข้อมูล → ทดสอบรหัสผ่าน' : '🔑 Check you still remember the backup passphrase: Settings → Backups → Test passphrase');
  if (w.updates) lines.push(`🪟 Windows Update: ⚠️ ${escHtml(w.updates)}`);
  return lines.join('\n');
}
