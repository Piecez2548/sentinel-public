import { execFile } from 'node:child_process';
import { Router } from 'express';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { body, clientIp, HttpError, num, oneOf } from '../lib/http.js';
import { L } from '../lib/i18n.js';
import { escHtml } from '../lib/util.js';
import { requireStepUp, userAgentOf } from './auth.js';
import { deviceLabel } from './login-watch.js';
import { enqueue } from './notify.js';

/**
 * Remote power control of the PC SENTINEL runs on (from the phone over Tailscale).
 * Every action needs 2FA (one code unlocks the page for 15 min, see requireStepUp), is audited and announced on Telegram.
 * Shutdown/restart always give a visible on-screen countdown (≥ 60 s) and can be cancelled.
 *
 * Safety for development: with LOCAL_TEST=1 (tests, preview servers) or POWER_DRY_RUN=1 nothing is
 * executed — the command is only logged — so working on SENTINEL can never switch the PC off.
 */

export const POWER_ACTIONS = ['lock', 'sleep', 'hibernate', 'restart', 'shutdown'] as const;
export type PowerAction = (typeof POWER_ACTIONS)[number];

const MIN_COUNTDOWN_SEC = 60;
const MAX_DELAY_MIN = 12 * 60;
/** Sleep/hibernate right away still waits a few seconds so the reply and the Telegram message get out first. */
const GRACE_MS = 8_000;

export const dryRun = () => process.env.LOCAL_TEST === '1' || process.env.POWER_DRY_RUN === '1';

type Pending = { action: PowerAction; at: number; requestedAt: number; device: string };
let pending: Pending | null = null;
let timer: NodeJS.Timeout | null = null;
/** Last commands "run" in dry-run mode, for tests. */
export const dryRunLog: string[] = [];

const LABEL: Record<PowerAction, { en: string; th: string; icon: string }> = {
  lock: { en: 'Lock screen', th: 'ล็อกหน้าจอ', icon: '🔒' },
  sleep: { en: 'Sleep', th: 'Sleep', icon: '😴' },
  hibernate: { en: 'Hibernate', th: 'Hibernate (ปิดแบบจำงานไว้)', icon: '💤' },
  restart: { en: 'Restart', th: 'รีสตาร์ท', icon: '🔄' },
  shutdown: { en: 'Shut down', th: 'ปิดเครื่อง', icon: '🛑' },
};

function run(exe: string, args: string[]) {
  if (dryRun()) {
    dryRunLog.push([exe, ...args].join(' '));
    console.log(`[power] dry run: ${exe} ${args.join(' ')}`);
    return;
  }
  execFile(exe, args, { windowsHide: true, timeout: 30_000 }, (err) => {
    if (err) console.error(`[power] ${exe} failed:`, err.message);
  });
}

const ps = (script: string) => run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);

/** Runs the action now (shutdown/restart get Windows' own countdown of `countdownSec`). */
function execute(action: PowerAction, countdownSec = MIN_COUNTDOWN_SEC) {
  const note = 'SENTINEL: remote command from your phone. Save your work. Cancel from SENTINEL.';
  switch (action) {
    case 'lock':
      return run('rundll32.exe', ['user32.dll,LockWorkStation']);
    case 'sleep':
      // This laptop uses Modern Standby (S0): turning the display off is exactly what the power button does.
      return ps(
        "Add-Type -Namespace S -Name M -MemberDefinition '[DllImport(\"user32.dll\")] public static extern int SendMessage(int h, int m, int w, int l);'; [S.M]::SendMessage(0xFFFF, 0x0112, 0xF170, 2) | Out-Null",
      );
    case 'hibernate':
      return run('shutdown.exe', ['/h']);
    case 'restart':
      return run('shutdown.exe', ['/r', '/t', String(countdownSec), '/c', note]);
    case 'shutdown':
      return run('shutdown.exe', ['/s', '/t', String(countdownSec), '/c', note]);
  }
}

function clearPending() {
  if (timer) clearTimeout(timer);
  timer = null;
  pending = null;
}

/** Schedules (or runs) an action. delaySec 0 = now (with the minimum countdown for shutdown/restart). */
export function schedule(action: PowerAction, delaySec: number, device: string, now = Date.now()): Pending {
  clearPending();
  const usesWindowsTimer = action === 'restart' || action === 'shutdown';
  if (usesWindowsTimer) {
    // Windows keeps the timer (survives SENTINEL restarts) and shows the countdown on screen.
    const sec = Math.max(MIN_COUNTDOWN_SEC, delaySec);
    run('shutdown.exe', ['/a']); // replace any earlier schedule
    execute(action, sec);
    pending = { action, at: now + sec * 1000, requestedAt: now, device };
  } else {
    const ms = action === 'lock' && delaySec === 0 ? 0 : Math.max(GRACE_MS, delaySec * 1000);
    pending = { action, at: now + ms, requestedAt: now, device };
    if (ms === 0) {
      execute(action);
      pending = null;
    } else {
      timer = setTimeout(() => {
        pending = null;
        timer = null;
        execute(action);
        publish('power');
      }, ms);
      timer.unref();
    }
  }
  return pending ?? { action, at: now, requestedAt: now, device };
}

export function cancelPending(): Pending | null {
  const was = pending;
  if (was && (was.action === 'restart' || was.action === 'shutdown')) run('shutdown.exe', ['/a']);
  clearPending();
  return was;
}

export const getPending = () => pending;

function when(ms: number) {
  const min = Math.round(ms / 60_000);
  if (ms < 90_000) return L(`in ${Math.max(1, Math.round(ms / 1000))} s`, `ในอีก ${Math.max(1, Math.round(ms / 1000))} วินาที`);
  return L(`in ${min} min`, `ในอีก ${min} นาที`);
}

/* ---------- API ---------- */

export const powerRouter = Router();

powerRouter.get('/', (_req, res) => {
  res.json({ pending, dryRun: dryRun(), actions: POWER_ACTIONS });
});

powerRouter.post('/action', (req, res) => {
  const b = body(req);
  const action = oneOf(b.action, 'Action', POWER_ACTIONS)!;
  const delayMin = num(b.delayMin, 'Delay', { optional: true, min: 0, max: MAX_DELAY_MIN, int: true }) ?? 0;
  requireStepUp(req, b.code);

  const device = deviceLabel(userAgentOf(req));
  const p = schedule(action, delayMin * 60, device);
  const lab = LABEL[action];
  const inMs = p.at - Date.now();
  audit('power.action', { ip: clientIp(req), detail: { action, delayMin, device, dryRun: dryRun() } });
  const quiet = action === 'lock' ? '' : L('\nSENTINEL will be silent until the PC is back on — that is expected.', '\nSENTINEL จะเงียบไปจนกว่าเครื่องจะกลับมาเปิด — เป็นเรื่องปกติ');
  enqueue(
    'system',
    'power',
    `${lab.icon} <b>${escHtml(L(`Remote command: ${lab.en}`, `สั่งเครื่องจากระยะไกล: ${lab.th}`))}</b>\n` +
      escHtml(L(`From ${device} · ${action === 'lock' && inMs <= 0 ? 'now' : when(inMs)}`, `จาก ${device} · ${action === 'lock' && inMs <= 0 ? 'ทันที' : when(inMs)}`)) +
      escHtml(quiet) +
      escHtml(L("\n\nIf this wasn't you: open SENTINEL → Power → Cancel, then change your password.", '\n\nถ้าไม่ใช่คุณ: เปิด SENTINEL → ควบคุมเครื่อง → ยกเลิก แล้วเปลี่ยนรหัสผ่าน')),
  );
  publish('power');
  res.json({ ok: true, pending: getPending(), dryRun: dryRun() });
});

/** Cancelling is always safe, so it needs no code. */
powerRouter.post('/cancel', (req, res) => {
  const was = cancelPending();
  if (!was) throw new HttpError(404, 'Nothing is scheduled');
  audit('power.cancel', { ip: clientIp(req), detail: { action: was.action } });
  enqueue('system', 'power', `✋ <b>${escHtml(L(`Cancelled: ${LABEL[was.action].en}`, `ยกเลิกแล้ว: ${LABEL[was.action].th}`))}</b>`);
  publish('power');
  res.json({ ok: true });
});
