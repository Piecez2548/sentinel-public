/**
 * Automated acceptance tests (docs/04-MVP-Acceptance-Test-Plan.md).
 * Starts a real SENTINEL server on a throwaway data dir and drives its API.
 *
 *   npm run test:acceptance
 *
 * Event-log driven cases (AT-21 brute force) and live Telegram delivery need
 * the real machine / a real bot and are run manually.
 */
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { currentStep, hotp } from '../server/lib/totp.js';
import { unseal } from '../server/lib/backup-seal.js';

const PORT = 3900 + Math.floor(Math.random() * 90);
const BASE = `http://127.0.0.1:${PORT}`;
const PASSWORD = 'acceptance-pass-123';
const dataDir = mkdtempSync(join(tmpdir(), 'sentinel-at-'));
const copyDir = `${dataDir}-offsite`;
// Nothing listens on port 9: every ping fails, which lets the test check the secret never leaks.
const HEARTBEAT = 'https://127.0.0.1:9/ping/heartbeat-secret-7f3a';
// What Task Manager would show: a game, a browser in two processes, and Windows Defender.
const PROCESSES = JSON.stringify({
  rows: [
    { pid: 11, name: 'fczf', cpu: 45, mem: 3100, title: 'FC Online' },
    { pid: 12, name: 'brave', cpu: 6, mem: 500, title: 'Brave Browser' },
    { pid: 13, name: 'brave#1', cpu: 4, mem: 300 },
    { pid: 14, name: 'MsMpEng', cpu: 12, mem: 300 },
  ],
  names: ['fczf', 'brave', 'msmpeng'],
});
// A compromised-looking PC (pattern seen on the lab machine): broad Defender exclusions and a fake svchost auto-start.
const DEVICE_SNAPSHOT = JSON.stringify({
  isAdmin: true,
  defender: { antivirusEnabled: true, realTimeProtection: true, tamperProtected: true, signatureAgeDays: 0, signatureVersion: '1.0', quickScanAgeDays: 0, fullScanAgeDays: 9, lastQuickScan: null },
  updates: { lastInstalled: new Date().toISOString(), lastHotfix: 'KB1', rebootPending: false },
  firewall: [{ name: 'Domain', enabled: true }, { name: 'Private', enabled: true }, { name: 'Public', enabled: true }],
  encryption: { available: false },
  disks: [{ name: 'Test SSD', media: 'SSD', sizeGb: 500, health: 'Healthy', operational: 'OK', wearPct: 1, temperatureC: 40 }],
  battery: null,
  exclusions: { paths: ['C:\\', 'C:\\Users\\Me\\AppData\\Local\\svchost.exe'], processes: ['svchost.exe'], extensions: [] },
  startup: [{ name: 'svchost', command: 'C:\\Users\\Me\\AppData\\Local\\svchost.exe', location: 'HKU\\S-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', user: 'PC\\me' }],
  tasks: [],
  software: { programs: ['Git'], services: [], apps: [{ name: 'Git 2.44.0', publisher: 'The Git Development Community' }] },
  network: { hosts: ['100.64.0.20 phone.tail.ts.net. phone'], hostsOk: true, dns: [{ iface: '{a}', name: 'Wi-Fi', servers: ['8.8.8.8'] }], dnsOk: true, proxies: [], proxyOk: true, winhttp: '', nrpt: [], nrptOk: true },
  extensions: [{ browser: 'Brave', profile: 'Default', ok: true, exts: [{ browser: 'Brave', profile: 'Default', id: 'aaaa', name: 'Dark Reader', location: 1, fromStore: true, apis: ['storage'], hosts: [] }] }],
});
let server: ChildProcess;
let logs = '';

type Res = { status: number; body: any; cookie?: string };
async function call(method: string, path: string, body?: unknown, cookie?: string, headers: Record<string, string> = {}): Promise<Res> {
  const r = await fetch(`${BASE}/api${path}`, {
    method,
    headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const setCookie = r.headers.get('set-cookie');
  return { status: r.status, body: await r.json().catch(() => null), cookie: setCookie ? setCookie.split(';')[0] : undefined };
}

async function waitFor<T>(fn: () => Promise<T | undefined | false>, timeoutMs = 30_000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for condition');
    await new Promise((r) => setTimeout(r, 500));
  }
}

function startServer(env: Record<string, string> = {}) {
  server = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
    env: { ...process.env, DATA_DIR: dataDir, PORT: String(PORT), LOCAL_TEST: '1', ANTHROPIC_API_KEY: '', BACKUP_COPY_DIR: copyDir, HEARTBEAT_URL: HEARTBEAT, SENTINEL_TEST_DEVICE_SNAPSHOT: DEVICE_SNAPSHOT, SENTINEL_TEST_PROCESSES: PROCESSES, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout!.on('data', (d) => (logs += d));
  server.stderr!.on('data', (d) => (logs += d));
  return waitFor(async () => (await fetch(`${BASE}/api/auth/state`).then((r) => r.ok).catch(() => false)) || undefined);
}

async function stopServer() {
  if (!server || server.exitCode !== null) return;
  const exited = new Promise((r) => server.once('exit', r));
  server.kill();
  await exited;
}

let session = '';

before(async () => {
  await startServer();
});
after(async () => {
  await stopServer();
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(copyDir, { recursive: true, force: true });
});

describe('Access control (AT-05/06/07)', () => {
  test('first-run setup enforces a strong password and signs in', async () => {
    assert.equal((await call('POST', '/auth/setup', { password: 'short' })).status, 400);
    const r = await call('POST', '/auth/setup', { password: PASSWORD });
    assert.equal(r.status, 200);
    assert.ok(r.cookie);
    session = r.cookie!;
    assert.equal((await call('POST', '/auth/setup', { password: PASSWORD })).status, 409, 'setup cannot run twice');
  });

  test('AT-05: protected endpoints return 401 without a session', async () => {
    for (const p of ['/overview', '/assets', '/alerts/events', '/security/findings', '/incidents', '/logs', '/reports', '/settings', '/audit', '/backups', '/notifications/channels']) {
      assert.equal((await call('GET', p)).status, 401, p);
    }
    assert.equal((await call('POST', '/assets', { type: 'website', name: 'x', url: 'https://example.com' })).status, 401);
  });

  test('cross-origin state changes are rejected', async () => {
    const r = await call('POST', '/incidents', { title: 'csrf test' }, session, { origin: 'https://evil.example' });
    assert.equal(r.status, 403);
  });

  test('AT-07: MFA — code required, replay rejected', async () => {
    const setup = await call('POST', '/auth/mfa/setup', {}, session);
    assert.equal(setup.status, 200);
    const secret = setup.body.secret as string;
    assert.equal((await call('POST', '/auth/mfa/enable', { code: '000000' }, session)).status, 400);
    const enableStep = currentStep();
    assert.equal((await call('POST', '/auth/mfa/enable', { code: hotp(secret, enableStep) }, session)).status, 200);

    const login = await call('POST', '/auth/login', { password: PASSWORD });
    assert.equal(login.body.mfaRequired, true);
    const pending = login.cookie!;
    assert.equal((await call('GET', '/overview', undefined, pending)).status, 401, 'pending-MFA session must not access data');
    // Same step as used for enabling = replay → rejected.
    assert.equal((await call('POST', '/auth/mfa', { code: hotp(secret, enableStep) }, pending)).status, 401);
    // Right password + wrong code = the password may be known → a high finding for SENTINEL itself.
    const mfaFinding = (await call('GET', '/security/findings?ruleId=sentinel_mfa_failed', undefined, session)).body.findings[0];
    assert.equal(mfaFinding?.severity, 'high');
    assert.equal(mfaFinding.plainTh.title, 'รหัสผ่าน SENTINEL ถูก แต่รหัส 6 หลักผิด');
    // Wait for the next 30 s step, then a fresh code works.
    await waitFor(async () => currentStep() > enableStep || undefined, 35_000);
    const ok = await call('POST', '/auth/mfa', { code: hotp(secret, currentStep()) }, pending);
    assert.equal(ok.status, 200);
    session = ok.cookie!;
    assert.equal((await call('GET', '/overview', undefined, session)).status, 200);
    const signInStep = currentStep();

    // Power control: needs a fresh code even when signed in; runs as a dry run here (LOCAL_TEST).
    assert.equal((await call('POST', '/power/action', { action: 'sleep' }, session)).status, 423, 'no code while the page is locked');
    assert.equal((await call('GET', '/auth/unlock', undefined, session)).body.until, null);
    assert.equal((await call('GET', '/launcher/remote', undefined, session)).status, 423, 'RustDesk hand-off hidden while locked');
    assert.equal((await call('POST', '/power/action', { action: 'sleep', code: '000000' }, session)).status, 401, 'wrong code refused');
    assert.equal((await call('POST', '/power/action', { action: 'format_disk', code: '000000' }, session)).status, 400, 'unknown action refused');
    await waitFor(async () => currentStep() > signInStep || undefined, 35_000);
    const powerStep = currentStep();
    const sleep = await call('POST', '/power/action', { action: 'sleep', delayMin: 30, code: hotp(secret, powerStep) }, session);
    assert.equal(sleep.status, 200);
    assert.equal(sleep.body.dryRun, true, 'never runs for real in tests');
    assert.equal(sleep.body.pending.action, 'sleep');
    assert.ok(Math.abs(sleep.body.pending.at - Date.now() - 30 * 60_000) < 10_000, 'scheduled in 30 min');
    assert.equal((await call('POST', '/power/action', { action: 'sleep', code: hotp(secret, powerStep) }, session)).status, 401, 'a used code cannot be replayed');
    assert.equal((await call('POST', '/power/cancel', {}, session)).status, 200, 'cancel needs no code');
    assert.equal((await call('GET', '/power', undefined, session)).body.pending, null);
    assert.equal((await call('POST', '/power/cancel', {}, session)).status, 404, 'nothing left to cancel');

    // One good code unlocked the page for this session: further actions only need a confirm tap.
    assert.ok((await call('GET', '/auth/unlock', undefined, session)).body.until > Date.now(), 'unlocked after a good code');
    assert.equal((await call('POST', '/power/action', { action: 'lock' }, session)).status, 200, 'no code needed while unlocked');
    assert.equal((await call('PUT', '/settings', { digestHour: 8 }, session)).status, 200, 'security settings work while unlocked');
    assert.equal((await call('POST', '/auth/unlock', { code: hotp(secret, powerStep) }, session)).status, 401, 'unlock cannot reuse a code');
    assert.equal((await call('POST', '/auth/lock', {}, session)).status, 200);
    assert.equal((await call('POST', '/power/action', { action: 'lock' }, session)).status, 423, 'locked again');
    // Security-sensitive changes need the unlock too once 2FA is on.
    assert.equal((await call('PUT', '/settings', { digestHour: 8 }, session)).status, 423, 'settings need the code');
    assert.equal((await call('PUT', '/security/rules/brute_force', { enabled: false }, session)).status, 423, 'turning detection off needs the code');
    assert.equal((await call('POST', '/notifications/channels', { botToken: '1:x', chatId: '1' }, session)).status, 423, 'redirecting alerts needs the code');

    // Turn MFA off again for the remaining tests.
    await waitFor(async () => currentStep() > currentStep() - 1 || undefined);
    const off = await waitFor(async () => {
      const r = await call('POST', '/auth/mfa/disable', { password: PASSWORD, code: hotp(secret, currentStep()) }, session);
      return r.status === 200 ? r : undefined;
    }, 35_000);
    assert.equal(off.status, 200);
  });

  test('programs list, game mode and closing a program', async () => {
    const r = await call('GET', '/processes', undefined, session);
    assert.equal(r.status, 200);
    const names = r.body.groups.map((g: { name: string }) => g.name);
    assert.deepEqual(names, ['fczf', 'msmpeng', 'brave'], 'grouped per program, busiest first');
    assert.equal(r.body.groups.find((g: { name: string }) => g.name === 'brave').count, 2);
    assert.equal(r.body.groups.find((g: { name: string }) => g.name === 'msmpeng').protected, true);
    assert.equal(r.body.gameRunning?.name, 'fczf', 'FC Online is a game by default and is open');
    assert.equal((await call('PUT', '/processes/game-mode', { enabled: true, processes: [] }, session)).status, 200);
    assert.equal((await call('GET', '/processes', undefined, session)).body.gameRunning, null);
    assert.equal((await call('PUT', '/processes/game-mode', { enabled: true, processes: ['fczf.exe'] }, session)).body.gameMode.processes[0], 'fczf');
    assert.equal((await call('POST', '/processes/kill', { name: 'MsMpEng', code: '123456' }, session)).status, 400, 'Defender can never be closed');
    assert.equal((await call('POST', '/processes/kill', { name: 'x; Stop-Computer', code: '123456' }, session)).status, 400, 'odd names refused');
    assert.equal((await call('POST', '/processes/kill', { name: 'fczf', code: '123456' }, session)).status, 403, 'needs 2FA turned on');
  });

  test('power control is refused while 2FA is off', async () => {
    const r = await call('POST', '/power/action', { action: 'lock', code: '123456' }, session);
    assert.equal(r.status, 403);
  });

  test('AT-06: 5 wrong passwords lock the account (even the right password is refused)', async () => {
    for (let i = 0; i < 5; i++) assert.equal((await call('POST', '/auth/login', { password: `wrong-${i}` })).status, 401);
    const r = await call('POST', '/auth/login', { password: PASSWORD });
    assert.equal(r.status, 429);
    assert.match(r.body.error, /locked/i);
    // The guessing shows up as findings: "wrong password N times" (medium) and "locked" (high).
    const fs = (await call('GET', '/security/findings?ruleId=sentinel_login_failed', undefined, session)).body.findings as { severity: string; plainTh: { title: string } }[];
    assert.deepEqual(fs.map((f) => f.severity).sort(), ['high', 'medium']);
    assert.ok(fs.some((f) => f.plainTh.title.includes('จนบัญชีถูกล็อก')));
    // Unlock for the rest of the suite by editing the throwaway DB directly.
    const d = new DatabaseSync(join(dataDir, 'sentinel.db'));
    d.prepare('UPDATE admin_account SET locked_until = NULL, failed_attempts = 0').run();
    d.close();
  });

  test('sign-in from a new device is reported once; the same device again is not', async () => {
    const ua = { 'user-agent': 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36' };
    assert.equal((await call('POST', '/auth/login', { password: PASSWORD }, undefined, ua)).status, 200);
    assert.equal((await call('POST', '/auth/login', { password: PASSWORD }, undefined, ua)).status, 200);
    const fs = (await call('GET', '/security/findings?ruleId=sentinel_new_device', undefined, session)).body.findings as { plainTh: { title: string } }[];
    assert.equal(fs.length, 1);
    assert.match(fs[0].plainTh.title, /Chrome on Android/);
  });

  test('app PIN: asked after leaving the app, 5 wrong PINs sign that device out', async () => {
    const PIN = '482913';
    const db = () => new DatabaseSync(join(dataDir, 'sentinel.db'));
    const setRow = (cookieOwner: number, sql: string, ...args: (number | null)[]) => {
      const d = db();
      d.prepare(sql).run(...args, cookieOwner);
      d.close();
    };
    const sessionIdOf = async (cookie: string) => (await call('GET', '/auth/sessions', undefined, cookie)).body.sessions.find((s: { current: boolean }) => s.current).id as number;

    assert.equal((await call('POST', '/auth/pin', { pin: '123456' }, session)).status, 400, 'trivial PIN refused');
    assert.equal((await call('POST', '/auth/pin', { pin: '12345' }, session)).status, 400, 'must be 6 digits');
    assert.equal((await call('POST', '/auth/pin', { pin: PIN }, session)).status, 200);
    assert.equal((await call('GET', '/auth/state', undefined, session)).body.pinEnabled, true);
    assert.equal((await call('GET', '/overview', undefined, session)).status, 200, 'the device that set the PIN carries on');

    // A phone: just signed in with the password, so no PIN yet.
    const phone = (await call('POST', '/auth/login', { password: PASSWORD })).cookie!;
    const phoneId = await sessionIdOf(phone);
    assert.equal((await call('GET', '/overview', undefined, phone)).status, 200);

    // A short trip to another app (within 5 minutes): no PIN, and coming back clears the mark.
    const t0 = Date.now();
    assert.equal((await call('POST', '/auth/pin/away', { seq: t0 }, phone)).status, 200);
    assert.equal((await call('POST', '/auth/pin/back', { seq: t0 + 1 }, phone)).body.locked, false);
    assert.equal((await call('GET', '/overview', undefined, phone)).status, 200);
    // The "left" message arriving late (after "back") must not mark the session as away.
    await call('POST', '/auth/pin/away', { seq: t0 + 2 }, phone);
    await call('POST', '/auth/pin/back', { seq: t0 + 4 }, phone);
    await call('POST', '/auth/pin/away', { seq: t0 + 3 }, phone);
    setRow(phoneId, 'UPDATE sessions SET last_seen_at = ? WHERE id = ?', Date.now());
    {
      const d = db();
      assert.equal((d.prepare('SELECT away_at FROM sessions WHERE id = ?').get(phoneId) as { away_at: number | null }).away_at, null, 'late "left" ignored');
      d.close();
    }

    // Left the app for 6 minutes: everything asks for the PIN, the PIN endpoints still answer.
    await call('POST', '/auth/pin/away', { seq: t0 + 10 }, phone);
    setRow(phoneId, 'UPDATE sessions SET away_at = ? WHERE id = ?', Date.now() - 6 * 60_000);
    assert.equal((await call('GET', '/overview', undefined, phone)).status, 428);
    assert.equal((await call('GET', '/auth/state', undefined, phone)).body.pinLocked, true);
    const wrong = await call('POST', '/auth/pin/verify', { pin: '000001' }, phone);
    assert.equal(wrong.status, 401);
    assert.equal(wrong.body.triesLeft, 4);
    assert.equal((await call('POST', '/auth/pin/verify', { pin: PIN }, phone)).status, 200);
    assert.equal((await call('GET', '/overview', undefined, phone)).status, 200, 'unlocked again');

    // Phone asleep / app closed for over 7 minutes without any request: PIN again.
    setRow(phoneId, 'UPDATE sessions SET last_seen_at = ? WHERE id = ?', Date.now() - 8 * 60_000);
    assert.equal((await call('GET', '/overview', undefined, phone)).status, 428);

    // Five wrong PINs: this device is signed out; the other session is untouched.
    for (let i = 0; i < 4; i++) assert.equal((await call('POST', '/auth/pin/verify', { pin: `00000${i + 2}` }, phone)).status, 401);
    const last = await call('POST', '/auth/pin/verify', { pin: '000009' }, phone);
    assert.equal(last.status, 401);
    assert.match(last.body.error, /signed out/i);
    assert.equal((await call('GET', '/overview', undefined, phone)).status, 401, 'signed out');
    assert.equal((await call('POST', '/auth/pin/verify', { pin: PIN }, phone)).status, 401, 'the right PIN no longer helps');
    assert.equal((await call('GET', '/overview', undefined, session)).status, 200);

    // Changing the PIN asks every other device for the new one.
    const other = (await call('POST', '/auth/login', { password: PASSWORD })).cookie!;
    assert.equal((await call('POST', '/auth/pin', { pin: '905172' }, session)).status, 200);
    assert.equal((await call('GET', '/overview', undefined, other)).status, 428);
    assert.equal((await call('POST', '/auth/pin/verify', { pin: PIN }, other)).status, 401, 'old PIN no longer works');
    assert.equal((await call('POST', '/auth/pin/verify', { pin: '905172' }, other)).status, 200);

    // Turning it off: nobody is asked any more.
    assert.equal((await call('POST', '/auth/pin/remove', {}, session)).status, 200);
    assert.equal((await call('GET', '/auth/state', undefined, session)).body.pinEnabled, false);
    const otherId = await sessionIdOf(other);
    setRow(otherId, 'UPDATE sessions SET away_at = ? WHERE id = ?', Date.now() - 6 * 60_000);
    assert.equal((await call('GET', '/overview', undefined, other)).status, 200);
  });

  test('fingerprint endpoints: signed-in only, refused on an IP address, no shortcut without a scan', async () => {
    assert.equal((await call('GET', '/auth/passkey/status')).status, 401, 'needs a session');
    assert.equal((await call('GET', '/auth/passkey')).status, 401);
    assert.deepEqual((await call('GET', '/auth/passkey/status', undefined, session)).body, { available: false });
    const list = await call('GET', '/auth/passkey', undefined, session);
    assert.equal(list.body.supportedHere, false, 'this test talks to 127.0.0.1: WebAuthn needs a domain');
    assert.deepEqual(list.body.keys, []);
    const reg = await call('POST', '/auth/passkey/register/options', {}, session);
    assert.equal(reg.status, 400);
    assert.match(reg.body.error, /IP address/);
    assert.equal((await call('POST', '/auth/passkey/unlock/options', {}, session)).status, 400, 'nothing to unlock with');
    const forged = await call('POST', '/auth/passkey/unlock/verify', { response: { id: 'x', rawId: 'x', type: 'public-key', response: {} } }, session);
    assert.equal(forged.status, 400, 'no challenge was issued, so a made-up response is refused');
  });
});

describe('Monitoring & alerting', () => {
  test('AT-08: SSRF targets are rejected', async () => {
    for (const url of ['http://169.254.169.254/latest/meta-data', 'http://localhost:3001', 'http://127.0.0.1/', 'http://[::1]/', 'file:///c:/windows/win.ini', 'http://user:pw@example.com']) {
      const r = await call('POST', '/assets', { type: 'website', name: 'ssrf', url }, session);
      assert.equal(r.status, 400, url);
    }
  });

  test('AT-03 + AT-04: unreachable site goes Down, raises exactly one alert', async () => {
    const r = await call('POST', '/assets', { type: 'website', name: 'Dead site', url: 'https://sentinel-acceptance.invalid/', intervalSec: 30 }, session);
    assert.equal(r.status, 201);
    const id = r.body.id;
    await waitFor(async () => (await call('GET', `/assets/${id}`, undefined, session)).body.asset.status === 'down' || undefined);
    const alert = await waitFor(async () => {
      const ev = (await call('GET', '/alerts/events?status=active', undefined, session)).body.events as { title: string; assetId: number }[];
      return ev.find((e) => e.assetId === id);
    }, 45_000);
    assert.match(alert.title, /DOWN/);
    // Force more checks; dedup must keep a single open alert.
    await call('POST', `/assets/${id}/check`, {}, session);
    await call('POST', `/assets/${id}/check`, {}, session);
    await new Promise((r) => setTimeout(r, 31_000)); // one more alert evaluation cycle
    const open = ((await call('GET', '/alerts/events?status=active', undefined, session)).body.events as { assetId: number }[]).filter((e) => e.assetId === id);
    assert.equal(open.length, 1);
  });

  test('AT-22: Log Explorer queries are limited (14-day span, 500 rows)', async () => {
    const now = Date.now();
    const tooWide = await call('GET', `/logs?from=${now - 15 * 86_400_000}&to=${now}`, undefined, session);
    assert.equal(tooWide.status, 400);
    assert.match(tooWide.body.error, /14 days/);
    const big = await call('GET', `/logs?from=${now - 86_400_000}&to=${now}&limit=100000`, undefined, session);
    assert.equal(big.status, 200);
    assert.ok(big.body.events.length <= 500);
    assert.deepEqual(big.body.limits, { maxSpanDays: 14, maxLimit: 500 });
    assert.equal((await call('GET', `/logs?from=${now}&to=${now - 1000}`, undefined, session)).status, 400, 'reversed range');
  });

  test('AT-32: incident status changes are recorded with reason and audit; reopen works', async () => {
    const inc = (await call('POST', '/incidents', { title: 'AT-32 lifecycle', severity: 'medium' }, session)).body.id as number;
    assert.equal((await call('POST', `/incidents/${inc}/status`, { status: 'closed' }, session)).status, 409, 'open → closed is not allowed');
    assert.equal((await call('POST', `/incidents/${inc}/status`, { status: 'acknowledged' }, session)).status, 200);
    assert.equal((await call('POST', `/incidents/${inc}/status`, { status: 'resolved' }, session)).status, 400, 'resolution text is required');
    assert.equal((await call('POST', `/incidents/${inc}/status`, { status: 'resolved', reason: 'False alarm: test' }, session)).status, 200);
    assert.equal((await call('POST', `/incidents/${inc}/status`, { status: 'open' }, session)).status, 400, 'reopen needs a reason');
    assert.equal((await call('POST', `/incidents/${inc}/status`, { status: 'open', reason: 'Happened again' }, session)).status, 200);
    const d = (await call('GET', `/incidents/${inc}`, undefined, session)).body;
    const changes = (d.timeline as { type: string; fromStatus: string; toStatus: string; message: string | null }[]).filter((e) => e.type === 'status_change');
    assert.deepEqual(changes.map((c) => `${c.fromStatus}>${c.toStatus}`), ['open>acknowledged', 'acknowledged>resolved', 'resolved>open']);
    assert.equal(changes[1].message, 'False alarm: test');
    assert.equal(d.incident.status, 'open');
    assert.equal(d.incident.resolvedAt, null, 'reopen clears resolved time');
    const auditRows = (await call('GET', '/audit?limit=50', undefined, session)).body.entries as { action: string; resourceId: string | null }[];
    assert.equal(auditRows.filter((a) => a.action === 'incident.status' && String(a.resourceId) === String(inc)).length, 3);
  });

  test('bulk finding status: needs a reason, updates each finding, audits each one', async () => {
    const d = new DatabaseSync(join(dataDir, 'sentinel.db'));
    const now = Date.now();
    const ins = d.prepare(
      "INSERT INTO security_findings (rule_id, asset_id, severity, title, summary, fingerprint, status, first_seen, last_seen, count, evidence) VALUES ('unexpected_shutdown', NULL, 'low', ?, 'bulk test', ?, 'open', ?, ?, 1, '{}')",
    );
    const ids = [1, 2, 3].map((i) => Number(ins.run(`Bulk ${i}`, `bulk:${i}`, now, now).lastInsertRowid));
    d.close();

    assert.equal((await call('POST', '/security/findings/bulk-status', { ids, status: 'resolved' }, session)).status, 400, 'resolve needs a note');
    assert.equal((await call('POST', '/security/findings/bulk-status', { ids: [], status: 'acknowledged' }, session)).status, 400, 'empty list');
    assert.equal((await call('POST', '/security/findings/bulk-status', { ids: ['1; DROP'], status: 'acknowledged' }, session)).status, 400, 'non-integer id');
    const r = await call('POST', '/security/findings/bulk-status', { ids: [ids[0], ids[1], 999_999], status: 'resolved', note: 'Battery ran out' }, session);
    assert.equal(r.status, 200);
    assert.equal(r.body.updated, 2, 'unknown ids are skipped');

    const all = (await call('GET', '/security/findings?status=all&limit=500', undefined, session)).body.findings as { id: number; status: string; note: string | null }[];
    const byId = new Map(all.map((f) => [f.id, f]));
    assert.equal(byId.get(ids[0])!.status, 'resolved');
    assert.equal(byId.get(ids[0])!.note, 'Battery ran out');
    assert.equal(byId.get(ids[1])!.status, 'resolved');
    assert.equal(byId.get(ids[2])!.status, 'open', 'unselected finding untouched');
    const auditRows = (await call('GET', '/audit?limit=50', undefined, session)).body.entries as { action: string; resourceId: string | null }[];
    for (const id of ids.slice(0, 2)) {
      assert.equal(auditRows.filter((a) => a.action === 'finding.status' && String(a.resourceId) === String(id)).length, 1, `audit for #${id}`);
    }
  });

  test('device health: dangerous Defender exclusions and a fake svchost auto-start become critical findings', async () => {
    const d = await waitFor(async () => {
      const r = (await call('GET', '/device-health', undefined, session)).body;
      return r.latest ? r : undefined;
    }, 60_000);
    const ex = d.latest.checks.find((c: { id: string }) => c.id === 'defender_exclusions');
    assert.equal(ex.status, 'bad');
    assert.equal(ex.severity, 'critical');
    assert.ok(d.findings.some((f: { ruleId: string; severity: string; title: string }) => f.ruleId === 'persistence_added' && f.severity === 'critical' && /svchost/.test(f.title)), 'fake svchost flagged even on the first (baseline) run');
    const findings = (await call('GET', '/security/findings?status=active&limit=500', undefined, session)).body.findings as { ruleId: string; severity: string }[];
    assert.ok(findings.some((f) => f.ruleId === 'device_protection' && f.severity === 'critical'));
    assert.equal((await call('POST', '/device-health/refresh', {}, session)).status, 200, 'manual re-check works and is idempotent');
    const again = (await call('GET', '/security/findings?status=active&limit=500', undefined, session)).body.findings as { ruleId: string }[];
    assert.equal(again.filter((f) => f.ruleId === 'device_protection').length, findings.filter((f) => f.ruleId === 'device_protection').length, 'no duplicate findings');
  });

  test('device health: fixing the problems auto-resolves their findings', async () => {
    const fixed = JSON.parse(DEVICE_SNAPSHOT);
    fixed.exclusions = { paths: [], processes: [], extensions: [] };
    fixed.startup = [];
    // Meanwhile a cracked program was installed (and Git updated, which must not count as new).
    fixed.software.apps = [{ name: 'Git 2.47.1', publisher: 'The Git Development Community' }, { name: 'Adobe Photoshop 2020 (repack by KpoJIuK)', version: '21.1.3', publisher: 'Adobe' }];
    // …and a program dropped an unpacked extension into Brave.
    // …and something pointed the bank at another server and turned on a proxy.
    fixed.network.hosts.push('203.0.113.9 www.kasikornbank.com');
    fixed.network.proxies = [{ who: 'S-1-5-21-9-1001', server: '127.0.0.1:8888' }];
    fixed.extensions[0].exts.push({ browser: 'Brave', profile: 'Default', id: 'bbbb', name: 'Free VPN', location: 4, fromStore: false, apis: ['proxy'], hosts: ['<all_urls>'] });
    await stopServer();
    await startServer({ SENTINEL_TEST_DEVICE_SNAPSHOT: JSON.stringify(fixed) });
    session = (await call('POST', '/auth/login', { password: PASSWORD })).cookie!;
    await call('POST', '/device-health/refresh', {}, session);
    const active = (await call('GET', '/security/findings?status=active&limit=500', undefined, session)).body.findings as { ruleId: string; severity: string }[];
    assert.ok(!active.some((f) => f.ruleId === 'persistence_added'), 'removed fake auto-start entry is resolved');
    assert.ok(!active.some((f) => f.ruleId === 'device_protection' && f.severity === 'critical'), 'exclusions removed → finding resolved');
    const progs = active.filter((f) => f.ruleId === 'program_installed');
    assert.equal(progs.length, 1, 'only the new program, not the Git update');
    assert.equal(progs[0].severity, 'high', 'crack name → high');
    const dev = (await call('GET', '/device-health', undefined, session)).body;
    assert.deepEqual(dev.recentPrograms.map((e: { kind: string; name: string }) => `${e.kind}:${e.name}`), ['added:Adobe Photoshop 2020 (repack by KpoJIuK)']);
    assert.ok(dev.findings.some((f: { ruleId: string }) => f.ruleId === 'program_installed'), 'listed on the Device page');
    const exts = active.filter((f) => f.ruleId === 'browser_extension');
    assert.deepEqual(exts.map((f) => f.severity), ['high'], 'only the sideloaded extension, as high');
    assert.deepEqual(active.filter((f) => f.ruleId === 'network_changed').map((f) => f.severity).sort(), ['high', 'medium'], 'fake bank line high, local proxy medium');
    assert.equal(dev.latest.network.hosts.length, 1, 'Tailscale line not counted');
    assert.equal(dev.latest.extensions.count, 2);
    assert.deepEqual(dev.recentExtensions.map((e: { kind: string; name: string }) => `${e.kind}:${e.name}`), ['added:Free VPN']);
    await stopServer();
    await startServer(); // back to the default snapshot for the remaining tests
    session = (await call('POST', '/auth/login', { password: PASSWORD })).cookie!;
    await call('POST', '/device-health/refresh', {}, session);
    const after = (await call('GET', '/security/findings?status=active&limit=500', undefined, session)).body.findings as { ruleId: string }[];
    assert.ok(!after.some((f) => f.ruleId === 'program_installed'), 'uninstalled → its finding is resolved');
    assert.ok(!after.some((f) => f.ruleId === 'browser_extension'), 'extension removed → its finding is resolved');
    assert.ok(!after.some((f) => f.ruleId === 'network_changed'), 'hosts line and proxy removed → resolved');
    const ev = (await call('GET', '/device-health', undefined, session)).body.recentPrograms as { kind: string }[];
    assert.equal(ev[0].kind, 'removed');
  });

  test('weekly automatic scan: shown with the scan status, owner can change it, bad values refused', async () => {
    const st = (await call('GET', '/device-health/scan', undefined, session)).body;
    assert.deepEqual({ enabled: st.auto.enabled, day: st.auto.day, hour: st.auto.hour }, { enabled: true, day: 0, hour: 20 }, 'default Sunday 20:00');
    assert.equal((await call('POST', '/device-health/scan/auto', { hour: 25 }, session)).status, 400);
    const r = await call('POST', '/device-health/scan/auto', { enabled: false, day: 3, hour: 9 }, session);
    assert.equal(r.status, 200);
    assert.deepEqual({ enabled: r.body.auto.enabled, day: r.body.auto.day, hour: r.body.auto.hour }, { enabled: false, day: 3, hour: 9 });
    await call('POST', '/device-health/scan/auto', { enabled: true, day: 0, hour: 20 }, session);
  });

  test('AI summary is off without an API key and refuses cleanly', async () => {
    const st = await call('GET', '/ai/status', undefined, session);
    assert.equal(st.body.enabled, false);
    const inc = await call('POST', '/incidents', { title: 'AI off test', severity: 'low' }, session);
    const r = await call('POST', `/incidents/${inc.body.id}/ai-summary`, {}, session);
    assert.equal(r.status, 503);
    assert.match(r.body.error, /ANTHROPIC_API_KEY/);
  });

  test('AT-10: Telegram failure is recorded, not silent', async () => {
    const ch = await call('POST', '/notifications/channels', { botToken: '123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', chatId: '1' }, session);
    assert.equal(ch.status, 201);
    const t = await call('POST', `/notifications/channels/${ch.body.id}/test`, {}, session);
    assert.equal(t.status, 502);
    const d = (await call('GET', '/notifications/deliveries', undefined, session)).body.deliveries as { status: string; lastError: string | null }[];
    assert.ok(d.some((x) => x.status === 'failed' && x.lastError), 'failed delivery with reason is listed');
    await call('DELETE', `/notifications/channels/${ch.body.id}`, undefined, session);
  });
});

describe('Integrity & recovery', () => {
  test('AT-14: audit log is append-only and its hash chain verifies', async () => {
    const v = await call('GET', '/audit/verify', undefined, session);
    assert.equal(v.body.ok, true);
    assert.ok(v.body.checked > 5);
    const d = new DatabaseSync(join(dataDir, 'sentinel.db'));
    assert.throws(() => d.prepare("UPDATE audit_logs SET action = 'tampered' WHERE seq = 1").run(), /append-only/);
    assert.throws(() => d.prepare('DELETE FROM audit_logs WHERE seq = 1').run(), /append-only/);
    d.close();
  });

  test('AT-12: backup can be verified and restored', async () => {
    const b = await call('POST', '/backups', {}, session);
    assert.equal(b.status, 200);
    const v = await call('POST', `/backups/${b.body.name}/verify`, {}, session);
    assert.equal(v.body.ok, true);
    // Off-disk copy (BACKUP_COPY_DIR): complete folder, no partial left behind, listed as copied.
    assert.equal(b.body.copied, true);
    assert.ok(existsSync(join(copyDir, b.body.name, 'sentinel.db')) && existsSync(join(copyDir, b.body.name, 'master.key')), 'copy has db + key');
    assert.ok(!readdirSync(copyDir).some((f) => f.startsWith('.partial-')), 'no partial copy left');
    const listed = (await call('GET', '/backups', undefined, session)).body;
    assert.equal(listed.copyDir, copyDir);
    assert.equal(listed.backups.find((x: { name: string }) => x.name === b.body.name).copied, true);
    const assetsBefore = (await call('GET', '/assets', undefined, session)).body.assets.length;

    // Make a change after the backup, then restore and confirm it is gone.
    await call('POST', '/assets', { type: 'website', name: 'Added after backup', url: 'https://example.com' }, session);
    await stopServer();
    const restore = spawn(process.execPath, ['--import', 'tsx', 'scripts/restore.ts', join(dataDir, 'backups', b.body.name)], { env: { ...process.env, DATA_DIR: dataDir, PORT: String(PORT) } });
    let out = '';
    restore.stdout!.on('data', (x) => (out += x));
    restore.stderr!.on('data', (x) => (out += x));
    const code = await new Promise((r) => restore.once('exit', r));
    assert.equal(code, 0, out);
    assert.ok(readdirSync(dataDir).some((f) => f.startsWith('pre-restore-')), 'previous data kept aside');

    await startServer(); // AT-09: restart keeps business data
    const login = await call('POST', '/auth/login', { password: PASSWORD });
    session = login.cookie!;
    const assetsAfter = (await call('GET', '/assets', undefined, session)).body.assets as { name: string }[];
    assert.equal(assetsAfter.length, assetsBefore);
    assert.ok(!assetsAfter.some((a) => a.name === 'Added after backup'));

    // Encrypted off-disk copy: after a passphrase is set, the cloud folder holds only sealed files, no master.key.
    assert.equal((await call('POST', '/backups/seal', { passphrase: 'short' }, session)).status, 400);
    const PASS = 'test backup passphrase 2026';
    const sealed = await call('POST', '/backups/seal', { passphrase: PASS }, session);
    assert.equal(sealed.status, 200, JSON.stringify(sealed.body));
    const files = readdirSync(copyDir);
    assert.ok(files.length > 0 && files.every((f) => f.endsWith('.sbk')), `only sealed files: ${files.join(', ')}`);
    const listed2 = (await call('GET', '/backups', undefined, session)).body;
    assert.equal(listed2.sealed, true);
    assert.ok(listed2.backups.every((x: { copied: boolean }) => x.copied === true), 'every backup has a sealed copy');
    const one = readFileSync(join(copyDir, `${b.body.name}.sbk`));
    assert.equal(one.indexOf(readFileSync(join(dataDir, 'master.key'))), -1, 'master.key not readable in the cloud copy');
    const opened = unseal(one, PASS).files.map((f) => f.name).sort();
    assert.deepEqual(opened, ['manifest.json', 'master.key', 'sentinel.db']);
    assert.ok(!logs.includes(PASS), 'passphrase not in logs');

    // "Do I still remember the passphrase?": right one opens the newest copy, wrong one is refused, then rate-limited.
    const good = await call('POST', '/backups/check-passphrase', { passphrase: PASS }, session);
    assert.equal(good.status, 200);
    assert.equal(good.body.ok, true);
    assert.match(good.body.opened, /^sentinel-/);
    assert.ok((await call('GET', '/backups', undefined, session)).body.passCheckedAt > 0);
    for (let i = 0; i < 5; i++) {
      const w = await call('POST', '/backups/check-passphrase', { passphrase: `wrong passphrase ${i}` }, session);
      assert.equal(w.body.ok, false);
      assert.equal(w.body.triesLeft, 4 - i);
    }
    assert.equal((await call('POST', '/backups/check-passphrase', { passphrase: PASS }, session)).status, 429, 'limited after 5 tries');
    assert.ok(!logs.includes(PASS) && !logs.includes('wrong passphrase 0'), 'passphrases never logged');

    // Restore test of the newest cloud copy: passes, leaves nothing unpacked; a damaged copy is caught.
    const drill = await call('POST', '/backups/restore-test', {}, session);
    assert.equal(drill.status, 200);
    assert.equal(drill.body.ok, true, JSON.stringify(drill.body.problems));
    assert.ok(!readdirSync(dataDir).some((f) => f.startsWith('restore-test-')), 'unpacked files removed');
    const newest = readdirSync(copyDir).filter((f) => f.endsWith('.sbk')).sort().reverse()[0];
    const buf = readFileSync(join(copyDir, newest));
    buf[buf.length - 100] ^= 0xff;
    writeFileSync(join(copyDir, newest), buf);
    const bad = await call('POST', '/backups/restore-test', {}, session);
    assert.equal(bad.body.ok, false);
    assert.match(bad.body.problems.join(' '), /damaged/);
    assert.equal((await call('GET', '/backups', undefined, session)).body.drill.ok, false, 'last result is kept');
    const deliveries = (await call('GET', '/notifications/deliveries', undefined, session)).body.deliveries as { preview: string }[];
    assert.ok(deliveries.length === 0 || deliveries.some((d) => /restore|กู้คืน/.test(d.preview)), 'failure is queued for Telegram when a channel exists');
    rmSync(join(copyDir, newest));
    await call('POST', '/backups', {}, session); // fresh good copy for later tests
  });

  test('heartbeat failure is visible in self-monitoring without exposing the URL', async () => {
    const hb = await waitFor(async () => {
      const comps = (await call('GET', '/health', undefined, session)).body.components as { name: string; ok: boolean; message: string }[];
      const c = comps.find((x) => x.name === 'heartbeat');
      return c && !c.ok ? c : undefined;
    });
    assert.match(hb.message, /Ping to 127\.0\.0\.1:9 failed/);
    assert.ok(!hb.message.includes('heartbeat-secret'), 'secret path not shown');
    assert.ok(!JSON.stringify((await call('GET', '/settings', undefined, session)).body).includes('heartbeat-secret'));
  });

  test('AT-13: no credentials in server output or database plaintext', async () => {
    assert.ok(!logs.includes(PASSWORD), 'admin password not in logs');
    assert.ok(!logs.includes('heartbeat-secret'), 'heartbeat URL not in logs');
    assert.ok(!logs.includes('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'bot token not in logs');
    const dbBytes = readFileSync(join(dataDir, 'sentinel.db'));
    assert.ok(!dbBytes.includes(Buffer.from(PASSWORD)), 'password not stored in plaintext');
    assert.ok(existsSync(join(dataDir, 'master.key')));
  });
});
