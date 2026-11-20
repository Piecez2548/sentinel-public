import { hash as argonHash, verify as argonVerify } from '@node-rs/argon2';
import { Router, type NextFunction, type Request, type Response } from 'express';
import QRCode from 'qrcode';
import { all, get, getSetting, run, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { decrypt, encrypt, randomToken, sha256 } from '../lib/crypto.js';
import { body, clientIp, HttpError, isLoopback, str } from '../lib/http.js';
import { generateSecret, otpauthUrl, verifyTotp } from '../lib/totp.js';
import { PIN_MAX_FAILS, pinNeeded, pinProblem } from '../lib/pin.js';
import { deviceLabel, onLoginFailed, onLoginSuccess } from './login-watch.js';
import { securityNotice } from './notify.js';

declare module 'express-serve-static-core' {
  interface Request {
    sessionId?: number;
  }
}

const COOKIE = 'sentinel_sid';
/** Sessions unlocked with a 6-digit code for the control page (see requireStepUp), kept in memory. */
const unlocked = new Map<number, number>();
/** Signed in for at most 3 days, and signed out after 24 h without use. */
const SESSION_TTL = 3 * 86_400_000;
const IDLE_TTL = 86_400_000;
const MFA_PENDING_TTL = 5 * 60_000;
const MAX_FAILED = 5;
const LOCK_MS = 15 * 60_000;
const MIN_PASSWORD = 12;

type Admin = {
  password_hash: string;
  totp_secret_enc: string | null;
  totp_enabled: number;
  totp_last_step: number | null;
  failed_attempts: number;
  locked_until: number | null;
  pin_hash: string | null;
};
type SessionRow = { id: number; mfa_pending: number; expires_at: number; last_seen_at: number; revoked_at: number | null; pin_ok: number; away_at: number | null; pin_failures: number; vis_seq: number };

const getAdmin = () => get<Admin>('SELECT * FROM admin_account WHERE id = 1');
export const adminExists = () => !!getAdmin();

/* ---------- cookies & sessions ---------- */

function readCookie(req: Request): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE) return decodeURIComponent(v.join('='));
  }
  return undefined;
}

function setCookie(req: Request, res: Response, token: string, maxAgeMs: number) {
  // Browsers accept Secure cookies on http://localhost too, so the cookie is always Secure
  // (the phone reaches SENTINEL over HTTPS via tailscale serve). COOKIE_SECURE=false only for old browsers.
  const secure = process.env.COOKIE_SECURE !== 'false';
  res.setHeader(
    'Set-Cookie',
    `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure ? '; Secure' : ''}`,
  );
}

function clearCookie(res: Response) {
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

function createSession(req: Request, res: Response, mfaPending: boolean) {
  const token = randomToken();
  const now = Date.now();
  const ttl = mfaPending ? MFA_PENDING_TTL : SESSION_TTL;
  run(
    'INSERT INTO sessions (token_hash, mfa_pending, created_at, last_seen_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)',
    sha256(token), mfaPending ? 1 : 0, now, now, now + ttl, clientIp(req), String(req.headers['user-agent'] ?? '').slice(0, 200),
  );
  setCookie(req, res, token, ttl);
}

function currentSession(req: Request): SessionRow | undefined {
  const token = readCookie(req);
  if (!token) return undefined;
  const s = get<SessionRow>(
    'SELECT id, mfa_pending, expires_at, last_seen_at, revoked_at, pin_ok, away_at, pin_failures, vis_seq FROM sessions WHERE token_hash = ?',
    sha256(token),
  );
  const now = Date.now();
  if (!s || s.revoked_at || s.expires_at < now) return undefined;
  if (!s.mfa_pending && now - s.last_seen_at > IDLE_TTL) return undefined;
  return s;
}

/**
 * App PIN gate: true when this signed-in session must enter the PIN first. A session that left the app
 * (or went quiet) is marked locked, and its 15-minute control unlock is dropped as well.
 */
function pinLocked(s: SessionRow, now = Date.now()): boolean {
  if (!getAdmin()?.pin_hash) return false;
  if (!pinNeeded(s, now)) return false;
  if (s.pin_ok) {
    run('UPDATE sessions SET pin_ok = 0 WHERE id = ?', s.id);
    s.pin_ok = 0;
  }
  unlocked.delete(s.id);
  return true;
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const s = currentSession(req);
  if (!s || s.mfa_pending) {
    res.status(401).json({ error: 'Not authenticated' });
    return;
  }
  const now = Date.now();
  // Checked before last_seen_at moves, so a session that went quiet stays locked.
  if (pinLocked(s, now)) {
    res.status(428).json({ error: 'Enter your PIN', pin: true });
    return;
  }
  if (now - s.last_seen_at > 60_000) run('UPDATE sessions SET last_seen_at = ? WHERE id = ?', now, s.id);
  req.sessionId = s.id;
  next();
}

/* ---------- brute-force protection ---------- */

const ipFailures = new Map<string, { count: number; resetAt: number }>();

function ipBlocked(ip: string): boolean {
  const f = ipFailures.get(ip);
  if (!f) return false;
  if (f.resetAt < Date.now()) {
    ipFailures.delete(ip);
    return false;
  }
  return f.count >= 20;
}

function recordFailure(ip: string, reason: string, userAgent: string) {
  const now = Date.now();
  const f = ipFailures.get(ip);
  if (!f || f.resetAt < now) ipFailures.set(ip, { count: 1, resetAt: now + LOCK_MS });
  else f.count++;

  const admin = getAdmin();
  if (!admin) return;
  const attempts = admin.failed_attempts + 1;
  const locked = attempts >= MAX_FAILED;
  if (locked) {
    run('UPDATE admin_account SET failed_attempts = 0, locked_until = ? WHERE id = 1', now + LOCK_MS);
    audit('auth.locked', { ip, detail: { minutes: LOCK_MS / 60_000 } });
  } else {
    run('UPDATE admin_account SET failed_attempts = ? WHERE id = 1', attempts);
  }
  audit('auth.login_failed', { ip, detail: { reason } });
  watch(() => onLoginFailed(ip, reason, locked, userAgent));
}

/** Detection must never break sign-in. */
function watch(fn: () => void) {
  try {
    fn();
  } catch (e) {
    console.error('[login-watch]', e);
  }
}

const uaOf = (req: Request) => String(req.headers['user-agent'] ?? '');

function lockedFor(admin: Admin): number {
  return admin.locked_until && admin.locked_until > Date.now() ? admin.locked_until - Date.now() : 0;
}

/* ---------- router ---------- */

export const authRouter = Router();

authRouter.get('/state', (req, res) => {
  const admin = getAdmin();
  const s = currentSession(req);
  res.json({
    setupRequired: !admin,
    setupAllowed: !admin && isLoopback(req),
    authenticated: !!s && !s.mfa_pending,
    mfaPending: !!s?.mfa_pending,
    mfaEnabled: !!admin?.totp_enabled,
    pinEnabled: !!admin?.pin_hash,
    pinLocked: !!s && !s.mfa_pending && pinLocked(s),
  });
});

authRouter.post('/setup', async (req, res) => {
  if (adminExists()) throw new HttpError(409, 'Admin account already exists');
  if (!isLoopback(req)) throw new HttpError(403, 'First-time setup is only allowed from this computer (localhost)');
  const password = str(body(req).password, 'Password', { min: MIN_PASSWORD, max: 200 })!;
  const now = Date.now();
  run(
    'INSERT INTO admin_account (id, password_hash, created_at, password_changed_at) VALUES (1, ?, ?, ?)',
    await argonHash(password), now, now,
  );
  audit('auth.setup', { ip: clientIp(req) });
  createSession(req, res, false);
  res.json({ ok: true });
});

authRouter.post('/login', async (req, res) => {
  const ip = clientIp(req);
  const admin = getAdmin();
  if (!admin) throw new HttpError(409, 'Setup required');
  if (ipBlocked(ip)) throw new HttpError(429, 'Too many attempts from this address. Try again later.');
  const locked = lockedFor(admin);
  if (locked) throw new HttpError(429, `Account locked. Try again in ${Math.ceil(locked / 60_000)} minute(s).`);

  const password = typeof body(req).password === 'string' ? (body(req).password as string) : '';
  if (!password || !(await argonVerify(admin.password_hash, password))) {
    recordFailure(ip, 'bad_password', uaOf(req));
    throw new HttpError(401, 'Wrong password');
  }
  run('UPDATE admin_account SET failed_attempts = 0, locked_until = NULL WHERE id = 1');

  if (admin.totp_enabled) {
    createSession(req, res, true);
    res.json({ mfaRequired: true });
    return;
  }
  createSession(req, res, false);
  audit('auth.login', { ip });
  watch(() => onLoginSuccess(ip, uaOf(req)));
  res.json({ ok: true });
});

authRouter.post('/mfa', (req, res) => {
  const ip = clientIp(req);
  const s = currentSession(req);
  const admin = getAdmin();
  if (!s || !s.mfa_pending || !admin?.totp_enabled || !admin.totp_secret_enc) throw new HttpError(401, 'Sign in with your password first');
  const locked = lockedFor(admin);
  if (locked) throw new HttpError(429, `Account locked. Try again in ${Math.ceil(locked / 60_000)} minute(s).`);

  const code = String(body(req).code ?? '').replace(/\s/g, '');
  const step = verifyTotp(decrypt(admin.totp_secret_enc), code, admin.totp_last_step);
  if (step == null) {
    recordFailure(ip, 'bad_mfa_code', uaOf(req));
    throw new HttpError(401, 'Invalid or already-used code');
  }
  run('UPDATE admin_account SET totp_last_step = ?, failed_attempts = 0 WHERE id = 1', step);
  run('UPDATE sessions SET revoked_at = ? WHERE id = ?', Date.now(), s.id); // rotate: pending → full
  createSession(req, res, false);
  audit('auth.login', { ip, detail: { mfa: true } });
  watch(() => onLoginSuccess(ip, uaOf(req)));
  res.json({ ok: true });
});

authRouter.post('/logout', (req, res) => {
  const s = currentSession(req);
  if (s) {
    run('UPDATE sessions SET revoked_at = ? WHERE id = ?', Date.now(), s.id);
    audit('auth.logout', { ip: clientIp(req) });
  }
  clearCookie(res);
  res.json({ ok: true });
});

/* ----- app PIN (signed-in session, PIN not yet entered) ----- */

export function fullSession(req: Request): SessionRow {
  const s = currentSession(req);
  if (!s || s.mfa_pending) throw new HttpError(401, 'Not authenticated');
  return s;
}

/** Is the PIN needed now? (read only) */
authRouter.get('/pin', (req, res) => {
  const s = fullSession(req);
  res.json({ enabled: !!getAdmin()?.pin_hash, locked: pinLocked(s), triesLeft: PIN_MAX_FAILS - s.pin_failures });
});

/**
 * "Left the app" / "came back" carry a sequence number (the page's clock when it happened). The "left"
 * message is sent while the page is being hidden and can arrive after the "came back" one; without the
 * order check a late "left" would mark a session that is in use as away, and lock it once the grace period ran out.
 */
const visSeq = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.floor(v) : null);

authRouter.post('/pin/away', (req, res) => {
  const s = currentSession(req);
  const seq = visSeq(body(req).seq);
  if (s && !s.mfa_pending && seq != null && seq > s.vis_seq) {
    run('UPDATE sessions SET vis_seq = ?, away_at = CASE WHEN pin_ok = 1 AND away_at IS NULL THEN ? ELSE away_at END WHERE id = ?', seq, Date.now(), s.id);
  }
  res.json({ ok: true });
});

/** Came back to the app: within the grace period the "away" mark is cleared, otherwise the PIN is needed. */
authRouter.post('/pin/back', (req, res) => {
  const s = fullSession(req);
  const seq = visSeq(body(req).seq);
  const locked = pinLocked(s);
  if (seq != null && seq > s.vis_seq) run(`UPDATE sessions SET vis_seq = ?${locked ? '' : ', away_at = NULL'} WHERE id = ?`, seq, s.id);
  res.json({ locked });
});

authRouter.post('/pin/verify', async (req, res) => {
  const s = fullSession(req);
  const admin = getAdmin();
  if (!admin?.pin_hash) throw new HttpError(400, 'No PIN is set');
  const pin = String(body(req).pin ?? '');
  if (/^\d{6}$/.test(pin) && (await argonVerify(admin.pin_hash, pin))) {
    pinPassed(req, s, 'pin');
    res.json({ ok: true });
    return;
  }
  pinFailed(req, res, s, 'pin');
});

/** The app is unlocked for this session (right PIN or fingerprint). */
export function pinPassed(req: Request, s: SessionRow, how: 'pin' | 'fingerprint') {
  run('UPDATE sessions SET pin_ok = 1, away_at = NULL, pin_failures = 0, last_seen_at = ? WHERE id = ?', Date.now(), s.id);
  audit('auth.pin_ok', { ip: clientIp(req), detail: { how } });
}

/** A wrong PIN or a fingerprint that did not verify: counts toward the 5 tries; the 5th signs the device out. Always throws/answers 401. */
export function pinFailed(req: Request, res: Response, s: SessionRow, how: 'pin' | 'fingerprint') {
  const fails = s.pin_failures + 1;
  audit('auth.pin_failed', { ip: clientIp(req), detail: { fails, how } });
  if (fails >= PIN_MAX_FAILS) {
    run('UPDATE sessions SET revoked_at = ?, pin_failures = ? WHERE id = ?', Date.now(), fails, s.id);
    clearCookie(res);
    audit('auth.pin_lockout', { ip: clientIp(req) });
    securityNotice(`Wrong app PIN ${PIN_MAX_FAILS} times — that device was signed out`, `ใส่ PIN ผิด ${PIN_MAX_FAILS} ครั้ง — ออกจากระบบอุปกรณ์นั้นแล้ว`, req);
    throw new HttpError(401, 'Wrong PIN 5 times — signed out. Sign in again with your password.');
  }
  run('UPDATE sessions SET pin_failures = ? WHERE id = ?', fails, s.id);
  res.status(401).json({ error: how === 'pin' ? 'Wrong PIN' : 'Fingerprint not accepted', triesLeft: PIN_MAX_FAILS - fails });
}

/* ----- everything below needs a full session ----- */

authRouter.use(requireAuth);

/** Set or change the app PIN. Other devices must enter the new PIN next time. */
authRouter.post('/pin', stepUp, async (req, res) => {
  const pin = body(req).pin;
  const problem = pinProblem(pin);
  if (problem) throw new HttpError(400, problem);
  const had = !!getAdmin()?.pin_hash;
  run('UPDATE admin_account SET pin_hash = ? WHERE id = 1', await argonHash(String(pin)));
  run('UPDATE sessions SET pin_ok = 0 WHERE revoked_at IS NULL AND id != ?', req.sessionId ?? -1);
  run('UPDATE sessions SET pin_ok = 1, away_at = NULL, pin_failures = 0 WHERE id = ?', req.sessionId ?? -1);
  audit(had ? 'auth.pin_changed' : 'auth.pin_set', { ip: clientIp(req) });
  securityNotice(had ? 'App PIN changed' : 'App PIN turned on', had ? 'เปลี่ยน PIN เข้าแอปแล้ว' : 'เปิดใช้ PIN เข้าแอปแล้ว', req);
  res.json({ ok: true });
});

authRouter.post('/pin/remove', stepUp, (req, res) => {
  run('UPDATE admin_account SET pin_hash = NULL WHERE id = 1');
  run('UPDATE sessions SET pin_ok = 1, away_at = NULL, pin_failures = 0 WHERE revoked_at IS NULL');
  audit('auth.pin_removed', { ip: clientIp(req) });
  securityNotice('App PIN turned OFF', 'ปิด PIN เข้าแอปแล้ว', req);
  res.json({ ok: true });
});

authRouter.post('/logout-all', (req, res) => {
  const r = run('UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL', Date.now());
  audit('auth.logout_all', { ip: clientIp(req), detail: { sessions: Number(r.changes) } });
  clearCookie(res);
  res.json({ ok: true });
});

authRouter.get('/sessions', (req, res) => {
  const rows = all<{ id: number; created_at: number; last_seen_at: number; expires_at: number; ip: string; user_agent: string }>(
    `SELECT id, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions
     WHERE revoked_at IS NULL AND mfa_pending = 0 AND expires_at > ? ORDER BY last_seen_at DESC`,
    Date.now(),
  );
  res.json({
    sessions: rows.map((r) => ({
      id: r.id,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      expiresAt: r.expires_at,
      ip: r.ip,
      userAgent: r.user_agent,
      current: r.id === req.sessionId,
    })),
  });
});

authRouter.delete('/sessions/:id', (req, res) => {
  const id = Number(req.params.id);
  run('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', Date.now(), id);
  audit('session.revoked', { ip: clientIp(req), resourceType: 'session', resourceId: id });
  res.json({ ok: true });
});

authRouter.post('/password', stepUp, async (req, res) => {
  const admin = getAdmin()!;
  const b = body(req);
  const current = typeof b.current === 'string' ? b.current : '';
  if (!(await argonVerify(admin.password_hash, current))) {
    recordFailure(clientIp(req), 'bad_password_on_change', uaOf(req));
    throw new HttpError(401, 'Current password is wrong');
  }
  const next = str(b.next, 'New password', { min: MIN_PASSWORD, max: 200 })!;
  run('UPDATE admin_account SET password_hash = ?, password_changed_at = ? WHERE id = 1', await argonHash(next), Date.now());
  // Sign out every other session.
  run('UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND id != ?', Date.now(), req.sessionId ?? -1);
  audit('auth.password_changed', { ip: clientIp(req) });
  securityNotice('Password changed', 'เปลี่ยนรหัสผ่าน SENTINEL แล้ว', req);
  res.json({ ok: true });
});

authRouter.post('/mfa/setup', async (req, res) => {
  const admin = getAdmin()!;
  if (admin.totp_enabled) throw new HttpError(409, 'MFA is already enabled');
  const secret = generateSecret();
  setSetting('pending_totp_secret', encrypt(secret));
  const url = otpauthUrl(secret, 'admin');
  res.json({ secret, otpauthUrl: url, qr: await QRCode.toDataURL(url, { margin: 1, width: 220 }) });
});

authRouter.post('/mfa/enable', (req, res) => {
  const pending = getSetting('pending_totp_secret');
  if (!pending) throw new HttpError(400, 'Start MFA setup first');
  const secret = decrypt(pending);
  const step = verifyTotp(secret, String(body(req).code ?? '').replace(/\s/g, ''), null);
  if (step == null) throw new HttpError(400, 'Code does not match. Check the time on your phone and try again.');
  run('UPDATE admin_account SET totp_secret_enc = ?, totp_enabled = 1, totp_last_step = ? WHERE id = 1', encrypt(secret), step);
  run("DELETE FROM settings WHERE key = 'pending_totp_secret'");
  audit('auth.mfa_enabled', { ip: clientIp(req) });
  res.json({ ok: true });
});

authRouter.post('/mfa/disable', async (req, res) => {
  const admin = getAdmin()!;
  if (!admin.totp_enabled || !admin.totp_secret_enc) throw new HttpError(400, 'MFA is not enabled');
  const b = body(req);
  if (!(await argonVerify(admin.password_hash, typeof b.password === 'string' ? b.password : ''))) {
    recordFailure(clientIp(req), 'bad_password_on_mfa_disable', uaOf(req));
    throw new HttpError(401, 'Password is wrong');
  }
  const step = verifyTotp(decrypt(admin.totp_secret_enc), String(b.code ?? ''), admin.totp_last_step);
  if (step == null) throw new HttpError(401, 'Invalid code');
  run('UPDATE admin_account SET totp_enabled = 0, totp_secret_enc = NULL, totp_last_step = NULL, failed_attempts = 0 WHERE id = 1');
  audit('auth.mfa_disabled', { ip: clientIp(req) });
  securityNotice('Two-factor authentication was turned OFF', 'ปิดการยืนยันตัวตน 2 ชั้นแล้ว', req);
  res.json({ ok: true });
});

/**
 * Step-up check for dangerous actions (power control): a fresh 6-digit code is required even inside a
 * signed-in session, so a stolen session cookie alone cannot shut the PC down. A wrong code counts as a
 * failed sign-in step (feeds the lockout and the "wrong 2FA code" detection).
 */
export function verifyActionCode(req: Request, code: unknown): void {
  const admin = getAdmin();
  if (!admin?.totp_enabled || !admin.totp_secret_enc) throw new HttpError(403, 'Turn on two-factor authentication in Settings first');
  if (lockedFor(admin)) throw new HttpError(429, 'Too many wrong codes — try again in 15 minutes');
  const step = verifyTotp(decrypt(admin.totp_secret_enc), String(code ?? '').replace(/\s/g, ''), admin.totp_last_step);
  if (step == null) {
    recordFailure(clientIp(req), 'bad_mfa_code', uaOf(req));
    throw new HttpError(401, 'Invalid code');
  }
  run('UPDATE admin_account SET totp_last_step = ?, failed_attempts = 0 WHERE id = 1', step);
}

/* ---------- unlock the control page once ---------- */

/**
 * One code unlocks the Power control page for UNLOCK_MS in this signed-in session only (kept in memory,
 * so a SENTINEL restart, sign-out or another device always needs a fresh code). Inside that window the
 * page asks for a confirm tap instead of a code on every action.
 */
export const UNLOCK_MS = 15 * 60_000;

export function unlockedUntil(req: Request, now = Date.now()): number | null {
  const id = req.sessionId;
  const until = id != null ? unlocked.get(id) : undefined;
  if (until == null) return null;
  if (until <= now) {
    unlocked.delete(id!);
    return null;
  }
  return until;
}

/** For dangerous actions: a code in the request is checked (and unlocks), otherwise the session must be unlocked. */
export function requireStepUp(req: Request, code: unknown): void {
  if (code != null && String(code).trim() !== '') {
    verifyActionCode(req, code);
    if (req.sessionId != null) unlocked.set(req.sessionId, Date.now() + UNLOCK_MS);
    return;
  }
  const admin = getAdmin();
  if (!admin?.totp_enabled) throw new HttpError(403, 'Turn on two-factor authentication in Settings first');
  if (unlockedUntil(req) == null) throw new HttpError(423, 'Locked — enter your 6-digit code to unlock this page');
}

authRouter.get('/unlock', (req, res) => {
  res.json({ until: unlockedUntil(req), mfa: !!getAdmin()?.totp_enabled });
});

authRouter.post('/unlock', (req, res) => {
  verifyActionCode(req, body(req).code);
  const until = Date.now() + UNLOCK_MS;
  unlocked.set(req.sessionId!, until);
  audit('auth.control_unlocked', { ip: clientIp(req), detail: { minutes: UNLOCK_MS / 60_000 } });
  securityNotice('Control unlocked for 15 min', 'ปลดล็อกการควบคุม 15 นาที', req);
  res.json({ ok: true, until });
});

authRouter.post('/lock', (req, res) => {
  if (req.sessionId != null) unlocked.delete(req.sessionId);
  res.json({ ok: true });
});

/**
 * Middleware for security-sensitive changes (notification channels, detection/alert rules, settings,
 * deleting monitored assets, password): the session must be unlocked with a 6-digit code first.
 * A function declaration on purpose — it is hoisted, so routers in import cycles can use it.
 */
export function stepUp(req: Request, _res: Response, next: NextFunction) {
  // Before 2FA is set up there is no second factor to ask for (power control still refuses).
  if (getAdmin()?.totp_enabled) requireStepUp(req, body(req).code);
  next();
}

export const userAgentOf = uaOf;
export const deviceOf = (req: Request) => deviceLabel(uaOf(req));

/** Housekeeping: drop expired/revoked sessions older than 30 days. */
export function purgeSessions() {
  run('DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)', Date.now() - 30 * 86_400_000, Date.now() - 30 * 86_400_000);
}
