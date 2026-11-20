import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { Router, type Request } from 'express';
import { all, get, run } from '../db.js';
import { audit } from '../lib/audit.js';
import { body, clientIp, HttpError } from '../lib/http.js';
import { relyingParty } from '../lib/passkey-rp.js';
import { deviceOf, fullSession, pinFailed, pinPassed, requireAuth, stepUp } from './auth.js';
import { securityNotice } from './notify.js';

/**
 * Fingerprint (or face / Windows Hello) instead of typing the app PIN. Uses WebAuthn: the phone keeps a
 * private key behind its fingerprint sensor and signs a one-time challenge; SENTINEL stores only the
 * public key. Adding a fingerprint needs the 2FA unlock; a failed check counts toward the 5 PIN tries.
 */

type Row = { id: string; rp_id: string; public_key: string; counter: number; transports: string | null; label: string | null; created_at: number; last_used_at: number | null };

const CHALLENGE_MS = 2 * 60_000;
/** One pending challenge per signed-in session, kept in memory. */
const challenges = new Map<number, { kind: 'register' | 'unlock'; challenge: string; rpID: string; origin: string; at: number }>();

function takeChallenge(sessionId: number, kind: 'register' | 'unlock') {
  const c = challenges.get(sessionId);
  challenges.delete(sessionId);
  if (!c || c.kind !== kind || Date.now() - c.at > CHALLENGE_MS) throw new HttpError(400, 'Fingerprint request expired — try again');
  return c;
}

function rpOf(req: Request) {
  const rp = relyingParty(req.headers.host);
  if (!rp) throw new HttpError(400, 'Fingerprint works only on the https://…ts.net address (phone) or http://localhost — not on an IP address');
  return rp;
}

const keysFor = (rpID: string) => all<Row>('SELECT * FROM passkeys WHERE rp_id = ? ORDER BY created_at', rpID);
const transportsOf = (r: Row) => (r.transports ? (JSON.parse(r.transports) as string[]) : undefined);

export const passkeyRouter = Router();

/* ----- usable on the PIN screen (signed in, PIN not yet entered) ----- */

passkeyRouter.get('/status', (req, res) => {
  fullSession(req);
  const rp = relyingParty(req.headers.host);
  res.json({ available: !!rp && keysFor(rp.rpID).length > 0 });
});

passkeyRouter.post('/unlock/options', async (req, res) => {
  const s = fullSession(req);
  const rp = rpOf(req);
  const keys = keysFor(rp.rpID);
  if (!keys.length) throw new HttpError(400, 'No fingerprint is set up on this device');
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    allowCredentials: keys.map((k) => ({ id: k.id, transports: transportsOf(k) })),
    userVerification: 'required',
    timeout: 60_000,
  });
  challenges.set(s.id, { kind: 'unlock', challenge: options.challenge, rpID: rp.rpID, origin: rp.origin, at: Date.now() });
  res.json(options);
});

passkeyRouter.post('/unlock/verify', async (req, res) => {
  const s = fullSession(req);
  const c = takeChallenge(s.id, 'unlock');
  const response = body(req).response as AuthenticationResponseJSON | undefined;
  const key = response?.id ? get<Row>('SELECT * FROM passkeys WHERE id = ? AND rp_id = ?', response.id, c.rpID) : undefined;
  let ok = false;
  if (key && response) {
    try {
      const v = await verifyAuthenticationResponse({
        response,
        expectedChallenge: c.challenge,
        expectedOrigin: c.origin,
        expectedRPID: c.rpID,
        credential: { id: key.id, publicKey: new Uint8Array(Buffer.from(key.public_key, 'base64url')), counter: key.counter, transports: transportsOf(key) },
        requireUserVerification: true,
      });
      ok = v.verified;
      if (ok) run('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?', v.authenticationInfo.newCounter, Date.now(), key.id);
    } catch {
      ok = false;
    }
  }
  if (!ok) {
    pinFailed(req, res, s, 'fingerprint');
    return;
  }
  pinPassed(req, s, 'fingerprint');
  res.json({ ok: true });
});

/* ----- managing fingerprints (signed in and PIN entered) ----- */

passkeyRouter.use(requireAuth);

passkeyRouter.get('/', (req, res) => {
  const rp = relyingParty(req.headers.host);
  const rows = all<Row>('SELECT * FROM passkeys ORDER BY created_at');
  res.json({
    supportedHere: !!rp,
    keys: rows.map((r) => ({ id: r.id, label: r.label, rpId: r.rp_id, here: r.rp_id === rp?.rpID, createdAt: r.created_at, lastUsedAt: r.last_used_at })),
  });
});

passkeyRouter.post('/register/options', stepUp, async (req, res) => {
  const rp = rpOf(req);
  const options = await generateRegistrationOptions({
    rpName: 'SENTINEL',
    rpID: rp.rpID,
    userName: 'admin',
    userDisplayName: 'SENTINEL admin',
    attestationType: 'none',
    excludeCredentials: keysFor(rp.rpID).map((k) => ({ id: k.id, transports: transportsOf(k) })),
    authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' },
    timeout: 60_000,
  });
  challenges.set(req.sessionId!, { kind: 'register', challenge: options.challenge, rpID: rp.rpID, origin: rp.origin, at: Date.now() });
  res.json(options);
});

passkeyRouter.post('/register/verify', async (req, res) => {
  const c = takeChallenge(req.sessionId!, 'register');
  const response = body(req).response as RegistrationResponseJSON | undefined;
  if (!response) throw new HttpError(400, 'Missing fingerprint response');
  let v;
  try {
    v = await verifyRegistrationResponse({ response, expectedChallenge: c.challenge, expectedOrigin: c.origin, expectedRPID: c.rpID, requireUserVerification: true });
  } catch (e) {
    throw new HttpError(400, `Fingerprint could not be added: ${e instanceof Error ? e.message : e}`);
  }
  if (!v.verified) throw new HttpError(400, 'Fingerprint could not be verified');
  const cred = v.registrationInfo.credential;
  const label = (typeof body(req).label === 'string' && (body(req).label as string).trim().slice(0, 60)) || deviceOf(req);
  run(
    'INSERT INTO passkeys (id, rp_id, public_key, counter, transports, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    cred.id, c.rpID, Buffer.from(cred.publicKey).toString('base64url'), cred.counter, cred.transports ? JSON.stringify(cred.transports) : null, label, Date.now(),
  );
  audit('auth.passkey_added', { ip: clientIp(req), detail: { label, rpId: c.rpID } });
  securityNotice(`Fingerprint added: ${label}`, `เพิ่มลายนิ้วมือสำหรับเข้าแอปแล้ว: ${label}`, req);
  res.json({ ok: true, label });
});

passkeyRouter.post('/:id/remove', stepUp, (req, res) => {
  const row = get<Row>('SELECT * FROM passkeys WHERE id = ?', String(req.params.id));
  if (!row) throw new HttpError(404, 'Not found');
  run('DELETE FROM passkeys WHERE id = ?', row.id);
  audit('auth.passkey_removed', { ip: clientIp(req), detail: { label: row.label } });
  securityNotice(`Fingerprint removed: ${row.label ?? '?'}`, `ลบลายนิ้วมือแล้ว: ${row.label ?? '?'}`, req);
  res.json({ ok: true });
});
