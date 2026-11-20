import { all, getSetting, setSetting } from '../db.js';
import { escHtml, HOUR, MIN, parseJson } from '../lib/util.js';
import { SEV_ICON } from '../lib/device-messages.js';
import { rule, upsertFinding } from './detection.js';

/**
 * Watches SENTINEL's own sign-in page. auth.ts already blocks guessing (account lock, per-IP block)
 * and audits every attempt; this turns those attempts into findings + plain Thai Telegram messages.
 * Called right after auth.ts writes the audit row, so the counts below include the current attempt.
 */

const WINDOW = 15 * MIN;
const KNOWN_KEY = 'sentinel_known_logins';

const isLocal = (ip: string) => ip === '127.0.0.1' || ip === '::1';
const whereTh = (ip: string) => (isLocal(ip) ? 'จากเครื่องนี้เอง' : `จาก IP ${ip}`);
const whereEn = (ip: string) => (isLocal(ip) ? 'from this PC' : `from ${ip}`);

/** Wrong 2FA codes, or wrong passwords of any kind (sign-in, password change, turning 2FA off). */
function recentFailures(ip: string, mfa: boolean, now: number): number {
  return all<{ detail: string | null }>("SELECT detail FROM audit_logs WHERE action = 'auth.login_failed' AND ip = ? AND ts > ?", ip, now - WINDOW)
    .filter((r) => (parseJson<{ reason?: string }>(r.detail ?? '', {}).reason === 'bad_mfa_code') === mfa).length;
}

const msg = (sev: string, headTh: string, whyTh: string, fixTh: string, headEn: string, whyEn: string, fixEn: string) => ({
  th: `${SEV_ICON[sev]} <b>${escHtml(headTh)}</b>\n${escHtml(whyTh)}\n\n👉 <b>วิธีแก้:</b> ${escHtml(fixTh)}\n\n💻 SENTINEL`,
  en: `${SEV_ICON[sev]} <b>${escHtml(headEn)}</b>\n${escHtml(whyEn)}\n\n👉 <b>Fix:</b> ${escHtml(fixEn)}\n\n💻 SENTINEL`,
});

const CHANGE_PW_TH = 'SENTINEL → ตั้งค่า → เปลี่ยนรหัสผ่าน แล้วกด "ออกจากระบบทุกที่"';
const CHANGE_PW_EN = 'SENTINEL → Settings → Change password, then "Sign out everywhere"';

/** A failed sign-in step. `locked` = this attempt locked the account. */
export function onLoginFailed(ip: string, reason: string, locked: boolean, userAgent: string, now = Date.now()) {
  const details = { ip, userAgent: userAgent.slice(0, 200), reason };

  if (reason === 'bad_mfa_code') {
    const r = rule('sentinel_mfa_failed');
    if (!r) return;
    const n = recentFailures(ip, true, now);
    const repeated = n >= (r.p.repeat ?? 3);
    const sev = repeated ? 'critical' : 'high';
    upsertFinding({
      ruleId: 'sentinel_mfa_failed',
      assetId: null,
      severity: sev,
      title: `Correct password, wrong 2FA code ${whereEn(ip)}${repeated ? ` (${n} times)` : ''}`,
      summary: `${n} wrong 6-digit code(s) in 15 min after the correct SENTINEL password`,
      fingerprint: `sentinel_mfa_failed:${ip}:${repeated ? 'repeat' : 'once'}`,
      condition: repeated ? `≥ ${r.p.repeat} wrong 2FA codes within 15 min` : 'Correct password followed by a wrong 2FA code',
      extra: { details: { ...details, attempts: n } },
      mergeWindowMs: HOUR,
      notify: repeated
        ? msg(sev, `มีคนรู้รหัสผ่าน SENTINEL และกำลังเดารหัส 6 หลัก (${n} ครั้ง)`, `${whereTh(ip)} — รหัสผ่านหลุดแล้ว ตอนนี้เหลือแค่รหัส 6 หลักที่กันไว้`, CHANGE_PW_TH,
            `Someone knows your SENTINEL password and is guessing the 6-digit code (${n} times)`, `${whereEn(ip)} — the password is out; only the code is stopping them.`, CHANGE_PW_EN)
        : msg(sev, 'รหัสผ่าน SENTINEL ถูก แต่รหัส 6 หลักผิด', `${whereTh(ip)} — ถ้าเป็นคุณพิมพ์ผิดเอง ไม่ต้องทำอะไร ถ้าไม่ใช่ แปลว่ามีคนรู้รหัสผ่านของคุณ`, `ถ้าไม่ใช่คุณ: ${CHANGE_PW_TH}`,
            'Correct SENTINEL password but a wrong 6-digit code', `${whereEn(ip)} — if it was you mistyping, nothing to do. If not, someone knows your password.`, `If it wasn't you: ${CHANGE_PW_EN}`),
    });
    return;
  }

  const r = rule('sentinel_login_failed');
  if (!r) return;
  const n = recentFailures(ip, false, now);
  if (locked) {
    upsertFinding({
      ruleId: 'sentinel_login_failed',
      assetId: null,
      severity: 'high',
      title: `SENTINEL account locked after wrong passwords ${whereEn(ip)}`,
      summary: `${n} wrong password(s) in 15 min; sign-in is locked for 15 minutes`,
      fingerprint: `sentinel_login_failed:${ip}:locked`,
      condition: 'Too many wrong passwords — account locked',
      extra: { details: { ...details, attempts: n, locked: true } },
      mergeWindowMs: HOUR,
      notify: msg('high', 'มีคนเดารหัสผ่านเข้า SENTINEL จนบัญชีถูกล็อก', `${whereTh(ip)} ใส่รหัสผิด ${n} ครั้งใน 15 นาที — ระบบล็อกไว้ 15 นาทีแล้ว`, 'ถ้าไม่ใช่คุณ: ตั้งรหัสผ่านให้ยาวและไม่ซ้ำกับที่อื่น และตรวจว่าใครเข้าถึง Tailscale ได้บ้าง',
        'Someone guessed the SENTINEL password until the account locked', `${whereEn(ip)}: ${n} wrong passwords in 15 min — locked for 15 minutes.`, 'If it was not you: use a long unique password and check who can reach your Tailscale network'),
    });
  } else if (n >= (r.p.threshold ?? 3)) {
    upsertFinding({
      ruleId: 'sentinel_login_failed',
      assetId: null,
      severity: 'medium',
      title: `Wrong SENTINEL password ${n} times ${whereEn(ip)}`,
      summary: `${n} wrong password(s) within 15 min`,
      fingerprint: `sentinel_login_failed:${ip}:fail`,
      condition: `≥ ${r.p.threshold} wrong passwords from one address within 15 min`,
      extra: { details: { ...details, attempts: n } },
      mergeWindowMs: HOUR,
      notify: msg('medium', `ใส่รหัสผ่าน SENTINEL ผิด ${n} ครั้ง`, `${whereTh(ip)} ภายใน 15 นาที — ถ้าเป็นคุณจำรหัสไม่ได้ ก็ไม่เป็นไร`, 'ถ้าไม่ใช่คุณ: เปลี่ยนรหัสผ่าน SENTINEL ให้ยาวและไม่ซ้ำกับที่อื่น',
        `Wrong SENTINEL password ${n} times`, `${whereEn(ip)} within 15 minutes — fine if it was you.`, 'If not: change the SENTINEL password to a long unique one'),
    });
  }
}

/** "Mozilla/5.0 (Linux; Android 14…) … Chrome/…" → "Chrome on Android" */
export function deviceLabel(ua: string): string {
  const os = /Android/i.test(ua) ? 'Android' : /iPhone|iPad/i.test(ua) ? 'iPhone/iPad' : /Windows/i.test(ua) ? 'Windows' : /Mac OS X|Macintosh/i.test(ua) ? 'Mac' : /Linux/i.test(ua) ? 'Linux' : 'unknown OS';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : ua ? 'browser' : 'unknown browser';
  return `${br} on ${os}`;
}

const deviceKey = (ip: string, ua: string) => `${ip}|${deviceLabel(ua)}`;

/** At startup: learn the devices of past sign-ins silently, so only devices after that are "new". */
export function seedKnownLogins() {
  if (getSetting(KNOWN_KEY) != null) return;
  const past = all<{ ip: string | null; user_agent: string | null }>('SELECT ip, user_agent FROM sessions WHERE mfa_pending = 0');
  if (!past.length) return; // fresh install: the first sign-in becomes the first known device
  setSetting(KNOWN_KEY, JSON.stringify([...new Set(past.map((s) => deviceKey(s.ip ?? '', s.user_agent ?? '')))]));
}

/** A completed sign-in (after 2FA when it is on). */
export function onLoginSuccess(ip: string, userAgent: string) {
  const raw = getSetting(KNOWN_KEY);
  const key = deviceKey(ip, userAgent);
  if (raw == null) {
    // Very first sign-in (fresh install): nothing to compare with yet.
    setSetting(KNOWN_KEY, JSON.stringify([key]));
    return;
  }
  const known = new Set(parseJson<string[]>(raw, []));
  if (known.has(key)) return;
  known.add(key);
  setSetting(KNOWN_KEY, JSON.stringify([...known].slice(-200)));
  if (!rule('sentinel_new_device')) return;
  const dev = deviceLabel(userAgent);
  upsertFinding({
    ruleId: 'sentinel_new_device',
    assetId: null,
    title: `SENTINEL sign-in from a new device: ${dev} ${whereEn(ip)}`,
    summary: `First successful sign-in from ${ip} with ${dev}`,
    fingerprint: `sentinel_new_device:${key}`,
    condition: 'Address + browser never seen in a successful sign-in before',
    extra: { details: { ip, userAgent: userAgent.slice(0, 200), device: dev } },
    mergeWindowMs: 365 * 24 * HOUR,
    notify: msg('medium', `เข้าสู่ระบบ SENTINEL จากอุปกรณ์ใหม่: ${dev}`, `${whereTh(ip)} — ถ้าเป็นคุณ (เช่น เพิ่งเปิดจากมือถือ) ไม่ต้องทำอะไร`, `ถ้าไม่ใช่คุณ: ${CHANGE_PW_TH}`,
      `New device signed in to SENTINEL: ${dev}`, `${whereEn(ip)} — if it was you (e.g. your phone), nothing to do.`, `If not: ${CHANGE_PW_EN}`),
  });
}
