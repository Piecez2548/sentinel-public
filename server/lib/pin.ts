/**
 * App PIN: a 6-digit PIN the owner chooses, asked whenever SENTINEL is opened again after being left.
 * It sits on top of the signed-in session (password + 2FA happen at sign-in); it does not replace them.
 */

/** Switching away for a while (reading Telegram, answering a chat) does not ask again. Owner's choice: 5 minutes. */
export const PIN_GRACE_MS = 5 * 60_000;
/**
 * No request at all for this long also asks again (covers a "left the app" message that never arrived).
 * Longer than the grace period: a hidden app stops polling, and last_seen_at moves only once a minute.
 */
export const PIN_IDLE_MS = 7 * 60_000;
/** Wrong PINs before this session is signed out (then password + 2FA are needed). */
export const PIN_MAX_FAILS = 5;

export type PinSession = { pin_ok: number; away_at: number | null; last_seen_at: number };

/** Does this session have to enter the PIN before it may continue? */
export function pinNeeded(s: PinSession, now = Date.now()): boolean {
  if (!s.pin_ok) return true;
  if (s.away_at != null && now - s.away_at > PIN_GRACE_MS) return true;
  return now - s.last_seen_at > PIN_IDLE_MS;
}

const WEAK = new Set(['123456', '654321', '123123', '112233', '121212', '159753', '147258', '258369', '123321', '696969', '102030', '111222', '987654', '456789', '000111']);

/** Why a PIN is not acceptable, or null when it is fine. */
export function pinProblem(pin: unknown): string | null {
  if (typeof pin !== 'string' || !/^\d{6}$/.test(pin)) return 'PIN must be exactly 6 digits';
  if (/^(\d)\1{5}$/.test(pin)) return 'PIN is too easy to guess (all the same digit)';
  const d = [...pin].map(Number);
  const step = d[1] - d[0];
  if ((step === 1 || step === -1) && d.every((x, i) => i === 0 || x - d[i - 1] === step)) return 'PIN is too easy to guess (a run of digits)';
  if (WEAK.has(pin)) return 'PIN is too easy to guess (a common PIN)';
  return null;
}
