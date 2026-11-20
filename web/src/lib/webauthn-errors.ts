import { ApiError } from './api';
import { t } from './i18n';

/**
 * Plain words for a failed fingerprint scan or setup. The browser and @simplewebauthn report
 * technical English (DOMException names, "The operation either timed out or was not allowed…");
 * the owner sees a short explanation and what to do instead. SENTINEL's own server errors are
 * already translated strings and pass through t().
 */
export function fingerprintError(e: unknown, phase: 'unlock' | 'register'): string {
  if (e instanceof ApiError) return t(e.message);
  const name = e instanceof Error ? e.name : '';
  const msg = e instanceof Error ? e.message : String(e);
  console.warn('[fingerprint]', name, msg);
  switch (name) {
    case 'NotAllowedError':
    case 'AbortError':
      return phase === 'register' ? t('Cancelled on the device') : t('Cancelled — tap the fingerprint to try again, or use your PIN');
    case 'InvalidStateError':
      return phase === 'register' ? t('This device already has a fingerprint set up') : t('This fingerprint is not set up for SENTINEL — use your PIN');
    case 'SecurityError':
      return t('Fingerprints only work on the SENTINEL web address (…ts.net), not an IP address — use your PIN');
    case 'NotSupportedError':
      return t('This browser or device does not support fingerprint sign-in — use your PIN');
    case 'ConstraintError':
      return t('Turn on a screen lock and fingerprint on this device first');
  }
  if (/not supported/i.test(msg)) return t('This browser or device does not support fingerprint sign-in — use your PIN');
  return phase === 'register' ? t('Fingerprint setup did not work — try again') : t('Fingerprint did not work — try again or use your PIN');
}
