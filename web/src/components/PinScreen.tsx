import { startAuthentication } from '@simplewebauthn/browser';
import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../lib/api';
import { fingerprintError } from '../lib/webauthn-errors';
import { getLang, t } from '../lib/i18n';
import { useTick } from '../lib/hooks';
import { Icon } from './icons';

const KEYS = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', '⌫'] as const;

/** Fingerprint glyph (concentric ridges), drawn here so it matches the theme. */
function FingerprintIcon({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" className={className} aria-hidden="true">
      <path d="M17 13.5A25 25 0 0 1 47 13.5" />
      <path d="M11 24a23 23 0 0 1 42 0" />
      <path d="M14 46c-2.5-4-3.5-8.5-3-13a21 21 0 0 1 42 0c0 3-.5 5-1.5 7" />
      <path d="M20 52c-2.5-3.5-4-8-4-13a16 16 0 0 1 32 0v2a5 5 0 0 1-10 0v-2a6 6 0 0 0-12 0c0 7 3 13 8 17" />
      <path d="M27 56c-3-3.5-5-9-5-15a10 10 0 0 1 20 0" />
      <path d="M32 39c0 8 3.5 13.5 9 17" />
      <path d="M46 52c-2-1-3.5-2.5-4.5-4.5" />
    </svg>
  );
}

/** Phone-style clock and date at the top of the scan screen. */
function Clock() {
  useTick(1000);
  const now = new Date();
  const locale = getLang() === 'th' ? 'th-TH' : 'en-GB';
  const time = now.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', hour12: false });
  const date = now.toLocaleDateString(locale, { weekday: 'short', day: 'numeric', month: 'short' });
  return (
    <div className="text-center">
      <div className="text-lg font-medium text-slate-200">{date}</div>
      <div className="tabular mt-1 text-7xl font-light tracking-tight text-white">{time}</div>
    </div>
  );
}

/**
 * Lock screen shown when SENTINEL is opened again. With a fingerprint set up on this device it looks like
 * the phone's own lock screen (clock, a fingerprint button at the bottom, "Use PIN"); otherwise it is the
 * PIN pad. Wrong PINs and failed fingerprints share 5 tries; the 5th signs this device out (server-side).
 */
export function PinScreen({ onUnlocked, onSignedOut }: { onUnlocked: () => void; onSignedOut: () => void }) {
  const [mode, setMode] = useState<'loading' | 'scan' | 'pin'>('loading');
  const [hasFingerprint, setHasFingerprint] = useState(false);
  const [pin, setPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  const autoTried = useRef(false);

  /** Shared result handling for the PIN and the fingerprint (both count toward the same 5 tries). */
  const settle = useCallback(
    async (res: Response, how: 'pin' | 'fingerprint') => {
      const data = (await res.json().catch(() => ({}))) as { error?: string; triesLeft?: number };
      if (res.ok) {
        onUnlocked();
        return;
      }
      setPin('');
      setBusy(false);
      setShake(true);
      setTimeout(() => setShake(false), 450);
      if (data.triesLeft == null && res.status === 401) {
        // Too many wrong tries: this device was signed out.
        setError(t(data.error ?? 'Signed out'));
        setTimeout(onSignedOut, 1800);
        return;
      }
      if (data.triesLeft != null) setError(how === 'pin' ? t('Wrong PIN — {n} tries left', { n: data.triesLeft }) : t('Fingerprint not accepted — {n} tries left', { n: data.triesLeft }));
      else setError(t(data.error ?? 'Failed'));
    },
    [onUnlocked, onSignedOut],
  );

  const submit = useCallback(
    async (value: string) => {
      setBusy(true);
      setError(null);
      const res = await fetch('/api/auth/pin/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pin: value }) });
      await settle(res, 'pin');
    },
    [settle],
  );

  const scan = useCallback(
    async (auto: boolean) => {
      setBusy(true);
      setScanning(true);
      setError(null);
      setHint(null);
      const started = Date.now();
      try {
        const opt = await fetch('/api/auth/passkey/unlock/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        const optionsJSON = await opt.json();
        if (!opt.ok) throw new ApiError(opt.status, optionsJSON.error ?? 'Failed');
        const response = await startAuthentication({ optionsJSON });
        const res = await fetch('/api/auth/passkey/unlock/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ response }) });
        await settle(res, 'fingerprint');
      } catch (e) {
        setBusy(false);
        const cancelled = e instanceof Error && e.name === 'NotAllowedError';
        // The phone refuses a scan that was not started by a tap: that is not an error, just ask for the tap.
        if (cancelled && auto && Date.now() - started < 1500) setHint(t('Tap the fingerprint to unlock'));
        else if (cancelled) setHint(t('Cancelled — tap the fingerprint to try again, or use your PIN'));
        else setError(fingerprintError(e, 'unlock'));
      } finally {
        setScanning(false);
      }
    },
    [settle],
  );

  // Scan screen first when this device has a fingerprint; the scanner opens once by itself.
  useEffect(() => {
    fetch('/api/auth/passkey/status')
      .then((r) => (r.ok ? r.json() : { available: false }))
      .catch(() => ({ available: false }))
      .then((d: { available: boolean }) => {
        setHasFingerprint(d.available);
        setMode(d.available ? 'scan' : 'pin');
        if (d.available && !autoTried.current) {
          autoTried.current = true;
          void scan(true);
        }
      });
  }, [scan]);

  const press = useCallback(
    (k: string) => {
      if (busy) return;
      if (k === '⌫') {
        setPin((p) => p.slice(0, -1));
        return;
      }
      if (!/^\d$/.test(k)) return;
      setPin((p) => (p.length >= 6 ? p : p + k));
    },
    [busy],
  );

  // The sixth digit submits.
  useEffect(() => {
    if (pin.length === 6 && !busy) void submit(pin);
  }, [pin, busy, submit]);

  // A keyboard works too (SENTINEL on the PC).
  useEffect(() => {
    if (mode !== 'pin') return;
    const on = (e: KeyboardEvent) => {
      if (/^\d$/.test(e.key)) press(e.key);
      else if (e.key === 'Backspace') press('⌫');
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [press, mode]);

  async function signOut() {
    await api.post('/auth/logout').catch(() => undefined);
    onSignedOut();
  }

  if (mode === 'loading') return <div className="fixed inset-0 z-[60] bg-bg" />;

  if (mode === 'scan')
    return (
      <div className="fade-in fixed inset-0 z-[60] flex flex-col items-center bg-bg px-6 pb-10 pt-[12vh]" role="dialog" aria-label={t('Unlock SENTINEL')}>
        <div className="flex items-center gap-2 text-sm font-semibold tracking-[0.3em] text-muted">
          <Icon.logo /> SENTINEL
        </div>
        <div className="mt-8">
          <Clock />
        </div>

        <div className="mt-auto flex w-full max-w-xs flex-col items-center">
          <div className={`min-h-10 px-2 text-center text-sm ${error ? 'text-bad' : 'text-slate-300'} ${shake ? 'animate-[pin-shake_0.4s]' : ''}`} aria-live="polite">
            {error ?? hint ?? (scanning ? t('Touch the fingerprint sensor') : t('Tap the fingerprint to unlock'))}
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={() => void scan(false)}
            aria-label={t('Use fingerprint')}
            className="relative mt-4 grid size-24 place-items-center rounded-full text-white transition active:scale-95 disabled:opacity-90"
          >
            {scanning && <span className="absolute inset-0 animate-ping rounded-full bg-accent/25" />}
            <span className={`absolute inset-0 rounded-full border ${scanning ? 'border-accent/70 bg-accent/15' : 'border-white/15 bg-white/5'}`} />
            <FingerprintIcon className={`relative size-14 ${scanning ? 'text-violet-200' : 'text-white'}`} />
          </button>
          <button
            type="button"
            onClick={() => {
              setError(null);
              setHint(null);
              setMode('pin');
            }}
            className="mt-8 rounded-full px-5 py-2 text-sm text-slate-300 transition hover:bg-white/5 hover:text-white"
          >
            {t('Use PIN')}
          </button>
        </div>
      </div>
    );

  return (
    <div className="fade-in fixed inset-0 z-[60] flex flex-col items-center justify-center bg-bg px-6 py-8" role="dialog" aria-label={t('Enter your PIN')}>
      <div className="flex w-full max-w-xs flex-col items-center">
        <div className="mb-3 scale-125">
          <Icon.logo />
        </div>
        <div className="bg-gradient-to-r from-white to-violet-200 bg-clip-text text-lg font-bold tracking-[0.3em] text-transparent">SENTINEL</div>
        <p className="mt-6 text-sm text-muted">{t('Enter your PIN')}</p>

        <div className={`mt-4 flex gap-3 ${shake ? 'animate-[pin-shake_0.4s]' : ''}`} aria-live="polite" aria-label={t('{n} of 6 digits', { n: pin.length })}>
          {Array.from({ length: 6 }, (_, i) => (
            <span key={i} className={`size-3.5 rounded-full border transition ${i < pin.length ? 'border-accent bg-accent shadow-[0_0_8px] shadow-accent/60' : 'border-line bg-panel-2'}`} />
          ))}
        </div>
        <div className="mt-3 min-h-5 text-center text-sm text-bad">{error}</div>

        <div className="mt-4 grid w-full grid-cols-3 gap-3">
          {KEYS.map((k, i) =>
            k === '' ? (
              hasFingerprint ? (
                <button
                  key={i}
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setError(null);
                    setMode('scan');
                    void scan(false);
                  }}
                  aria-label={t('Use fingerprint')}
                  className="grid h-16 place-items-center rounded-2xl text-slate-300 transition hover:text-white active:scale-95"
                >
                  <FingerprintIcon className="size-8" />
                </button>
              ) : (
                <span key={i} />
              )
            ) : (
              <button
                key={i}
                type="button"
                disabled={busy}
                onClick={() => press(k)}
                aria-label={k === '⌫' ? t('Delete') : k}
                className={`grid h-16 place-items-center rounded-2xl text-2xl font-medium transition active:scale-95 disabled:opacity-50 ${k === '⌫' ? 'text-muted hover:text-white' : 'border border-line bg-panel hover:border-accent/60 active:bg-accent/20'}`}
              >
                {k}
              </button>
            ),
          )}
        </div>

        <button type="button" onClick={() => void signOut()} className="mt-8 text-xs text-muted underline-offset-4 hover:text-white hover:underline">
          {t('Forgot PIN? Sign out and sign in with your password')}
        </button>
      </div>
    </div>
  );
}
