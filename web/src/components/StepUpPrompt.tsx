import { useEffect, useState, type FormEvent } from 'react';
import { api, setStepUpPrompt } from '../lib/api';
import { t } from '../lib/i18n';
import { Button, Input, Modal } from './ui';

/**
 * Security-sensitive changes (Telegram channel, detection rules, settings, password…) need the session
 * unlocked with a 6-digit code. When the server answers 423, this asks for the code once; the change is
 * then retried automatically and further changes work for 15 minutes.
 */
export function StepUpPrompt() {
  const [pending, setPending] = useState<((ok: boolean) => void) | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setStepUpPrompt(
      () =>
        new Promise<boolean>((resolve) => {
          setCode('');
          setError(null);
          setBusy(false);
          setPending(() => resolve);
        }),
    );
    return () => setStepUpPrompt(null);
  }, []);

  if (!pending) return null;
  const close = (ok: boolean) => {
    pending(ok);
    setPending(null);
  };

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/auth/unlock', { code });
      close(true);
    } catch (err) {
      setError(err instanceof Error ? t(err.message) : String(err));
      setCode('');
      setBusy(false);
    }
  }

  return (
    <Modal title={`🔐 ${t('Confirm it is you')}`} onClose={() => close(false)}>
      <form onSubmit={submit} className="space-y-3">
        <p className="text-sm text-muted">{t('This change affects security. Enter your 6-digit code — security changes then work without a code for 15 minutes.')}</p>
        <Input
          inputMode="numeric"
          autoComplete="one-time-code"
          autoFocus
          maxLength={6}
          placeholder="••••••"
          aria-label={t('6-digit code from your authenticator app')}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          className="text-center text-2xl tracking-[0.6em]"
        />
        {error && <div className="rounded-lg bg-bad/10 px-3 py-2 text-sm text-bad">{error}</div>}
        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" onClick={() => close(false)}>
            {t('Cancel')}
          </Button>
          <Button variant="primary" disabled={busy || code.length !== 6}>
            {busy ? t('Working…') : `🔓 ${t('Confirm')}`}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
