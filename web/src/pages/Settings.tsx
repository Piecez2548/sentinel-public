import { browserSupportsWebAuthn, startRegistration } from '@simplewebauthn/browser';
import { useState } from 'react';
import { Button, Card, Empty, ErrorNote, Field, FormModal, Input, PageHeader, Select, Tabs, Td, Th, Toggle } from '../components/ui';
import { api, type ComponentHealth } from '../lib/api';
import { ago, bytes, duration, sevLabel, stamp } from '../lib/format';
import { getLang, setLang, t } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';
import { fingerprintError } from '../lib/webauthn-errors';

type Settings = { digestEnabled: boolean; digestHour: number; backupHour: number; notifyFindingMinSeverity: string; localCollectorEnabled: boolean; eventlogEnabled: boolean; language: 'th' | 'en'; platform: string };
type Session = { id: number; createdAt: number; lastSeenAt: number; expiresAt: number; ip: string; userAgent: string; current: boolean };
type Backup = { name: string; createdAt: number; reason: string; bytes: number; hasKey: boolean; counts: Record<string, number>; copied: boolean | null };
type AuditEntry = { seq: number; ts: number; action: string; resourceType: string | null; resourceId: string | null; detail: unknown; ip: string | null; hash: string };

/** Set, change or remove the app PIN asked when SENTINEL is opened again. Needs the 2FA unlock (423 → code prompt). */
function PassCheckForm({ onClose, onResult }: { onClose: () => void; onResult: (ok: boolean, text: string) => void }) {
  const [pass, setPass] = useState('');
  return (
    <FormModal
      title={t('Test the backup passphrase')}
      submitLabel={`🔑 ${t('Check')}`}
      onClose={onClose}
      onSubmit={async () => {
        const r = await api.post<{ ok: boolean; opened: string | null; fileProblem: string | null; triesLeft: number }>('/backups/check-passphrase', { passphrase: pass });
        if (!r.ok) throw new Error(t('Not the backup passphrase. {n} tries left in the next 15 minutes.', { n: r.triesLeft }));
        onResult(
          !r.fileProblem,
          r.opened
            ? t('Correct — and it opens the newest cloud copy ({name}). You could restore on another PC.', { name: r.opened })
            : r.fileProblem
              ? `${t('Correct passphrase, but the newest cloud copy did not open')}: ${t(r.fileProblem)}`
              : t('Correct passphrase.'),
        );
      }}
    >
      <p className="text-sm text-muted">{t('Type the passphrase from where you wrote it down (not from memory of this screen). It is checked and then forgotten: never stored or logged.')}</p>
      <Field label={t('Backup passphrase')}>
        <Input type="password" autoComplete="off" value={pass} onChange={(e) => setPass(e.target.value)} autoFocus />
      </Field>
    </FormModal>
  );
}

function SealForm({ change, onClose, onDone }: { change: boolean; onClose: () => void; onDone: () => void }) {
  const [pass, setPass] = useState('');
  const [again, setAgain] = useState('');
  const [noted, setNoted] = useState(false);
  return (
    <FormModal
      title={change ? t('Change backup passphrase') : t('Encrypt the cloud copy')}
      submitLabel={`🔒 ${t('Encrypt')}`}
      onClose={onClose}
      onSubmit={async () => {
        if (pass !== again) throw new Error(t('The two passphrases do not match'));
        if (!noted) throw new Error(t('Tick the box once the passphrase is written down'));
        await api.post('/backups/seal', { passphrase: pass });
        onDone();
      }}
    >
      <p className="text-sm text-muted">{t('Each backup in the cloud folder becomes one encrypted file that only this passphrase opens. The plain copies there (which hold master.key) are deleted.')}</p>
      <Field label={t('Passphrase (min. 12 characters)')} hint={t('A few unrelated words is easy to remember and hard to guess.')}>
        <Input type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} autoFocus />
      </Field>
      <Field label={t('Type it again')}>
        <Input type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
      </Field>
      <p className="rounded-lg bg-warn/10 px-3 py-2 text-xs text-warn">{t('If you forget it, the cloud copies cannot be opened by anyone, including you. Keep it somewhere other than this PC, e.g. a password manager or on paper.')}</p>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={noted} onChange={(e) => setNoted(e.target.checked)} className="size-4 accent-[var(--color-accent)]" />
        {t('I have written the passphrase down')}
      </label>
    </FormModal>
  );
}

function PinForm({ change, onClose, onDone }: { change: boolean; onClose: () => void; onDone: () => void }) {
  const [pin, setPin] = useState('');
  const [again, setAgain] = useState('');
  return (
    <FormModal
      title={change ? t('Change app PIN') : t('Set app PIN')}
      submitLabel={`✓ ${t('Save PIN')}`}
      onClose={onClose}
      onSubmit={async () => {
        if (pin !== again) throw new Error(t('The two PINs do not match'));
        await api.post('/auth/pin', { pin });
        onDone();
      }}
    >
      <p className="text-sm text-muted">{t('6 digits you choose. Asked when you open SENTINEL again after more than 5 minutes away. 5 wrong PINs sign that device out.')}</p>
      <Field label={t('New PIN')}>
        <Input type="password" inputMode="numeric" autoComplete="new-password" maxLength={6} value={pin} onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))} autoFocus className="text-center text-2xl tracking-[0.6em]" />
      </Field>
      <Field label={t('Type it again')}>
        <Input type="password" inputMode="numeric" autoComplete="new-password" maxLength={6} value={again} onChange={(e) => setAgain(e.target.value.replace(/\D/g, ''))} className="text-center text-2xl tracking-[0.6em]" />
      </Field>
      <p className="text-xs text-muted">{t('Avoid 123456, 000000, birthdays and your phone unlock PIN.')}</p>
    </FormModal>
  );
}

type PasskeyList = { supportedHere: boolean; keys: { id: string; label: string | null; rpId: string; here: boolean; createdAt: number; lastUsedAt: number | null }[] };

/** Fingerprint / face / Windows Hello that can unlock the PIN screen instead of typing the PIN. */
function Fingerprints({ pinEnabled }: { pinEnabled: boolean }) {
  const list = useApi(() => api.get<PasskeyList>('/auth/passkey'), []);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const canHere = !!list.data?.supportedHere && browserSupportsWebAuthn();

  async function add() {
    setBusy(true);
    setErr(null);
    setDone(null);
    try {
      const optionsJSON = await api.post<Parameters<typeof startRegistration>[0]['optionsJSON']>('/auth/passkey/register/options');
      const response = await startRegistration({ optionsJSON });
      const r = await api.post<{ ok: boolean; label: string }>('/auth/passkey/register/verify', { response });
      setDone(t('Fingerprint added for {device}', { device: r.label }));
      list.reload();
    } catch (e) {
      setErr(fingerprintError(e, 'register'));
    }
    setBusy(false);
  }

  return (
    <Card title={`👆 ${t('Fingerprint unlock')}`}>
      <p className="mb-3 text-xs text-muted">
        {t('Unlock the PIN screen with this device’s fingerprint, face or Windows Hello instead of typing the PIN. Only a public key is stored here; your fingerprint never leaves the device. A failed check counts as a wrong PIN.')}
      </p>
      {!pinEnabled && <p className="mb-3 rounded-lg bg-warn/10 px-3 py-2 text-xs text-warn">{t('Set an app PIN first — the fingerprint unlocks the PIN screen.')}</p>}
      <ErrorNote error={list.error ?? err} />
      {done && <p className="mb-3 rounded-lg bg-ok/10 px-3 py-2 text-xs text-ok">✓ {done}</p>}
      {!!list.data?.keys.length && (
        <ul className="mb-3 space-y-2 text-xs">
          {list.data.keys.map((k) => (
            <li key={k.id} className="flex items-center justify-between gap-2 rounded-lg bg-panel-2 px-3 py-2">
              <span className="min-w-0">
                <span className="block truncate text-sm">
                  {k.label ?? t('Unknown device')} {k.here && <b className="text-ok">· {t('this address')}</b>}
                </span>
                <span className="block truncate text-muted">
                  {k.rpId} · {t('added {ago}', { ago: ago(k.createdAt) })}
                  {k.lastUsedAt ? ` · ${t('used {ago}', { ago: ago(k.lastUsedAt) })}` : ''}
                </span>
              </span>
              <Button
                variant="ghost"
                onClick={async () => {
                  if (!confirm(t('Remove this fingerprint?'))) return;
                  await api.post(`/auth/passkey/${encodeURIComponent(k.id)}/remove`).catch((e) => setErr(e instanceof Error ? t(e.message) : String(e)));
                  list.reload();
                }}
              >
                {t('Remove')}
              </Button>
            </li>
          ))}
        </ul>
      )}
      {canHere ? (
        <Button variant="primary" disabled={busy || !pinEnabled} onClick={() => void add()}>
          {busy ? t('Waiting for the fingerprint…') : `👆 ${t('Add this device’s fingerprint')}`}
        </Button>
      ) : (
        list.data && <p className="text-xs text-muted">{t('Open SENTINEL from the phone app (the https://…ts.net address) to add its fingerprint. The PC app at 127.0.0.1 cannot use fingerprints.')}</p>
      )}
    </Card>
  );
}

function Account({ onLogout }: { onLogout: () => void }) {
  const state = useApi(() => api.get<{ mfaEnabled: boolean; pinEnabled?: boolean }>('/auth/state'), []);
  const [pinForm, setPinForm] = useState(false);
  const sessions = useApi(() => api.get<{ sessions: Session[] }>('/auth/sessions'), []);
  const [pw, setPw] = useState(false);
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [mfaDisable, setMfaDisable] = useState(false);
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [code, setCode] = useState('');

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title={t('Password & two-factor authentication')}>
        <div className="space-y-4 text-sm">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div>{t('Password')}</div>
              <div className="text-xs text-muted">{t('Argon2id hashed. Changing it signs out every other session.')}</div>
            </div>
            <Button onClick={() => setPw(true)}>{t('Change')}</Button>
          </div>
          <div className="flex items-center justify-between gap-3">
            <div>
              <div>{t('Two-factor (TOTP)')}</div>
              <div className="text-xs text-muted">{state.data?.mfaEnabled ? t('Enabled — a 6-digit code is required at sign-in.') : t('Off. Recommended, especially if you ever expose SENTINEL beyond this PC.')}</div>
            </div>
            {state.data?.mfaEnabled ? (
              <Button variant="danger" onClick={() => setMfaDisable(true)}>
                {t('Disable')}
              </Button>
            ) : (
              <Button variant="primary" onClick={async () => setMfaSetup(await api.post<{ secret: string; qr: string }>('/auth/mfa/setup'))}>
                {t('Enable')}
              </Button>
            )}
          </div>
          <div className="flex items-center justify-between gap-3">
            <div>
              <div>{t('App PIN')}</div>
              <div className="text-xs text-muted">{state.data?.pinEnabled ? t('On — a 6-digit PIN is asked whenever SENTINEL is opened again.') : t('Off. A 6-digit PIN you choose, asked whenever SENTINEL is opened again.')}</div>
            </div>
            <div className="flex shrink-0 gap-2">
              {state.data?.pinEnabled && (
                <Button
                  variant="danger"
                  onClick={async () => {
                    if (!confirm(t('Turn the app PIN off?'))) return;
                    await api.post('/auth/pin/remove');
                    state.reload();
                  }}
                >
                  {t('Turn off')}
                </Button>
              )}
              <Button variant={state.data?.pinEnabled ? 'default' : 'primary'} onClick={() => setPinForm(true)}>
                {state.data?.pinEnabled ? t('Change') : t('Set PIN')}
              </Button>
            </div>
          </div>
        </div>
      </Card>
      {pinForm && <PinForm change={!!state.data?.pinEnabled} onClose={() => setPinForm(false)} onDone={() => state.reload()} />}
      <Fingerprints pinEnabled={!!state.data?.pinEnabled} />

      <Card
        title={t('Active sessions')}
        right={
          <Button
            variant="danger"
            onClick={async () => {
              if (!confirm(t('Sign out everywhere (including here)?'))) return;
              await api.post('/auth/logout-all');
              onLogout();
            }}
          >
            {t('Sign out everywhere')}
          </Button>
        }
      >
        <ul className="space-y-2 text-xs">
          {sessions.data?.sessions.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-2 rounded-lg bg-panel-2 px-3 py-2">
              <span className="min-w-0">
                <span className="block truncate">{s.userAgent || t('Unknown browser')}</span>
                <span className="text-muted">
                  {s.ip} · {t('signed in {ago}', { ago: ago(s.createdAt) })} · {t('active {ago}', { ago: ago(s.lastSeenAt) })} {s.current && <b className="text-ok">· {t('this session')}</b>}
                </span>
              </span>
              {!s.current && (
                <Button
                  variant="ghost"
                  onClick={async () => {
                    await api.del(`/auth/sessions/${s.id}`);
                    sessions.reload();
                  }}
                >
                  {t('Revoke')}
                </Button>
              )}
            </li>
          ))}
        </ul>
      </Card>

      {pw && (
        <FormModal
          title={t('Change password')}
          onClose={() => setPw(false)}
          onSubmit={async () => {
            await api.post('/auth/password', { current: cur, next });
            setCur('');
            setNext('');
            sessions.reload();
          }}
        >
          <Field label={t('Current password')}>
            <Input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoFocus />
          </Field>
          <Field label={t('New password (min. 12 characters)')}>
            <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
          </Field>
        </FormModal>
      )}
      {mfaSetup && (
        <FormModal
          title={t('Enable two-factor authentication')}
          submitLabel={t('Verify & enable')}
          onClose={() => setMfaSetup(null)}
          onSubmit={async () => {
            await api.post('/auth/mfa/enable', { code });
            setCode('');
            state.reload();
          }}
        >
          <p className="text-sm text-muted">{t('Scan with Google Authenticator, Microsoft Authenticator, 1Password, etc. Then enter the 6-digit code.')}</p>
          <div className="flex justify-center rounded-xl bg-white p-3">
            <img src={mfaSetup.qr} alt="MFA QR code" width={200} height={200} />
          </div>
          <p className="break-all text-center text-xs text-muted">
            {t('Or enter this key manually:')} <code className="text-slate-300">{mfaSetup.secret}</code>
          </p>
          <Field label={t('Code')}>
            <Input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} autoFocus />
          </Field>
        </FormModal>
      )}
      {mfaDisable && (
        <FormModal
          title={t('Disable two-factor authentication')}
          submitLabel={t('Disable')}
          danger
          onClose={() => setMfaDisable(false)}
          onSubmit={async () => {
            await api.post('/auth/mfa/disable', { password: cur, code });
            setCur('');
            setCode('');
            state.reload();
          }}
        >
          <Field label={t('Password')}>
            <Input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoFocus />
          </Field>
          <Field label={t('Current 6-digit code')}>
            <Input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
          </Field>
        </FormModal>
      )}
    </div>
  );
}

function Monitoring() {
  useTick();
  const settings = useApi(() => api.get<Settings>('/settings'), [], ['settings']);
  const health = useApi(() => api.get<{ components: ComponentHealth[]; notifications: { channels: number; pendingDeliveries: number; failedDeliveries24h: number }; uptimeSec: number; memoryMb: number }>('/health'), [], ['health', 'notifications'], 15_000);
  const [err, setErr] = useState<string | null>(null);
  const s = settings.data;

  async function update(patch: Partial<Settings>) {
    setErr(null);
    try {
      settings.setData(await api.put<Settings>('/settings', patch));
    } catch (e) {
      setErr(e instanceof Error ? t(e.message) : t('Failed'));
    }
  }

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title={t('Collection & notifications')}>
        <ErrorNote error={err} />
        {!s ? (
          <Empty>{t('Loading…')}</Empty>
        ) : (
          <div className="space-y-4 text-sm">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div>{t('Language')}</div>
                <div className="text-xs text-muted">{t('Interface language. Log details and event text stay as Windows writes them.')}</div>
              </div>
              <Select className="w-32" value={getLang()} onChange={(e) => setLang(e.target.value as 'th' | 'en')}>
                <option value="th">ไทย</option>
                <option value="en">English</option>
              </Select>
            </div>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div>{t('Telegram message language')}</div>
                <div className="text-xs text-muted">{t('Alerts, findings, incidents and the daily summary.')}</div>
              </div>
              <Select className="w-32" value={s.language} onChange={(e) => update({ language: e.target.value as 'th' | 'en' })}>
                <option value="th">ไทย</option>
                <option value="en">English</option>
              </Select>
            </div>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div>{t('Collect metrics from this PC')}</div>
                <div className="text-xs text-muted">{t('CPU, memory, disks, network every minute.')}</div>
              </div>
              <Toggle checked={s.localCollectorEnabled} onChange={(v) => update({ localCollectorEnabled: v })} />
            </div>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div>{t('Read Windows security logs')}</div>
                <div className="text-xs text-muted">{s.platform === 'win32' ? t('Logons, account changes, services, Defender. Needs Administrator or "Event Log Readers" membership.') : t('Only available on Windows.')}</div>
              </div>
              <Toggle checked={s.eventlogEnabled} disabled={s.platform !== 'win32'} onChange={(v) => update({ eventlogEnabled: v })} />
            </div>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div>{t('Notify me about security findings of at least')}</div>
                <div className="text-xs text-muted">{t('Lower-severity findings still appear in Security Center.')}</div>
              </div>
              <Select className="w-32" value={s.notifyFindingMinSeverity} onChange={(e) => update({ notifyFindingMinSeverity: e.target.value })}>
                {['low', 'medium', 'high', 'critical'].map((v) => (
                  <option key={v} value={v}>{sevLabel(v)}</option>
                ))}
              </Select>
            </div>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div>{t('Daily summary on Telegram')}</div>
                <div className="text-xs text-muted">{t('Also proves SENTINEL is alive: if it stops arriving, SENTINEL is not running.')}</div>
              </div>
              <div className="flex items-center gap-2">
                <Select className="w-24" value={s.digestHour} onChange={(e) => update({ digestHour: Number(e.target.value) })} disabled={!s.digestEnabled}>
                  {Array.from({ length: 24 }, (_, h) => (
                    <option key={h} value={h}>
                      {String(h).padStart(2, '0')}:00
                    </option>
                  ))}
                </Select>
                <Toggle checked={s.digestEnabled} onChange={(v) => update({ digestEnabled: v })} />
              </div>
            </div>
          </div>
        )}
      </Card>

      <Card title={t('Self-monitoring')} right={health.data && <span className="text-xs text-muted">{t('up {d}', { d: duration(health.data.uptimeSec * 1000) })} · {health.data.memoryMb} MB RAM</span>}>
        <ul className="space-y-2 text-xs">
          {health.data?.components.map((c) => (
            <li key={c.name} className="rounded-lg bg-panel-2 px-3 py-2">
              <div className="flex items-center gap-2 text-sm">
                <span className={`h-2 w-2 rounded-full ${c.ok ? 'bg-ok' : 'bg-bad'}`} />
                {t(c.label)}
                <span className="ml-auto text-xs text-muted">{c.lastRunAt ? ago(c.lastRunAt) : t('not run yet')}</span>
              </div>
              <div className={`mt-1 ${c.ok ? 'text-muted' : 'text-bad'}`}>
                {t(c.message)}
                {c.errorSince && ` (${t('failing for {d}', { d: duration(Date.now() - c.errorSince) })})`}
              </div>
            </li>
          ))}
          {health.data && (
            <li className="text-muted">
              {t('Notification channels')}: {health.data.notifications.channels} · {t('pending')}: {health.data.notifications.pendingDeliveries} · {t('failed (24h)')}: {health.data.notifications.failedDeliveries24h}
            </li>
          )}
        </ul>
      </Card>
    </div>
  );
}

type Drill = { at: number; reason: string; ok: boolean; skipped?: boolean; problems: string[]; name?: string; createdAt?: number; bytes?: number; ms?: number };

/** Monthly restore test of the newest encrypted cloud copy. */
function DrillBox({ drill, testing, onTest, passCheckedAt, onPassCheck }: { drill: Drill | null; testing: boolean; onTest: () => void; passCheckedAt: number | null; onPassCheck: () => void }) {
  const tone = !drill || drill.skipped ? 'bg-panel-2 text-muted' : drill.ok ? 'bg-ok/10 text-ok' : 'bg-bad/10 text-bad';
  return (
    <div className={`mb-3 flex flex-wrap items-center gap-3 rounded-lg px-3 py-2 text-xs ${tone}`}>
      <span className="min-w-0 flex-1">
        {!drill
          ? `🧪 ${t('Restore test: not run yet. It runs by itself once a month.')}`
          : drill.ok
            ? `🧪 ${t('Last restore test passed {when}: {name} decrypts, the database is intact and complete.', { when: stamp(drill.at), name: drill.name ?? '' })}`
            : `🧪 ${t('Last restore test failed {when}', { when: stamp(drill.at) })}: ${drill.problems.map((p) => t(p)).join(' · ')}`}
        <span className="block text-muted">{t('Tests the newest encrypted copy in the cloud folder once a month, with the key SENTINEL keeps. It does not check that you still remember the passphrase.')}</span>
        <span className="block text-muted">
          🔑 {passCheckedAt ? t('Passphrase last confirmed {when}.', { when: stamp(passCheckedAt) }) : t('You have not confirmed the passphrase yet — worth doing every few months.')}
        </span>
      </span>
      <div className="flex flex-wrap gap-2">
        <Button variant="ghost" disabled={testing} onClick={onTest}>
          {testing ? t('Testing…') : t('Test restore')}
        </Button>
        <Button variant="ghost" onClick={onPassCheck}>
          🔑 {t('Test passphrase')}
        </Button>
      </div>
    </div>
  );
}

function Backups() {
  const settings = useApi(() => api.get<Settings>('/settings'), []);
  const list = useApi(() => api.get<{ dir: string; copyDir: string | null; sealed: boolean; sealSetAt: number | null; drill: Drill | null; passCheckedAt: number | null; backups: Backup[] }>('/backups'), []);
  const [testing, setTesting] = useState(false);
  const [passCheck, setPassCheck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [sealForm, setSealForm] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  return (
    <Card
      title={t('Backups')}
      right={
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted">{t('Daily at')}</span>
          <Select
            className="w-24 !py-1 text-xs"
            value={settings.data?.backupHour ?? 3}
            onChange={async (e) => settings.setData(await api.put<Settings>('/settings', { backupHour: Number(e.target.value) }))}
          >
            {Array.from({ length: 24 }, (_, h) => (
              <option key={h} value={h}>
                {String(h).padStart(2, '0')}:00
              </option>
            ))}
          </Select>
          <Button
            variant="primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setMsg(null);
              try {
                const r = await api.post<{ name: string; bytes: number }>('/backups');
                setMsg({ ok: true, text: t('Backup {name} created ({size}).', { name: r.name, size: bytes(r.bytes) }) });
                list.reload();
              } catch (e) {
                setMsg({ ok: false, text: e instanceof Error ? t(e.message) : t('Failed') });
              }
              setBusy(false);
            }}
          >
            {busy ? t('Backing up…') : t('Back up now')}
          </Button>
        </div>
      }
    >
      {msg && <div className={`mb-3 rounded-lg px-3 py-2 text-sm ${msg.ok ? 'bg-ok/10 text-ok' : 'bg-bad/10 text-bad'}`}>{msg.text}</div>}
      <p className="mb-3 text-xs text-muted">
        {t('Stored in')} <code className="text-slate-300">{list.data?.dir}</code> {t('(newest 7 kept). Each backup contains the database and master.key (needed to decrypt the Telegram token). Copy them to another disk or cloud drive for real protection. Restore: stop SENTINEL, then run')}{' '}
        <code className="text-slate-300">npm run restore -- &lt;backup folder&gt;</code>
      </p>
      {list.data && (
        <p className={`mb-3 rounded-lg px-3 py-2 text-xs ${list.data.copyDir ? 'bg-ok/10 text-ok' : 'bg-warn/10 text-warn'}`}>
          {list.data.copyDir ? (
            <>
              {t('Copied to')} <code>{list.data.copyDir}</code>
            </>
          ) : (
            t('No off-disk copy configured — set BACKUP_COPY_DIR in .env (e.g. a OneDrive folder).')
          )}
        </p>
      )}
      {list.data?.copyDir && (
        <div className={`mb-3 flex flex-wrap items-center gap-3 rounded-lg px-3 py-2 text-xs ${list.data.sealed ? 'bg-ok/10 text-ok' : 'bg-warn/10 text-warn'}`}>
          <span className="min-w-0 flex-1">
            {list.data.sealed
              ? `🔒 ${t('Cloud copies are encrypted with your backup passphrase (set {when}). Restore one with', { when: list.data.sealSetAt ? stamp(list.data.sealSetAt) : '—' })} `
              : `⚠️ ${t('Cloud copies are NOT encrypted: anyone who gets into that cloud account can read master.key and every stored secret.')}`}
            {list.data.sealed && <code className="text-slate-300">npm run restore -- &lt;file.sbk&gt;</code>}
          </span>
          <Button variant={list.data.sealed ? 'ghost' : 'primary'} onClick={() => setSealForm(true)}>
            {list.data.sealed ? t('Change passphrase') : `🔒 ${t('Encrypt')}`}
          </Button>
        </div>
      )}
      {list.data?.copyDir && list.data.sealed && (
        <DrillBox
          drill={list.data.drill}
          passCheckedAt={list.data.passCheckedAt}
          onPassCheck={() => setPassCheck(true)}
          testing={testing}
          onTest={async () => {
            setTesting(true);
            setMsg(null);
            try {
              const r = await api.post<Drill>('/backups/restore-test');
              setMsg(r.ok ? { ok: true, text: t('Restore test passed: {name} opens and is complete.', { name: r.name ?? '' }) } : { ok: false, text: `${t('Restore test failed')}: ${r.problems.map((p) => t(p)).join(' · ')}` });
              list.reload();
            } catch (e) {
              setMsg({ ok: false, text: e instanceof Error ? t(e.message) : t('Failed') });
            }
            setTesting(false);
          }}
        />
      )}
      {passCheck && (
        <PassCheckForm
          onClose={() => setPassCheck(false)}
          onResult={(ok, text) => {
            setMsg({ ok, text });
            list.reload();
          }}
        />
      )}
      {sealForm && (
        <SealForm
          change={!!list.data?.sealed}
          onClose={() => setSealForm(false)}
          onDone={() => {
            setSealForm(false);
            setMsg({ ok: true, text: t('Cloud copies are now encrypted.') });
            list.reload();
          }}
        />
      )}
      {!list.data?.backups.length ? (
        <Empty>{t('No backups yet.')}</Empty>
      ) : (
        <table className="w-full text-sm">
          <thead className="border-b border-line">
            <tr>
              <Th>{t('Backup')}</Th>
              <Th>{t('Created')}</Th>
              <Th>{t('Size')}</Th>
              <Th>{t('Contents')}</Th>
              <Th />
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {list.data.backups.map((b) => (
              <tr key={b.name}>
                <Td className="text-xs">{b.name}</Td>
                <Td className="text-xs text-muted">
                  {stamp(b.createdAt)} · {t(b.reason)}
                </Td>
                <Td className="text-xs">{bytes(b.bytes)}</Td>
                <Td className="text-xs text-muted">
                  {t('{a} assets · {i} incidents · {e} audit entries', { a: b.counts.assets ?? 0, i: b.counts.incidents ?? 0, e: b.counts.audit_logs ?? 0 })} {b.hasKey ? `· ${t('key')} ✓` : `· ${t('key missing!')}`}
                  {b.copied != null && <span className={b.copied ? 'text-ok' : 'text-warn'}> · {b.copied ? `☁ ${t('Copied off-disk')} ✓` : t('Not copied yet')}</span>}
                </Td>
                <Td className="text-right">
                  <Button
                    variant="ghost"
                    onClick={async () => {
                      const r = await api.post<{ ok: boolean; integrity?: string; reason?: string }>(`/backups/${b.name}/verify`);
                      setMsg({ ok: r.ok, text: r.ok ? `${b.name}: ${t('integrity OK.')}` : `${b.name}: ${r.integrity ?? r.reason}` });
                    }}
                  >
                    {t('Verify')}
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function AuditLog() {
  const { data, reload } = useApi(() => api.get<{ entries: AuditEntry[] }>('/audit?limit=200'), []);
  const [verify, setVerify] = useState<{ ok: boolean; checked: number; brokenAt?: number; reason?: string } | null>(null);
  return (
    <Card
      title={t('Audit log')}
      pad={false}
      right={
        <div className="flex gap-2">
          <Button onClick={reload}>{t('Refresh')}</Button>
          <Button variant="primary" onClick={async () => setVerify(await api.get('/audit/verify'))}>
            {t('Verify integrity')}
          </Button>
        </div>
      }
    >
      {verify && (
        <div className={`mx-4 mb-3 rounded-lg px-3 py-2 text-sm ${verify.ok ? 'bg-ok/10 text-ok' : 'bg-bad/10 text-bad'}`}>
          {verify.ok ? `✓ ${t('Hash chain intact — {n} entries verified. No entry was modified or deleted.', { n: verify.checked })}` : `✗ ${t('Chain broken at #{n}', { n: verify.brokenAt })}: ${verify.reason}`}
        </div>
      )}
      {!data?.entries.length ? (
        <Empty>{t('No entries.')}</Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-line">
              <tr>
                <Th>#</Th>
                <Th>{t('Time')}</Th>
                <Th>{t('Action')}</Th>
                <Th>{t('Resource')}</Th>
                <Th>{t('Detail')}</Th>
                <Th>IP</Th>
                <Th>Hash</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {data.entries.map((e) => (
                <tr key={e.seq}>
                  <Td className="text-xs text-muted">{e.seq}</Td>
                  <Td className="whitespace-nowrap text-xs text-muted">{stamp(e.ts)}</Td>
                  <Td className={`text-xs ${/failed|locked/.test(e.action) ? 'text-bad' : ''}`}>{e.action}</Td>
                  <Td className="text-xs text-muted">{e.resourceType ? `${e.resourceType} ${e.resourceId ?? ''}` : '—'}</Td>
                  <Td className="max-w-md truncate text-xs text-muted">{e.detail ? JSON.stringify(e.detail) : ''}</Td>
                  <Td className="text-xs text-muted">{e.ip ?? ''}</Td>
                  <Td className="font-mono text-[11px] text-muted">{e.hash}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export default function SettingsPage({ onLogout }: { onLogout: () => void }) {
  const [tab, setTab] = useState<'account' | 'monitoring' | 'backups' | 'audit'>('account');
  return (
    <>
      <PageHeader title={t('Settings')} subtitle={t('Account security, collection, self-monitoring, backups and the audit trail')} />
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'account', label: t('Account & MFA') },
          { value: 'monitoring', label: t('Monitoring') },
          { value: 'backups', label: t('Backups') },
          { value: 'audit', label: t('Audit log') },
        ]}
      />
      {tab === 'account' && <Account onLogout={onLogout} />}
      {tab === 'monitoring' && <Monitoring />}
      {tab === 'backups' && <Backups />}
      {tab === 'audit' && <AuditLog />}
    </>
  );
}
