import { useState } from 'react';
import { api } from '../lib/api';
import { ago } from '../lib/format';
import { useApi, useTick } from '../lib/hooks';
import { t } from '../lib/i18n';
import { Button, Card, ErrorNote, FormModal, Select } from './ui';

type Run = { scanId: string; param: string; trigger: string; startedAt: number | null; endedAt: number | null; outcome: 'running' | 'done' | 'stopped' | 'failed'; durationSec: number | null; stopReason: string; threats?: number };
type Auto = { enabled: boolean; day: number; hour: number; lastAt: number | null; nextAt: number };
type Status = { running: Run | null; starting: { type: string; at: number } | null; lastQuick: Run | null; lastFull: Run | null; history: Run[]; dryRun: boolean; auto?: Auto };

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const hh = (h: number) => `${String(h).padStart(2, '0')}:00`;

function AutoScanForm({ auto, onClose }: { auto: Auto; onClose: () => void }) {
  const [enabled, setEnabled] = useState(auto.enabled);
  const [day, setDay] = useState(auto.day);
  const [hour, setHour] = useState(auto.hour);
  return (
    <FormModal title={t('Weekly automatic scan')} submitLabel={`✓ ${t('Save')}`} onClose={onClose} onSubmit={() => api.post('/device-health/scan/auto', { enabled, day, hour })}>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        {t('Run a quick scan every week')}
      </label>
      <div className="grid grid-cols-2 gap-2">
        <Select value={day} disabled={!enabled} onChange={(e) => setDay(Number(e.target.value))}>
          {DAYS.map((d, i) => (
            <option key={d} value={i}>
              {t(d)}
            </option>
          ))}
        </Select>
        <Select value={hour} disabled={!enabled} onChange={(e) => setHour(Number(e.target.value))}>
          {Array.from({ length: 24 }, (_, h) => (
            <option key={h} value={h}>
              {hh(h)}
            </option>
          ))}
        </Select>
      </div>
      <p className="text-xs text-muted">{t('Skipped when a scan already finished in the last 24 hours. Waits while a game is running. If the PC is off at that time, it runs within 3 days. A clean result is not sent on Telegram; it is in the Monday summary. Threats are always sent.')}</p>
    </FormModal>
  );
}
type ScanType = 'quick' | 'full' | 'offline';

const SCANS: { id: ScanType; icon: string; label: string; desc: string; danger?: boolean }[] = [
  { id: 'quick', icon: '⚡', label: 'Quick scan', desc: 'Places malware usually hides. About 2–5 minutes.' },
  { id: 'full', icon: '🔍', label: 'Full scan', desc: 'Every file on every drive. 1–4 hours; the PC is slower meanwhile. Keep it plugged in and awake.' },
  { id: 'offline', icon: '🛡️', label: 'Offline scan', desc: 'Restarts the PC and scans before Windows starts, catching malware that hides while Windows runs. About 15 minutes.', danger: true },
];

const PARAM_LABEL: Record<string, string> = { 'Quick Scan': 'Quick scan', 'Full Scan': 'Full scan', 'Custom Scan': 'Custom scan', 'Offline Scan': 'Offline scan' };
const label = (param: string) => t(PARAM_LABEL[param] ?? param);

const dur = (sec: number | null) => {
  if (sec == null) return '';
  const h = Math.floor(sec / 3600);
  const m = Math.round((sec % 3600) / 60);
  return h ? t('{h} h {m} min', { h, m }) : t('{m} min', { m: Math.max(1, m) });
};

function ScanConfirm({ scan, onClose }: { scan: (typeof SCANS)[number]; onClose: () => void }) {
  return (
    <FormModal
      title={t('Start: {scan}', { scan: t(scan.label) })}
      submitLabel={`✓ ${scan.danger ? t('Restart and scan') : t('Start scan')}`}
      danger={scan.danger}
      onClose={onClose}
      onSubmit={() => api.post('/device-health/scan', { type: scan.id })}
    >
      <p className="text-sm text-muted">{t(scan.desc)}</p>
      {scan.id === 'offline' && (
        <p className="rounded-lg bg-warn/10 px-3 py-2 text-xs text-warn">
          {t('Save your work first. SENTINEL and RustDesk are off until Windows is back and you sign in on the PC.')}
        </p>
      )}
      <p className="text-xs text-muted">{t('You get the result on Telegram when the scan ends.')}</p>
    </FormModal>
  );
}

/** Defender scans: start one from the phone, see what is running and how recent scans went. */
export function ScanCard({ quickScanAgeDays, fullScanAgeDays }: { quickScanAgeDays?: number | null; fullScanAgeDays?: number | null }) {
  useTick(5000);
  const { data, error, reload } = useApi(() => api.get<Status>('/device-health/scan'), [], ['device', 'logs'], 15_000);
  const [open, setOpen] = useState<(typeof SCANS)[number] | null>(null);
  const [autoOpen, setAutoOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const busy = data?.running ?? null;
  const starting = data?.starting ?? null;

  async function cancel() {
    setErr(null);
    try {
      await api.post('/device-health/scan/cancel');
      reload();
    } catch (e) {
      setErr(e instanceof Error ? t(e.message) : String(e));
    }
  }

  return (
    <Card title={`🦠 ${t('Virus scan (Microsoft Defender)')}`}>
      <ErrorNote error={error ?? err} />
      {data?.dryRun && <p className="mb-2 text-xs text-warn">{t('Test mode — commands are logged, not run')}</p>}

      {busy || starting ? (
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-xl bg-accent/10 px-4 py-3">
          <span className="size-2.5 animate-pulse rounded-full bg-accent" />
          <span className="min-w-0 flex-1 text-sm">
            <span className="font-medium text-white">{busy ? t('{scan} is running', { scan: label(busy.param) }) : t('Starting {scan}…', { scan: t(SCANS.find((s) => s.id === starting!.type)?.label ?? '') })}</span>
            <span className="block text-xs text-muted">
              {busy?.startedAt ? t('Started {when}', { when: ago(busy.startedAt) }) : t('Waiting for Defender to report the start')}
              {busy?.trigger ? ` · ${busy.trigger}` : ''}
            </span>
          </span>
          {busy && (
            <Button variant="danger" onClick={() => void cancel()}>
              ✋ {t('Stop scan')}
            </Button>
          )}
        </div>
      ) : (
        <div className="mb-3 grid gap-2 sm:grid-cols-3">
          {SCANS.map((s) => (
            <button
              key={s.id}
              type="button"
              disabled={!data}
              onClick={() => setOpen(s)}
              className={`flex items-center gap-3 rounded-xl border border-line bg-panel-2 px-3 py-3 text-left transition hover:border-accent/70 disabled:opacity-50 ${s.danger ? 'hover:border-warn/70' : ''}`}
            >
              <span className="text-xl">{s.icon}</span>
              <span className="text-sm font-medium">{t(s.label)}</span>
            </button>
          ))}
        </div>
      )}

      <dl className="grid grid-cols-2 gap-2 text-xs">
        <div className="rounded-lg bg-panel-2 px-3 py-2">
          <dt className="text-muted">{t('Last quick scan')}</dt>
          <dd className="mt-0.5 text-sm">{data?.lastQuick?.endedAt ? ago(data.lastQuick.endedAt) : quickScanAgeDays != null ? t('{n} day(s) ago', { n: quickScanAgeDays }) : '—'}</dd>
        </div>
        <div className="rounded-lg bg-panel-2 px-3 py-2">
          <dt className="text-muted">{t('Last full scan')}</dt>
          <dd className={`mt-0.5 text-sm ${!data?.lastFull && (fullScanAgeDays ?? 0) > 30 ? 'text-warn' : ''}`}>
            {data?.lastFull?.endedAt ? ago(data.lastFull.endedAt) : fullScanAgeDays != null ? t('{n} day(s) ago', { n: fullScanAgeDays }) : '—'}
          </dd>
        </div>
      </dl>

      {data?.auto && (
        <button type="button" onClick={() => setAutoOpen(true)} className="mt-2 flex w-full items-center gap-2 rounded-lg border border-line px-3 py-2 text-left text-xs hover:border-accent/70">
          <span>🗓️</span>
          <span className="min-w-0 flex-1">
            {data.auto.enabled ? t('Automatic quick scan every {day} at {time}', { day: t(DAYS[data.auto.day]), time: hh(data.auto.hour) }) : t('Weekly automatic scan is off')}
            {data.auto.enabled && data.auto.lastAt && <span className="block text-muted">{t('Last handled {when}', { when: ago(data.auto.lastAt) })}</span>}
          </span>
          <span className="text-muted">{t('Change')}</span>
        </button>
      )}

      {!!data?.history.length && (
        <ul className="mt-3 divide-y divide-line text-sm">
          {data.history.map((r) => (
            <li key={r.scanId} className="flex items-center gap-2 py-2">
              <span>{r.threats ? '🔴' : r.outcome === 'done' ? '✅' : '⚠️'}</span>
              <span className="min-w-0 flex-1">
                {label(r.param)}
                <span className="block text-xs text-muted">
                  {r.threats ? t('{n} threat(s) found', { n: r.threats }) : r.outcome === 'done' ? t('No threats found') : r.outcome === 'failed' ? t('Failed') : t('Stopped')}
                  {r.durationSec != null && ` · ${dur(r.durationSec)}`}
                </span>
              </span>
              <span className="whitespace-nowrap text-xs text-muted">{r.endedAt ? ago(r.endedAt) : ''}</span>
            </li>
          ))}
        </ul>
      )}

      {autoOpen && data?.auto && (
        <AutoScanForm
          auto={data.auto}
          onClose={() => {
            setAutoOpen(false);
            reload();
          }}
        />
      )}
      {open && (
        <ScanConfirm
          scan={open}
          onClose={() => {
            setOpen(null);
            reload();
          }}
        />
      )}
    </Card>
  );
}
