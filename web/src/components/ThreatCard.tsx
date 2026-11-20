import { useState } from 'react';
import { api } from '../lib/api';
import { ago } from '../lib/format';
import { useApi } from '../lib/hooks';
import { t } from '../lib/i18n';
import { Card, ErrorNote } from './ui';

type Threat = {
  name: string;
  severity: string;
  category: string;
  paths: string[];
  firstAt: number;
  lastAt: number;
  action: string;
  status: 'handled' | 'allowed' | 'failed' | 'pending';
  detections: number;
  attention: boolean;
};

const SEV_TONE: Record<string, string> = { Severe: 'bg-bad/15 text-bad', High: 'bg-bad/10 text-bad', Medium: 'bg-warn/15 text-warn', Moderate: 'bg-warn/15 text-warn', Low: 'bg-panel-2 text-muted' };

/** Defender's own English word (severity, category, action) in Thai when we have it, else as Defender wrote it. */
function word(kind: 'sev' | 'cat' | 'action', v: string) {
  const k = `defender.${kind}.${v}`;
  const s = t(k);
  return s === k ? v : s;
}

function statusText(x: Threat) {
  if (x.status === 'handled') return { icon: '✅', tone: 'text-ok', text: t('Handled: {action}', { action: word('action', x.action) }) };
  if (x.status === 'failed') return { icon: '🔴', tone: 'text-bad', text: t('Defender could not remove it') };
  if (x.status === 'allowed') return { icon: '⚠️', tone: 'text-warn', text: t('Allowed — still on this PC') };
  return x.attention ? { icon: '⚠️', tone: 'text-warn', text: t('No action reported yet') } : { icon: '⏳', tone: 'text-muted', text: t('Defender is dealing with it') };
}

function Row({ x }: { x: Threat }) {
  const [open, setOpen] = useState(false);
  const st = statusText(x);
  return (
    <li className="py-2.5">
      <button type="button" onClick={() => setOpen((o) => !o)} className="flex w-full items-start gap-3 text-left">
        <span className="mt-0.5">{st.icon}</span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="break-all font-medium text-white">{x.name}</span>
            {x.severity && <span className={`rounded-full px-2 py-0.5 text-[11px] ${SEV_TONE[x.severity] ?? 'bg-panel-2 text-muted'}`}>{word('sev', x.severity)}</span>}
          </span>
          <span className={`block text-xs ${st.tone}`}>
            {st.text}
            {x.category && <span className="text-muted"> · {word('cat', x.category)}</span>}
          </span>
        </span>
        <span className="whitespace-nowrap text-xs text-muted">{ago(x.lastAt)}</span>
      </button>
      {open && (
        <div className="mt-2 space-y-1 rounded-lg bg-panel-2 px-3 py-2 text-xs text-muted">
          {x.paths.map((p) => (
            <div key={p} className="break-all font-mono text-[11px] text-white/80">
              {p}
            </div>
          ))}
          <div>
            {t('First found {when}', { when: ago(x.firstAt) })}
            {x.detections > 1 && ` · ${t('found {n} times', { n: x.detections })}`}
          </div>
          {x.status !== 'handled' && <div className="text-warn">{t('Open Windows Security → Virus & threat protection → Protection history on the PC, then remove it or run an Offline scan.')}</div>}
        </div>
      )}
    </li>
  );
}

/** What Microsoft Defender found on this PC in the last 90 days, and whether it dealt with each one. */
export function ThreatCard() {
  const { data, error } = useApi(() => api.get<{ threats: Threat[]; days: number }>('/device-health/scan/threats'), [], ['device', 'logs'], 60_000);
  const list = data?.threats ?? [];
  const attention = list.filter((x) => x.attention).length;
  return (
    <Card
      title={`🛡️ ${t('Threat history')}`}
      right={data && <span className="text-xs text-muted">{t('Last {n} days', { n: data.days })}</span>}
    >
      <ErrorNote error={error} />
      {!data ? (
        <div className="skeleton h-16 rounded-xl" />
      ) : !list.length ? (
        <p className="rounded-xl bg-ok/10 px-4 py-3 text-sm text-ok">✓ {t('Defender has found nothing in this time')}</p>
      ) : (
        <>
          <p className={`mb-1 rounded-xl px-4 py-3 text-sm ${attention ? 'bg-warn/10 text-warn' : 'bg-ok/10 text-ok'}`}>
            {attention ? t('{n} item(s) need a look', { n: attention }) : t('Found {n} — Defender dealt with all of them', { n: list.length })}
          </p>
          <ul className="divide-y divide-line">
            {list.map((x) => (
              <Row key={`${x.name}|${x.paths.join('|')}`} x={x} />
            ))}
          </ul>
          <p className="mt-2 text-xs text-muted">{t('Tap an item to see where it was. Quarantined files cannot run; Defender deletes them after a while.')}</p>
        </>
      )}
    </Card>
  );
}
