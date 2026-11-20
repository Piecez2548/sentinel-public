import { useMemo, useState } from 'react';
import { Chart, C, baseAxis } from '../components/Chart';
import { Button, Card, Empty, ErrorNote, PageHeader, Segmented, StatusDot, Td, Th } from '../components/ui';
import { api, type Asset } from '../lib/api';
import { ago, clock, duration, fullDate, host, pct, statusLabel } from '../lib/format';
import { t } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';
import { WebsiteForm } from './Assets';

type Point = { t: number; latency: number | null; ok: boolean };
type Recent = { ts: number; ok: boolean; statusCode: number | null; latencyMs: number | null; error: string | null };

const HEADER_LABELS: Record<string, string> = {
  'strict-transport-security': 'HSTS',
  'content-security-policy': 'Content-Security-Policy',
  'x-frame-options': 'X-Frame-Options',
  'x-content-type-options': 'X-Content-Type-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
};

function StatusStrip({ points, hours }: { points: Point[]; hours: number }) {
  const SLOTS = 60;
  const end = Date.now();
  const start = end - hours * 3600_000;
  const slotMs = (end - start) / SLOTS;
  const slots = new Array<'none' | 'ok' | 'bad'>(SLOTS).fill('none');
  for (const p of points) {
    const i = Math.floor((p.t - start) / slotMs);
    if (i < 0 || i >= SLOTS) continue;
    if (!p.ok) slots[i] = 'bad';
    else if (slots[i] === 'none') slots[i] = 'ok';
  }
  const color = { none: 'bg-line/60', ok: 'bg-ok/80', bad: 'bg-bad' } as const;
  return (
    <div>
      <div className="flex h-7 gap-[2px]">
        {slots.map((s, i) => (
          <div key={i} className={`flex-1 rounded-[2px] ${color[s]}`} title={`${fullDate(start + i * slotMs)} — ${s === 'none' ? t('no data') : s === 'ok' ? t('all checks OK') : t('a check failed')}`} />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[11px] text-muted">
        <span>{hours < 24 ? t('{n}h ago', { n: hours }) : t('{n}d ago', { n: hours / 24 })}</span>
        <span>{t('now')}</span>
      </div>
    </div>
  );
}

function SiteDetail({ site, onEdit }: { site: Asset; onEdit: () => void }) {
  const [hours, setHours] = useState(24);
  const w = site.website!;
  const { data: series } = useApi(() => api.get<{ points: Point[] }>(`/assets/${site.id}/checks?hours=${hours}`), [site.id, hours, w.lastCheckedAt], ['checks']);
  const { data: recent } = useApi(() => api.get<{ checks: Recent[] }>(`/assets/${site.id}/recent?limit=15`), [site.id, w.lastCheckedAt], ['checks']);
  const [busy, setBusy] = useState(false);
  const pts = series?.points ?? [];
  const sslDays = w.tlsExpiresAt ? Math.floor((w.tlsExpiresAt - Date.now()) / 86_400_000) : null;

  const option = useMemo(() => {
    const now = Date.now();
    const first = pts.length ? Math.max(now - hours * 3600_000, pts[0].t - 60_000) : now - hours * 3600_000;
    return {
      grid: { left: 52, right: 12, top: 14, bottom: 26 },
      tooltip: { ...C.tooltip, trigger: 'axis' },
      xAxis: { type: 'time', min: first, max: now, ...baseAxis, splitLine: { show: false } },
      yAxis: { type: 'value', min: 0, ...baseAxis, axisLabel: { color: C.text, formatter: '{value} ms' } },
      series: [
        { name: t('Latency'), type: 'line', smooth: 0.3, showSymbol: pts.length <= 40, symbolSize: 6, data: pts.filter((p) => p.latency != null).map((p) => [p.t, p.latency]), lineStyle: { color: C.accent, width: 2 }, itemStyle: { color: C.accent }, areaStyle: { color: 'rgba(139,92,246,.18)' } },
        { name: t('Failed'), type: 'scatter', symbolSize: 10, itemStyle: { color: C.bad }, data: pts.filter((p) => !p.ok).map((p) => [p.t, 0]) },
      ],
    };
  }, [pts, hours]);

  const missingHeaders = w.headers ? Object.keys(HEADER_LABELS).filter((k) => !w.headers![k] && !(k === 'strict-transport-security' && !site.target?.startsWith('https'))) : [];

  return (
    <div className="space-y-4">
      <Card
        title={
          <span className="flex items-center gap-2">
            {site.name}
            <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${site.status === 'up' ? 'bg-ok/15 text-ok' : site.status === 'down' ? 'bg-bad/15 text-bad' : 'bg-line text-muted'}`}>
              {statusLabel(site.status)}
              {site.statusSince && (site.status === 'up' || site.status === 'down') ? ` · ${duration(Date.now() - site.statusSince)}` : ''}
            </span>
          </span>
        }
        right={<Segmented value={hours} onChange={setHours} options={[{ value: 24, label: t('24h') }, { value: 72, label: t('3d') }, { value: 168, label: t('7d') }, { value: 336, label: t('14d') }]} />}
      >
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <a href={site.target ?? '#'} target="_blank" rel="noreferrer noopener" className="break-all text-accent-2 hover:underline">
            {site.target}
          </a>
          <span className="text-muted">· {w.intervalSec < 60 ? t('every {n} sec', { n: w.intervalSec }) : t('every {n} min', { n: w.intervalSec / 60 })}</span>
          {w.keyword && <span className="text-muted">· {t('must contain “{k}”', { k: w.keyword })}</span>}
          {w.expectedStatus && <span className="text-muted">· {t('expects HTTP {s}', { s: w.expectedStatus })}</span>}
          <span className="text-muted">· {t('last check {ago}', { ago: ago(w.lastCheckedAt) })}</span>
        </div>
        {site.status === 'down' && w.lastError && <div className="mt-3 rounded-lg border border-bad/30 bg-bad/10 px-3 py-2 text-xs text-bad">{t('Last error')}: {w.lastError}</div>}

        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
          {[
            [t('Uptime 24h'), pct(w.uptime24h), w.uptime24h != null && w.uptime24h < site.sloTarget],
            [t('Uptime 30d'), pct(w.uptime30d), false],
            [t('SLO target'), `${site.sloTarget}%`, false],
            [t('Avg latency 24h'), w.avgLatency24h != null ? `${w.avgLatency24h} ms` : '—', false],
            [t('TLS expires'), site.target?.startsWith('https') ? (sslDays == null ? t('checking…') : t('{n} days', { n: sslDays })) : t('no HTTPS'), sslDays != null && sslDays <= 14],
          ].map(([label, value, bad]) => (
            <div key={String(label)} className="rounded-lg bg-panel-2 px-3 py-2">
              <div className="text-xs text-muted">{label}</div>
              <div className={`text-base font-semibold ${bad ? 'text-bad' : ''}`}>{value}</div>
            </div>
          ))}
        </div>

        <div className="mt-4">{pts.length ? <Chart option={option} height={220} /> : <Empty>{t('Waiting for the first check…')}</Empty>}</div>
        <div className="mt-2">
          <StatusStrip points={pts} hours={hours} />
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <Button
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              await api.post(`/assets/${site.id}/check`).catch(() => {});
              setBusy(false);
            }}
          >
            {busy ? t('Checking…') : t('Check now')}
          </Button>
          <Button onClick={onEdit}>{t('Edit')}</Button>
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card title={t('Recent checks')} pad={false}>
          {!recent?.checks.length ? (
            <Empty>{t('No checks yet.')}</Empty>
          ) : (
            <div className="overflow-x-auto pb-2">
              <table className="w-full text-xs">
                <thead>
                  <tr>
                    <Th>{t('Time')}</Th>
                    <Th>{t('Result')}</Th>
                    <Th>HTTP</Th>
                    <Th>{t('Latency')}</Th>
                    <Th>{t('Detail')}</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {recent.checks.map((c) => (
                    <tr key={c.ts}>
                      <Td className="whitespace-nowrap text-muted">{clock(c.ts)}</Td>
                      <Td>
                        <span className={`rounded px-1.5 py-0.5 ${c.ok ? 'bg-ok/15 text-ok' : 'bg-bad/15 text-bad'}`}>{c.ok ? t('OK') : t('Failed')}</span>
                      </Td>
                      <Td>{c.statusCode ?? '—'}</Td>
                      <Td>{c.latencyMs != null ? `${c.latencyMs} ms` : '—'}</Td>
                      <Td className="text-muted">{c.error ?? ''}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title={t('Security headers')}>
          {!w.headers ? (
            <Empty>{t('Not checked yet.')}</Empty>
          ) : (
            <ul className="space-y-1.5 text-xs">
              {Object.entries(HEADER_LABELS).map(([k, label]) => {
                const v = w.headers![k];
                const na = k === 'strict-transport-security' && !site.target?.startsWith('https');
                return (
                  <li key={k} className="flex items-start gap-2">
                    <span className={v ? 'text-ok' : na ? 'text-muted' : 'text-warn'}>{v ? '✓' : na ? '–' : '✗'}</span>
                    <span className="min-w-0">
                      <span className="text-slate-200">{label}</span>
                      {v && <span className="block truncate text-muted" title={v}>{v}</span>}
                    </span>
                  </li>
                );
              })}
              {w.headers['x-powered-by'] && (
                <li className="flex gap-2 text-warn">
                  ✗ <span>{t('Leaks')} X-Powered-By: {w.headers['x-powered-by']}</span>
                </li>
              )}
              {w.headers.server && <li className="text-muted">Server: {w.headers.server}</li>}
              {missingHeaders.length > 0 && (
                <li className="pt-2">
                  <a href="#/security" className="text-accent-2 hover:underline">
                    {t('See the finding in Security Center →')}
                  </a>
                </li>
              )}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

export default function ApplicationsPage({ selectedId, go }: { selectedId: number | null; go: (p: string) => void }) {
  useTick();
  const { data, error, reload } = useApi(() => api.get<{ assets: Asset[] }>('/assets?type=website'), [], ['assets', 'checks']);
  const [modal, setModal] = useState<{ site: Asset | null } | null>(null);
  const sites = useMemo(() => {
    const rank: Record<string, number> = { down: 0, unknown: 1, up: 2, paused: 3 };
    return [...(data?.assets ?? [])].sort((a, b) => rank[a.status] - rank[b.status] || a.name.localeCompare(b.name));
  }, [data]);
  const current = sites.find((s) => s.id === selectedId) ?? sites[0];

  return (
    <>
      <PageHeader title={t('Applications')} subtitle={t('Website & API health: uptime, latency, TLS and security headers')} actions={<Button variant="primary" onClick={() => setModal({ site: null })}>{t('+ Add website')}</Button>} />
      <ErrorNote error={error} />
      {data && !sites.length ? (
        <Card>
          <Empty>
            {t('No websites yet.')} <button className="text-accent-2 hover:underline" onClick={() => setModal({ site: null })}>{t('Add your first one')}</button>
          </Empty>
        </Card>
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
          <Card title={t('Websites ({n})', { n: sites.length })}>
            <ul className="space-y-1">
              {sites.map((s) => (
                <li key={s.id}>
                  <button
                    onClick={() => go(`applications/${s.id}`)}
                    className={`flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition hover:bg-panel-2 ${current?.id === s.id ? 'border-accent/60 bg-panel-2' : 'border-transparent'}`}
                  >
                    <StatusDot status={s.status} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{s.name}</span>
                      <span className="block truncate text-xs text-muted">{host(s.target)}</span>
                    </span>
                    <span className="shrink-0 text-right text-xs">
                      <span className={`block ${s.status === 'down' ? 'text-bad' : ''}`}>{s.status === 'down' ? statusLabel('down') : s.website?.lastLatencyMs != null ? `${s.website.lastLatencyMs} ms` : statusLabel(s.status)}</span>
                      <span className="block text-muted">{pct(s.website?.uptime24h)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          {current && <SiteDetail key={current.id} site={current} onEdit={() => setModal({ site: current })} />}
        </div>
      )}
      {modal && <WebsiteForm site={modal.site} onClose={() => setModal(null)} onSaved={reload} />}
    </>
  );
}
