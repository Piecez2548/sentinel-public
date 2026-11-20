import { useMemo } from 'react';
import { Chart, C, baseAxis } from '../components/Chart';
import { Icon } from '../components/icons';
import { Button, Card, Empty, ErrorNote, Kpi, PageHeader, SevBadge, StateBadge, StatusBanner, StatusDot } from '../components/ui';
import { api, findingText, type AlertEvent, type Asset, type ComponentHealth, type PlainText } from '../lib/api';
import { ago, pct, SEV_COLOR, sevLabel, statusLabel } from '../lib/format';
import { getLang, t } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';

type Overview = {
  assets: { total: number; hosts: number; websites: number; up: number; down: number; unknown: number; paused: number };
  websites24h: { uptime: number | null; avgLatency: number | null };
  alerts: { active: AlertEvent[]; bySeverity: Record<string, number> };
  findings: { openBySeverity: Record<string, number>; recent: { id: number; title: string; plainTh?: PlainText | null; severity: string; lastSeen: number; assetName: string | null; status: string }[] };
  incidents: { open: number; recent: { id: number; title: string; severity: string; status: string; openedAt: number }[] };
  security24h: { byCategory: { category: string; count: number }[]; hourly: { t: number; category: string; count: number }[]; failedLogons: number };
  health: ComponentHealth[];
};

const CAT_COLOR: Record<string, string> = {
  logon_failure: C.bad, logon: C.ok, credentials: C.accent2, account: C.orange, group: C.orange, log_tamper: '#f43f5e',
  service: C.warn, system: '#64748b', malware: '#dc2626', defense: '#fb7185', other: '#475569',
};

export default function OverviewPage({ go }: { go: (p: string) => void }) {
  useTick();
  const { data: o, error } = useApi(() => api.get<Overview>('/overview'), [], ['assets', 'alerts', 'findings', 'incidents', 'logs', 'checks', 'health', 'metrics']);
  const { data: assets } = useApi(() => api.get<{ assets: Asset[] }>('/assets'), [], ['assets', 'metrics', 'checks']);

  const eventsOption = useMemo(() => {
    if (!o) return {};
    const cats = [...new Set(o.security24h.hourly.map((h) => h.category))];
    const hours: number[] = [];
    const start = Math.floor((Date.now() - 23 * 3600_000) / 3600_000) * 3600_000;
    for (let i = 0; i < 24; i++) hours.push(start + i * 3600_000);
    return {
      grid: { left: 36, right: 10, top: 30, bottom: 24 },
      legend: { top: 0, textStyle: { color: C.text, fontSize: 11 }, itemWidth: 10, itemHeight: 10 },
      tooltip: { ...C.tooltip, trigger: 'axis' },
      xAxis: { type: 'category', data: hours.map((h) => new Date(h).getHours().toString().padStart(2, '0') + ':00'), ...baseAxis, splitLine: { show: false } },
      yAxis: { type: 'value', minInterval: 1, ...baseAxis },
      series: cats.map((c) => ({
        name: t(`cat.${c}`) === `cat.${c}` ? c.replace('_', ' ') : t(`cat.${c}`),
        type: 'bar',
        stack: 'ev',
        barMaxWidth: 14,
        itemStyle: { color: CAT_COLOR[c] ?? C.accent, borderRadius: 2 },
        data: hours.map((h) => o.security24h.hourly.find((x) => x.t === h && x.category === c)?.count ?? 0),
      })),
    };
  }, [o]);

  const findingsDonut = useMemo(() => {
    if (!o) return {};
    const entries = Object.entries(o.findings.openBySeverity).filter(([, n]) => n > 0);
    return {
      tooltip: { ...C.tooltip, trigger: 'item' },
      series: [
        {
          type: 'pie',
          radius: ['58%', '82%'],
          itemStyle: { borderColor: '#15141c', borderWidth: 3 },
          label: { show: false },
          data: entries.length ? entries.map(([k, v]) => ({ name: sevLabel(k), value: v, itemStyle: { color: SEV_COLOR[k] } })) : [{ name: t('none'), value: 1, itemStyle: { color: C.line } }],
        },
      ],
    };
  }, [o]);

  const totalFindings = o ? Object.values(o.findings.openBySeverity).reduce((s, n) => s + n, 0) : 0;
  const a = o?.assets;

  return (
    <>
      <PageHeader title={t('Overview')} subtitle={t('What is happening across your machine and websites right now')} />
      <ErrorNote error={error} />

      {o && (() => {
        // One verdict for the whole page: the worst thing that needs a look, with a button to it.
        const down = (assets?.assets ?? []).filter((x) => x.status === 'down').map((x) => x.name);
        const serious = (o.findings.openBySeverity.critical ?? 0) + (o.findings.openBySeverity.high ?? 0);
        if (down.length)
          return <StatusBanner tone="bad" title={t('{n} asset(s) down', { n: down.length })} detail={down.join(', ')} actions={<Button onClick={() => go('assets')}>{t('View')}</Button>} />;
        if (o.incidents.open)
          return <StatusBanner tone="bad" title={t('{n} open incident(s) need a look', { n: o.incidents.open })} actions={<Button onClick={() => go('incidents')}>{t('View')}</Button>} />;
        if (o.alerts.active.length)
          return <StatusBanner tone="warn" title={t('{n} active alert(s)', { n: o.alerts.active.length })} detail={o.alerts.active[0]?.title} actions={<Button onClick={() => go('alerts')}>{t('View')}</Button>} />;
        if (serious)
          return <StatusBanner tone="warn" title={t('{n} serious finding(s) to review', { n: serious })} actions={<Button onClick={() => go('security')}>{t('View')}</Button>} />;
        return <StatusBanner tone="ok" title={t('All clear')} detail={t('No alerts, incidents or serious findings right now.')} />;
      })()}

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label={t('Assets up')} value={a ? `${a.up} / ${a.total - a.paused}` : '—'} sub={a ? t('{h} host · {w} website(s)', { h: a.hosts, w: a.websites }) : undefined} tone={a && a.down === 0 && a.up > 0 ? 'ok' : a && a.down ? 'bad' : undefined} icon={<Icon.server />} onClick={() => go('assets')} />
        <Kpi label={t('Active alerts')} value={o ? o.alerts.active.length : '—'} sub={o ? t('{c} critical · {h} high', { c: o.alerts.bySeverity.critical ?? 0, h: o.alerts.bySeverity.high ?? 0 }) : undefined} tone={o?.alerts.active.length ? 'bad' : 'ok'} icon={<Icon.bell />} onClick={() => go('alerts')} />
        <Kpi label={t('Open findings')} value={o ? totalFindings : '—'} sub={o ? t('{c} critical · {h} high', { c: o.findings.openBySeverity.critical ?? 0, h: o.findings.openBySeverity.high ?? 0 }) : undefined} tone={o && (o.findings.openBySeverity.critical || o.findings.openBySeverity.high) ? 'warn' : undefined} icon={<Icon.shield />} onClick={() => go('security')} />
        <Kpi label={t('Open incidents')} value={o ? o.incidents.open : '—'} tone={o?.incidents.open ? 'bad' : undefined} icon={<Icon.incident />} onClick={() => go('incidents')} />
        <Kpi label={t('Failed logons (24h)')} value={o ? o.security24h.failedLogons : '—'} sub={t('Windows event 4625')} tone={o && o.security24h.failedLogons >= 5 ? 'warn' : undefined} icon={<Icon.logs />} onClick={() => go('logs')} />
        <Kpi label={t('Website uptime (24h)')} value={pct(o?.websites24h.uptime)} sub={o?.websites24h.avgLatency != null ? t('avg {n} ms', { n: o.websites24h.avgLatency }) : undefined} icon={<Icon.globe />} onClick={() => go('applications')} />
      </div>

      <div className="mb-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_minmax(0,0.9fr)]">
        <Card title={t('Active alerts')} icon={<Icon.bell />} right={<a href="#/alerts" className="text-xs text-muted hover:text-white">{t('View all')}</a>}>
          {!o?.alerts.active.length ? (
            <Empty>{t('No active alerts ✓')}</Empty>
          ) : (
            <ul className="space-y-2">
              {o.alerts.active.slice(0, 6).map((al) => (
                <li key={al.id} className="rounded-lg bg-panel-2 px-3 py-2 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-medium text-sm">{al.title}</span>
                    <SevBadge sev={al.severity} />
                  </div>
                  <div className="mt-1 flex justify-between text-muted">
                    <span className="truncate">{al.detail}</span>
                    <span className="shrink-0 pl-2">{ago(al.triggeredAt)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title={t('Security events · last 24h')} icon={<Icon.shield />} right={<a href="#/logs" className="text-xs text-muted hover:text-white">{t('Log Explorer')}</a>}>
          {o && o.security24h.hourly.length ? <Chart option={eventsOption} height={230} /> : <Empty>{t('No security events in the last 24 hours.')}</Empty>}
        </Card>

        <Card title={t('Open findings')} icon={<Icon.shield />} right={<a href="#/security" className="text-xs text-muted hover:text-white">{t('Security Center')}</a>}>
          <div className="relative">
            <Chart option={findingsDonut} height={170} />
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <div className="text-2xl font-semibold">{totalFindings}</div>
              <div className="text-[11px] text-muted">{t('open')}</div>
            </div>
          </div>
          <div className="mt-2 grid grid-cols-4 gap-1 text-center text-[11px]">
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <div key={s}>
                <div className="font-semibold" style={{ color: SEV_COLOR[s] }}>
                  {o?.findings.openBySeverity[s] ?? 0}
                </div>
                <div className="text-muted">{sevLabel(s)}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="mb-4 grid gap-4 xl:grid-cols-3">
        <Card title={t('Asset health')} icon={<Icon.box />}>
          {!assets?.assets.length ? (
            <Empty>{t('No assets yet.')}</Empty>
          ) : (
            <ul className="divide-y divide-line">
              {assets.assets.map((x) => (
                <li key={x.id}>
                  <a href={x.type === 'host' ? '#/infrastructure' : `#/applications/${x.id}`} className="flex items-center gap-3 py-2.5 hover:opacity-90">
                    <StatusDot status={x.status} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm">{x.name}</span>
                      <span className="block truncate text-xs text-muted">{x.type === 'host' ? x.host?.os : x.target}</span>
                    </span>
                    <span className="shrink-0 text-right text-xs">
                      {x.type === 'host' && x.host?.latest ? (
                        <>
                          <span className="block">CPU {x.host.latest.cpuPct ?? '—'}%</span>
                          <span className="block text-muted">RAM {x.host.latest.memPct ?? '—'}%</span>
                        </>
                      ) : x.website ? (
                        <>
                          <span className="block">{x.status === 'down' ? <span className="text-bad">{statusLabel('down')}</span> : x.website.lastLatencyMs != null ? `${x.website.lastLatencyMs} ms` : '—'}</span>
                          <span className="block text-muted">{pct(x.website.uptime24h)}</span>
                        </>
                      ) : null}
                    </span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title={t('Recent findings')} icon={<Icon.shield />}>
          {!o?.findings.recent.length ? (
            <Empty>{t('No open findings.')}</Empty>
          ) : (
            <ul className="space-y-2">
              {o.findings.recent.map((f) => (
                <li key={f.id}>
                  <a href={`#/security/${f.id}`} className="block rounded-lg bg-panel-2 px-3 py-2 text-xs hover:ring-1 hover:ring-accent/40">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm">{findingText(f, getLang()).title}</span>
                      <SevBadge sev={f.severity} />
                    </div>
                    <div className="mt-1 text-muted">
                      {f.assetName} · {ago(f.lastSeen)}
                    </div>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title={t('Incident timeline')} icon={<Icon.incident />} right={<a href="#/incidents" className="text-xs text-muted hover:text-white">{t('All incidents')}</a>}>
          {!o?.incidents.recent.length ? (
            <Empty>{t('No incidents recorded.')}</Empty>
          ) : (
            <ol className="relative ml-2 space-y-3 border-l border-line pl-4">
              {o.incidents.recent.map((i) => (
                <li key={i.id} className="relative">
                  <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full" style={{ background: SEV_COLOR[i.severity] }} />
                  <a href={`#/incidents/${i.id}`} className="block text-sm hover:underline">
                    {i.title}
                  </a>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-muted">
                    <StateBadge state={i.status} /> {ago(i.openedAt)}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>

      <Card title={t('SENTINEL self-monitoring')} icon={<Icon.settings />}>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
          {o?.health.map((h) => (
            <div key={h.name} className="rounded-lg bg-panel-2 px-3 py-2 text-xs">
              <div className="flex items-center gap-2 font-medium">
                <span className={`h-2 w-2 rounded-full ${h.ok ? 'bg-ok' : 'bg-bad'}`} />
                {t(h.label)}
              </div>
              <div className={`mt-1 ${h.ok ? 'text-muted' : 'text-bad'}`}>{t(h.message)}</div>
              <div className="mt-0.5 text-muted/70">{h.lastRunAt ? t('checked {ago}', { ago: ago(h.lastRunAt) }) : t('not run yet')}</div>
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}
