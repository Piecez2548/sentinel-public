import { useMemo, useState } from 'react';
import { Chart, C, baseAxis } from '../components/Chart';
import { Card, Empty, ErrorNote, Kpi, PageHeader, Segmented, SevBadge, Td, Th } from '../components/ui';
import { api } from '../lib/api';
import { duration, pct, SEV_COLOR } from '../lib/format';
import { t, tk } from '../lib/i18n';
import { useApi } from '../lib/hooks';

type AssetReport = {
  id: number; name: string; type: string; isLocalPc: boolean; sloTarget: number; daysCovered: number; availability: number | null; sloMet: boolean | null;
  downtimeMin: number | null; errorBudgetMin: number; errorBudgetLeftPct: number | null; latencyAvg: number | null; latencyP95: number | null;
  cpuAvg: number | null; cpuMax: number | null; memAvg: number | null; daily: { day: string; availability: number | null; latencyAvg: number | null; cpuAvg: number | null }[];
};
type Report = {
  days: number;
  generatedAt: number;
  assets: AssetReport[];
  incidents: { total: number; open: number; bySeverity: Record<string, number>; mttaMs: number | null; mttrMs: number | null };
  alerts: { bySeverity: Record<string, number>; byRule: { name: string; count: number }[] };
  security: { findingsByRule: { name: string; severity: string; count: number }[]; findingsDaily: { day: string; n: number }[]; failedLogonsDaily: { day: string; n: number }[]; note: string };
};

const EXPORTS = [
  { kind: 'summary', label: 'Summary (per site / PC)' },
  { kind: 'alerts', label: 'Every alert fired' },
  { kind: 'incidents', label: 'Every incident' },
  { kind: 'findings', label: 'Every security finding' },
] as const;

/** "Export CSV" menu: downloads the period shown on the page. */
function ExportMenu({ days }: { days: number }) {
  return (
    <details className="group relative">
      <summary className="inline-flex cursor-pointer list-none items-center gap-1.5 rounded-lg border border-line bg-panel-2 px-3 py-1.5 text-sm font-medium transition hover:border-accent/70 [&::-webkit-details-marker]:hidden">
        ⬇ {t('Export CSV')}
        <span className="text-xs text-muted transition group-open:rotate-180">▾</span>
      </summary>
      <div className="pop-in absolute right-0 z-20 mt-1 w-64 rounded-xl border border-line bg-panel p-1 shadow-2xl shadow-black/50">
        <div className="px-3 pb-1 pt-2 text-[11px] text-muted">{t('Last {n} days', { n: days })}</div>
        {EXPORTS.map((e) => (
          <a key={e.kind} href={`/api/reports/export.csv?kind=${e.kind}&days=${days}`} download className="block rounded-lg px-3 py-2 text-sm transition hover:bg-panel-2 hover:text-white">
            {t(e.label)}
          </a>
        ))}
      </div>
    </details>
  );
}

export default function ReportsPage() {
  const [days, setDays] = useState(30);
  const { data: r, error } = useApi(() => api.get<Report>(`/reports?days=${days}`), [days], [], 0);

  const availOpt = useMemo(() => {
    if (!r) return {};
    const allDays = [...new Set(r.assets.flatMap((a) => a.daily.map((d) => d.day)))].sort();
    // One distinct colour per asset (the old 5-colour palette repeated, so two lines looked the same).
    const palette = [C.accent, C.accent2, C.ok, C.orange, C.warn, '#f472b6', '#2dd4bf', '#a3e635', '#f87171', '#c4b5fd'];
    return {
      // Legend on its own scrolling row above the plot, so names never sit on top of the lines.
      grid: { left: 44, right: 12, top: 44, bottom: 24 },
      legend: { type: 'scroll', top: 0, left: 0, right: 0, itemWidth: 14, itemHeight: 8, itemGap: 14, icon: 'roundRect', textStyle: { color: C.text, fontSize: 11 }, pageIconColor: C.accent, pageIconInactiveColor: C.line, pageTextStyle: { color: C.text } },
      tooltip: { ...C.tooltip, trigger: 'axis', valueFormatter: (v: number) => (v == null ? '—' : `${v.toFixed(2)}%`) },
      xAxis: { type: 'category', data: allDays.map((d) => d.slice(5)), ...baseAxis, splitLine: { show: false } },
      yAxis: { type: 'value', min: (v: { min: number }) => Math.max(0, Math.floor(Math.min(v.min, 99) - 1)), max: 100, ...baseAxis, axisLabel: { color: C.text, formatter: '{value}%' } },
      series: r.assets.map((a, i) => ({
        name: a.name,
        type: 'line',
        showSymbol: allDays.length < 20,
        symbolSize: 5,
        emphasis: { focus: 'series' },
        data: allDays.map((d) => a.daily.find((x) => x.day === d)?.availability ?? null),
        lineStyle: { color: palette[i % palette.length], width: 2 },
        itemStyle: { color: palette[i % palette.length] },
      })),
    };
  }, [r]);

  const secOpt = useMemo(() => {
    if (!r) return {};
    const allDays = [...new Set([...r.security.findingsDaily.map((d) => d.day), ...r.security.failedLogonsDaily.map((d) => d.day)])].sort();
    return {
      grid: { left: 36, right: 12, top: 44, bottom: 24 },
      legend: { type: 'scroll', top: 0, left: 0, right: 0, itemWidth: 14, itemHeight: 8, icon: 'roundRect', textStyle: { color: C.text, fontSize: 11 } },
      tooltip: { ...C.tooltip, trigger: 'axis' },
      xAxis: { type: 'category', data: allDays.map((d) => d.slice(5)), ...baseAxis, splitLine: { show: false } },
      yAxis: { type: 'value', minInterval: 1, ...baseAxis },
      series: [
        { name: t('New findings'), type: 'bar', barMaxWidth: 14, itemStyle: { color: C.accent, borderRadius: 2 }, data: allDays.map((d) => r.security.findingsDaily.find((x) => x.day === d)?.n ?? 0) },
        { name: t('Failed logons'), type: 'line', itemStyle: { color: C.bad }, lineStyle: { color: C.bad }, data: allDays.map((d) => r.security.failedLogonsDaily.find((x) => x.day === d)?.n ?? 0) },
      ],
    };
  }, [r]);

  const totalAlerts = r ? Object.values(r.alerts.bySeverity).reduce((s, n) => s + n, 0) : 0;

  return (
    <>
      <PageHeader
        title={t('Reports')}
        subtitle={t('Availability, SLO & error budget, incident response times (MTTA/MTTR) and security trends')}
        actions={
          <>
            <Segmented value={days} onChange={setDays} options={[{ value: 7, label: t('{n} days', { n: 7 }) }, { value: 30, label: t('{n} days', { n: 30 }) }, { value: 90, label: t('{n} days', { n: 90 }) }]} />
            <ExportMenu days={days} />
          </>
        }
      />
      <ErrorNote error={error} />
      {!r ? (
        <Empty>{t('Building report…')}</Empty>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Kpi label={t('Incidents')} value={r.incidents.total} sub={t('{n} still open', { n: r.incidents.open })} />
            <Kpi label={t('MTTA (mean time to acknowledge)')} value={duration(r.incidents.mttaMs)} />
            <Kpi label={t('MTTR (mean time to resolve)')} value={duration(r.incidents.mttrMs)} />
            <Kpi label={t('Alerts fired')} value={totalAlerts} sub={t('{c} critical · {h} high', { c: r.alerts.bySeverity.critical ?? 0, h: r.alerts.bySeverity.high ?? 0 })} />
          </div>

          <Card title={t('Availability & SLO')} pad={false} className="mb-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-line">
                  <tr>
                    <Th>{t('Asset')}</Th>
                    <Th>{t('Availability')}</Th>
                    <Th>{t('SLO target')}</Th>
                    <Th>SLO</Th>
                    <Th>{t('Downtime (est.)')}</Th>
                    <Th>{t('Error budget left')}</Th>
                    <Th>{t('Performance')}</Th>
                    <Th>{t('Data')}</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {r.assets.map((a) => (
                    <tr key={a.id}>
                      <Td>
                        {a.name} <span className="text-xs text-muted">· {t(a.type)}</span>
                      </Td>
                      <Td className="font-semibold">{pct(a.availability, 3)}</Td>
                      <Td className="text-xs">{a.sloTarget}%</Td>
                      <Td>
                        {a.isLocalPc ? (
                          <span className="text-xs text-muted" title={t('This PC is turned off normally, so only monitoring coverage is shown.')}>{t('coverage only')}</span>
                        ) : a.sloMet == null ? (
                          <span className="text-xs text-muted">{t('no data')}</span>
                        ) : a.sloMet ? (
                          <span className="text-xs text-ok">✓ {t('met')}</span>
                        ) : (
                          <span className="text-xs text-bad">✗ {t('missed')}</span>
                        )}
                      </Td>
                      <Td className="text-xs">{a.downtimeMin != null ? duration(a.downtimeMin * 60_000) : '—'}</Td>
                      <Td className="text-xs">
                        {a.errorBudgetLeftPct != null ? (
                          <div className="w-28">
                            <div className="h-1.5 overflow-hidden rounded-full bg-line">
                              <div className={`h-full ${a.errorBudgetLeftPct > 50 ? 'bg-ok' : a.errorBudgetLeftPct > 10 ? 'bg-warn' : 'bg-bad'}`} style={{ width: `${a.errorBudgetLeftPct}%` }} />
                            </div>
                            <div className="mt-0.5">{t('{p}% of {d}', { p: a.errorBudgetLeftPct.toFixed(0), d: duration(a.errorBudgetMin * 60_000) })}</div>
                          </div>
                        ) : (
                          '—'
                        )}
                      </Td>
                      <Td className="text-xs text-muted">
                        {a.type === 'website'
                          ? `${t('avg')} ${a.latencyAvg != null ? Math.round(a.latencyAvg) : '—'} ms · p95 ${a.latencyP95 != null ? Math.round(a.latencyP95) : '—'} ms`
                          : `CPU ${t('avg')} ${a.cpuAvg?.toFixed(1) ?? '—'}% (${t('max')} ${a.cpuMax?.toFixed(0) ?? '—'}%) · RAM ${t('avg')} ${a.memAvg?.toFixed(1) ?? '—'}%`}
                      </Td>
                      <Td className="text-xs text-muted">{t('{n} day(s)', { n: a.daysCovered })}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="px-4 pb-3 pt-2 text-[11px] text-muted">
              {t('Website availability = share of successful checks; downtime is estimated from it over the covered days. For this PC the figure is monitoring coverage (share of minutes with metrics) — it drops whenever the PC or SENTINEL is off, which is normal, so no SLO is judged.')}
            </p>
          </Card>

          <div className="mb-4 grid gap-4 xl:grid-cols-2">
            <Card title={t('Daily availability')}>{r.assets.some((a) => a.daily.length) ? <Chart option={availOpt} height={240} /> : <Empty>{t('No data yet.')}</Empty>}</Card>
            <Card title={t('Security trend')}>{r.security.findingsDaily.length || r.security.failedLogonsDaily.length ? <Chart option={secOpt} height={240} /> : <Empty>{t('No findings or failed logons in this period.')}</Empty>}</Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Card title={t('Incidents by severity')}>
              <ul className="space-y-2 text-sm">
                {['critical', 'high', 'medium', 'low'].map((s) => (
                  <li key={s} className="flex items-center justify-between">
                    <SevBadge sev={s} />
                    <span style={{ color: SEV_COLOR[s] }} className="font-semibold">
                      {r.incidents.bySeverity[s] ?? 0}
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
            <Card title={t('Alerts by rule')}>
              {!r.alerts.byRule.length ? (
                <Empty>{t('No alerts in this period.')}</Empty>
              ) : (
                <ul className="space-y-1.5 text-sm">
                  {r.alerts.byRule.map((x) => (
                    <li key={x.name} className="flex justify-between">
                      <span>{tk(`alertRule.${x.name}`, x.name)}</span>
                      <span className="text-muted">{x.count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title={t('Findings by detection rule')}>
              {!r.security.findingsByRule.length ? (
                <Empty>{t('No findings in this period.')}</Empty>
              ) : (
                <ul className="space-y-1.5 text-sm">
                  {r.security.findingsByRule.map((x) => (
                    <li key={`${x.name}${x.severity}`} className="flex items-center justify-between gap-2">
                      <span className="truncate">{x.name}</span>
                      <span className="flex items-center gap-2">
                        <SevBadge sev={x.severity} />
                        <span className="text-muted">{x.count}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-3 text-[11px] text-muted">{t(r.security.note)}</p>
            </Card>
          </div>
        </>
      )}
    </>
  );
}
