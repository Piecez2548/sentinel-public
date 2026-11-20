import { useMemo, useState } from 'react';
import { Chart, C, baseAxis } from '../components/Chart';
import { Card, Empty, ErrorNote, Meter, PageHeader, Segmented, StatusDot } from '../components/ui';
import { api, type Asset } from '../lib/api';
import { ago, bps, bytes, duration, fullDate, statusLabel } from '../lib/format';
import { t } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';

type MetricPoint = { t: number; cpu: number | null; cpuMax: number | null; mem: number | null; rxBps: number | null; txBps: number | null; diskMaxPct: number };

function HostPanel({ host }: { host: Asset }) {
  const [hours, setHours] = useState(6);
  const { data } = useApi(() => api.get<{ points: MetricPoint[] }>(`/assets/${host.id}/metrics?hours=${hours}`), [host.id, hours], ['metrics'], 60_000);
  const pts = data?.points ?? [];
  const h = host.host!;
  const l = h.latest;
  const now = Date.now();
  const xAxis = { type: 'time', min: now - hours * 3600_000, max: now, ...baseAxis, splitLine: { show: false } };

  const usageOpt = useMemo(
    () => ({
      grid: { left: 40, right: 10, top: 28, bottom: 24 },
      legend: { top: 0, textStyle: { color: C.text, fontSize: 11 } },
      tooltip: { ...C.tooltip, trigger: 'axis', valueFormatter: (v: number) => (v == null ? '—' : `${v}%`) },
      xAxis,
      yAxis: { type: 'value', min: 0, max: 100, ...baseAxis, axisLabel: { color: C.text, formatter: '{value}%' } },
      series: [
        { name: t('CPU'), type: 'line', showSymbol: false, smooth: 0.2, data: pts.map((p) => [p.t, p.cpu]), lineStyle: { color: C.accent, width: 2 }, itemStyle: { color: C.accent }, areaStyle: { color: 'rgba(139,92,246,.15)' } },
        { name: t('Memory'), type: 'line', showSymbol: false, smooth: 0.2, data: pts.map((p) => [p.t, p.mem]), lineStyle: { color: C.accent2, width: 2 }, itemStyle: { color: C.accent2 } },
        { name: t('Disk (fullest)'), type: 'line', showSymbol: false, data: pts.map((p) => [p.t, p.diskMaxPct || null]), lineStyle: { color: C.warn, width: 1.5, type: 'dashed' }, itemStyle: { color: C.warn } },
      ],
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pts, hours],
  );

  const netOpt = useMemo(
    () => ({
      grid: { left: 64, right: 10, top: 28, bottom: 24 },
      legend: { top: 0, textStyle: { color: C.text, fontSize: 11 } },
      tooltip: { ...C.tooltip, trigger: 'axis', valueFormatter: (v: number) => bps(v) },
      xAxis,
      yAxis: { type: 'value', min: 0, ...baseAxis, axisLabel: { color: C.text, formatter: (v: number) => bps(v) } },
      series: [
        { name: t('Download'), type: 'line', showSymbol: false, data: pts.map((p) => [p.t, p.rxBps]), lineStyle: { color: C.ok, width: 1.5 }, itemStyle: { color: C.ok } },
        { name: t('Upload'), type: 'line', showSymbol: false, data: pts.map((p) => [p.t, p.txBps]), lineStyle: { color: C.orange, width: 1.5 }, itemStyle: { color: C.orange } },
      ],
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pts, hours],
  );

  return (
    <div className="space-y-4">
      <Card
        title={
          <span className="flex items-center gap-2">
            <StatusDot status={host.status} /> {host.name}
            <span className="text-xs font-normal text-muted">{statusLabel(host.status)}</span>
          </span>
        }
        right={<span className="text-xs text-muted">{t('last sample {ago}', { ago: ago(h.lastSeenAt) })}</span>}
      >
        <div className="grid gap-x-6 gap-y-1 text-xs text-muted sm:grid-cols-2 xl:grid-cols-4">
          <div>{t('OS')}: <span className="text-slate-200">{h.os ?? '—'}</span></div>
          <div>{t('CPU')}: <span className="text-slate-200">{h.cpuModel ?? '—'} ({t('{n} cores', { n: h.cores })})</span></div>
          <div>{t('Memory')}: <span className="text-slate-200">{bytes(h.memTotal)}</span></div>
          <div>{t('Up since')}: <span className="text-slate-200">{h.bootAt ? `${duration(Date.now() - h.bootAt)} (${t('booted {date}', { date: fullDate(h.bootAt) })})` : '—'}</span></div>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-xl bg-panel-2 p-3">
            <div className="flex justify-between text-xs text-muted">
              <span>CPU</span>
              <span className="text-lg font-semibold text-white">{l?.cpuPct ?? '—'}%</span>
            </div>
            <div className="mt-2">
              <Meter value={l?.cpuPct ?? null} />
            </div>
          </div>
          <div className="rounded-xl bg-panel-2 p-3">
            <div className="flex justify-between text-xs text-muted">
              <span>{t('Memory')} · {bytes(l?.memUsed)} / {bytes(l?.memTotal)}</span>
              <span className="text-lg font-semibold text-white">{l?.memPct ?? '—'}%</span>
            </div>
            <div className="mt-2">
              <Meter value={l?.memPct ?? null} />
            </div>
          </div>
          <div className="rounded-xl bg-panel-2 p-3">
            <div className="text-xs text-muted">{t('Network')}</div>
            <div className="mt-1 text-sm">
              ↓ {bps(l?.netRxBps)} <span className="text-muted">·</span> ↑ {bps(l?.netTxBps)}
            </div>
          </div>
          {l?.batteryPct != null && (
            <div className="rounded-xl bg-panel-2 p-3">
              <div className="flex justify-between text-xs text-muted">
                <span>
                  {t('Battery')} · {l.onAc ? `🔌 ${t('charger connected')}` : `🔋 ${t('on battery')}`}
                </span>
                <span className="text-lg font-semibold text-white">{l.batteryPct}%</span>
              </div>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-line">
                <div className={`h-full rounded-full ${l.batteryPct <= 20 ? 'bg-bad' : l.batteryPct <= 40 ? 'bg-warn' : 'bg-ok'}`} style={{ width: `${l.batteryPct}%` }} />
              </div>
            </div>
          )}
          <div className="rounded-xl bg-panel-2 p-3">
            <div className="text-xs text-muted">{t('Security events (24h)')}</div>
            <a href="#/logs" className="mt-1 block text-sm hover:underline">
              {t('{n} events →', { n: h.securityEvents24h })}
            </a>
          </div>
        </div>

        <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {(l?.disks ?? []).map((d) => (
            <div key={d.mount} className="rounded-xl bg-panel-2 p-3">
              <div className="flex justify-between text-xs text-muted">
                <span>{t('Disk {m} · {free} free of {total}', { m: d.mount, free: bytes(d.free), total: bytes(d.total) })}</span>
                <span className="font-semibold text-white">{d.usedPct}%</span>
              </div>
              <div className="mt-2">
                <Meter value={d.usedPct} warn={80} bad={90} />
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title={t('Resource usage')} right={<Segmented value={hours} onChange={setHours} options={[{ value: 1, label: t('1h') }, { value: 6, label: t('6h') }, { value: 24, label: t('24h') }, { value: 168, label: t('7d') }]} />}>
        {pts.length ? <Chart option={usageOpt} height={240} /> : <Empty>{t('Collecting the first samples (one per minute)…')}</Empty>}
      </Card>
      <Card title={t('Network throughput')}>{pts.length ? <Chart option={netOpt} height={200} /> : <Empty>{t('No data yet.')}</Empty>}</Card>
    </div>
  );
}

export default function InfrastructurePage() {
  useTick();
  const { data, error } = useApi(() => api.get<{ assets: Asset[] }>('/assets?type=host'), [], ['assets', 'metrics']);
  const hosts = data?.assets ?? [];
  return (
    <>
      <PageHeader title={t('Infrastructure')} subtitle={t('Host metrics: CPU, memory, disks, network and availability')} />
      <ErrorNote error={error} />
      {data && !hosts.length && (
        <Card>
          <Empty>{t('No hosts. The built-in collector for this PC is turned off in Settings.')}</Empty>
        </Card>
      )}
      <div className="space-y-6">
        {hosts.map((h) => (
          <HostPanel key={h.id} host={h} />
        ))}
      </div>
    </>
  );
}
