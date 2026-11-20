import { Fragment, useState } from 'react';
import { Button, Card, Empty, ErrorNote, Json, PageHeader, Td, Th } from '../components/ui';
import { api, type LogEvent } from '../lib/api';
import { stamp } from '../lib/format';
import { t, tk } from '../lib/i18n';
import { useApi } from '../lib/hooks';

type Facets = { categories: { value: string; count: number }[]; eventIds: { value: number; count: number }[]; channels: { value: string; count: number }[] };
type Page = { events: LogEvent[]; nextBefore: number | null; total: number; limits: { maxSpanDays: number; maxLimit: number } };

const RANGES = [
  { value: 1, label: 'Last hour' },
  { value: 24, label: 'Last 24 hours' },
  { value: 72, label: 'Last 3 days' },
  { value: 168, label: 'Last 7 days' },
  { value: 336, label: 'Last 14 days' },
];

const LEVEL_STYLE: Record<string, string> = { critical: 'text-bad', warning: 'text-warn', info: 'text-muted' };

const EVENT_HELP: Record<number, string> = {
  4624: 'Logon success', 4625: 'Logon failure', 4648: 'Explicit credentials', 4720: 'User created', 4722: 'User enabled', 4724: 'Password reset',
  4728: 'Added to global group', 4732: 'Added to local group', 4756: 'Added to universal group', 4740: 'Account lockout', 1102: 'Security log cleared',
  104: 'Log cleared', 6005: 'System start', 6006: 'Clean shutdown', 6008: 'Unexpected shutdown', 7045: 'Service installed', 1116: 'Malware detected',
  1117: 'Malware action', 5001: 'Defender disabled',
};

export default function LogsPage() {
  const [hours, setHours] = useState(24);
  const [category, setCategory] = useState('');
  const [eventId, setEventId] = useState('');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [extra, setExtra] = useState<LogEvent[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  const facets = useApi(() => api.get<Facets>('/logs/facets'), [], ['logs'], 0);
  const params = () => {
    const p = new URLSearchParams({ from: String(Date.now() - hours * 3600_000), to: String(Date.now()), limit: '200' });
    if (category) p.set('category', category);
    if (eventId) p.set('eventId', eventId);
    if (query) p.set('q', query);
    return p;
  };
  const { data, error } = useApi(
    async () => {
      const r = await api.get<Page>(`/logs?${params()}`);
      setExtra([]);
      setCursor(r.nextBefore);
      return r;
    },
    [hours, category, eventId, query],
    ['logs'],
  );

  async function more() {
    if (!cursor) return;
    setLoadingMore(true);
    const p = params();
    p.set('before', String(cursor));
    const r = await api.get<Page>(`/logs?${p}`);
    setExtra((x) => [...x, ...r.events]);
    setCursor(r.nextBefore);
    setLoadingMore(false);
  }

  const events = [...(data?.events ?? []), ...extra];

  return (
    <>
      <PageHeader title={t('Log Explorer')} subtitle={t('Windows security & system events collected from this PC (kept 14 days; queries limited to 14 days / 500 rows per page)')} />
      <ErrorNote error={error} />
      <Card className="mb-4">
        <form
          className="grid gap-2 md:grid-cols-[1fr_1fr_1fr_2fr_auto]"
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(q);
          }}
        >
          <select className="rounded-lg border border-line bg-panel-2 px-2 py-2 text-sm" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {t(r.label)}
              </option>
            ))}
          </select>
          <select className="rounded-lg border border-line bg-panel-2 px-2 py-2 text-sm" value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">{t('All categories')}</option>
            {facets.data?.categories.map((c) => (
              <option key={c.value} value={c.value}>
                {tk(`cat.${c.value}`, c.value.replace('_', ' '))} ({c.count})
              </option>
            ))}
          </select>
          <select className="rounded-lg border border-line bg-panel-2 px-2 py-2 text-sm" value={eventId} onChange={(e) => setEventId(e.target.value)}>
            <option value="">{t('All event IDs')}</option>
            {facets.data?.eventIds.map((c) => (
              <option key={c.value} value={c.value}>
                {c.value} {EVENT_HELP[c.value] ? `· ${t(EVENT_HELP[c.value])}` : ''} ({c.count})
              </option>
            ))}
          </select>
          <input className="rounded-lg border border-line bg-panel-2 px-3 py-2 text-sm outline-none focus:border-accent" placeholder={t('Search text, user, IP, service…')} value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} />
          <Button variant="primary">{t('Search')}</Button>
        </form>
      </Card>

      <Card pad={false} title={data ? t('{n} event(s)', { n: data.total.toLocaleString() }) : t('Events')}>
        {!events.length ? (
          <Empty>{t('No events match. Try a longer time range.')}</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line">
                <tr>
                  <Th>{t('Time')}</Th>
                  <Th>{t('Event')}</Th>
                  <Th>{t('Category')}</Th>
                  <Th>{t('Summary')}</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {events.map((e) => (
                  <Fragment key={e.id}>
                    <tr className="cursor-pointer hover:bg-panel-2/60" onClick={() => setOpen(open === e.id ? null : e.id)}>
                      <Td className="whitespace-nowrap text-xs text-muted">{stamp(e.ts)}</Td>
                      <Td className="whitespace-nowrap text-xs">
                        <span className={LEVEL_STYLE[e.level]}>●</span> {e.eventId} <span className="text-muted">{e.channel === 'Security' ? '' : `· ${e.channel.split('/')[0].replace('Microsoft-Windows-', '')}`}</span>
                      </Td>
                      <Td className="text-xs text-muted">{tk(`cat.${e.category}`, e.category.replace('_', ' '))}</Td>
                      <Td className="text-xs">{e.summary}</Td>
                    </tr>
                    {open === e.id && (
                      <tr>
                        <td colSpan={4} className="bg-black/20 px-3 py-3">
                          <div className="mb-2 text-xs text-muted">
                            {t('Channel')} {e.channel} · {t('record')} #{e.recordId}
                          </div>
                          <Json value={e.fields} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
            {cursor && (
              <div className="p-3 text-center">
                <Button onClick={more} disabled={loadingMore}>
                  {loadingMore ? t('Loading…') : t('Load older events')}
                </Button>
              </div>
            )}
          </div>
        )}
      </Card>
    </>
  );
}
