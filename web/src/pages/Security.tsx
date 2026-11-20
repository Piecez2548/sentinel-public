import { useMemo, useState } from 'react';
import { Button, Card, Empty, ErrorNote, Field, FormModal, Input, Json, Modal, PageHeader, Select, SevBadge, StateBadge, Tabs, Td, Textarea, Th, Toggle } from '../components/ui';
import { api, findingText, type Finding } from '../lib/api';
import { ago, sevLabel, stamp } from '../lib/format';
import { getLang, t, tk } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';

type Detail = {
  finding: Finding;
  evidence: {
    condition: string | null;
    from: number | null;
    to: number | null;
    eventCount: number;
    retainedEvents: { id: number; ts: number; eventId: number; channel: string; summary: string; fields: Record<string, string> }[];
    samples: { ts: number; summary: string }[];
    headers: Record<string, string | null> | null;
    url: string | null;
  };
  incidents: { id: number; title: string; status: string }[];
};

type Rule = { id: string; name: string; description: string; severity: string; enabled: boolean; params: Record<string, number>; paramKeys: string[]; findings30d: number };

const PARAM_LABEL: Record<string, string> = { threshold: 'Failed logons', windowMin: 'Window (minutes)', windowHours: 'Window (hours)',failures: 'Failures before success', repeat: 'Wrong codes before critical' };
const paramLabel = (k: string) => t(PARAM_LABEL[k] ?? k);
const ruleName = (id: string, name: string) => tk(`rule.${id}`, name);
const ruleDesc = (id: string, d: string) => tk(`rule.${id}.desc`, d);

function FindingDetail({ id, onClose }: { id: number; onClose: () => void }) {
  const { data, reload } = useApi(() => api.get<Detail>(`/security/findings/${id}`), [id], ['findings']);
  const [action, setAction] = useState<null | 'resolved' | 'false_positive'>(null);
  const [note, setNote] = useState('');
  const [openEvent, setOpenEvent] = useState<number | null>(null);
  const f = data?.finding;

  async function setStatus(status: string, n?: string) {
    await api.put(`/security/findings/${id}/status`, { status, note: n });
    reload();
  }

  return (
    <Modal title={f ? findingText(f, getLang()).title : t('Finding')} onClose={onClose} wide>
      {!data || !f ? (
        <Empty>{t('Loading…')}</Empty>
      ) : (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <SevBadge sev={f.severity} />
            <StateBadge state={f.status} />
            <span className="text-xs text-muted">
              {ruleName(f.ruleId, f.ruleName)} · {f.assetName} · {t('first {date}', { date: stamp(f.firstSeen) })} · {t('last {date}', { date: stamp(f.lastSeen) })} · {t('{n} event(s)', { n: f.count })}
            </span>
          </div>
          <p>{findingText(f, getLang()).summary}</p>
          {findingText(f, getLang()).fix && (
            <p className="rounded-lg bg-accent/10 px-3 py-2">👉 <b>{t('What to do')}:</b> {findingText(f, getLang()).fix}</p>
          )}
          {findingText(f, getLang()).plain && (
            <details className="text-xs text-muted">
              <summary className="cursor-pointer">{t('Technical details')}</summary>
              <div className="mt-1">{f.title}</div>
              <div className="mt-1 break-all">{f.summary}</div>
            </details>
          )}
          {f.note && <p className="rounded-lg bg-panel-2 px-3 py-2 text-xs text-muted">{t('Note')}: {f.note}</p>}

          <div className="rounded-xl border border-line p-3">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">{t('Evidence')}</div>
            {data.evidence.condition && (
              <div className="mb-2 text-xs">
                <span className="text-muted">{t('Matched condition')}: </span>
                {data.evidence.condition}
              </div>
            )}
            {data.evidence.from && (
              <div className="mb-2 text-xs text-muted">
                {t('Time range')}: {stamp(data.evidence.from)} → {stamp(data.evidence.to)}
              </div>
            )}
            {data.evidence.retainedEvents.length > 0 ? (
              <ul className="max-h-72 space-y-1 overflow-auto">
                {data.evidence.retainedEvents.map((e) => (
                  <li key={e.id} className="rounded-lg bg-panel-2 px-3 py-1.5 text-xs">
                    <button className="flex w-full justify-between gap-3 text-left" onClick={() => setOpenEvent(openEvent === e.id ? null : e.id)}>
                      <span>
                        <span className="text-muted">{stamp(e.ts)} · {e.channel} {e.eventId} · </span>
                        {e.summary}
                      </span>
                      <span className="text-muted">{openEvent === e.id ? '▲' : '▼'}</span>
                    </button>
                    {openEvent === e.id && (
                      <div className="mt-2">
                        <Json value={e.fields} />
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            ) : data.evidence.samples.length ? (
              <>
                <div className="mb-1 text-xs text-warn">{t('Raw events have aged out (14-day retention). Stored samples:')}</div>
                <ul className="space-y-1 text-xs">
                  {data.evidence.samples.map((s, i) => (
                    <li key={i} className="rounded bg-panel-2 px-3 py-1.5">
                      <span className="text-muted">{stamp(s.ts)} · </span>
                      {s.summary}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
            {data.evidence.headers && (
              <div className="mt-2">
                <div className="mb-1 text-xs text-muted">{t('Response headers of {url}', { url: data.evidence.url })}</div>
                <Json value={data.evidence.headers} />
              </div>
            )}
          </div>

          {data.incidents.length > 0 && (
            <div className="text-xs">
              {t('Part of incident(s)')}:{' '}
              {data.incidents.map((i) => (
                <a key={i.id} href={`#/incidents/${i.id}`} className="mr-2 text-accent-2 hover:underline">
                  #{i.id} {i.title} ({t(`state.${i.status}`)})
                </a>
              ))}
            </div>
          )}

          {action ? (
            <form
              className="space-y-2 rounded-xl border border-line p-3"
              onSubmit={async (e) => {
                e.preventDefault();
                await setStatus(action, note);
                setAction(null);
                setNote('');
              }}
            >
              <Field label={action === 'false_positive' ? t('Why is this a false positive? (future matches of the same pattern are suppressed)') : t('How was it resolved?')}>
                <Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} autoFocus />
              </Field>
              <div className="flex justify-end gap-2">
                <Button type="button" onClick={() => setAction(null)}>
                  {t('Cancel')}
                </Button>
                <Button variant="primary" disabled={!note.trim()}>
                  {t('Confirm')}
                </Button>
              </div>
            </form>
          ) : (
            <div className="flex flex-wrap gap-2">
              {f.status === 'open' && <Button onClick={() => setStatus('acknowledged')}>{t('Acknowledge')}</Button>}
              {(f.status === 'open' || f.status === 'acknowledged') && (
                <>
                  <Button variant="primary" onClick={() => setAction('resolved')}>
                    {t('Resolve')}
                  </Button>
                  <Button onClick={() => setAction('false_positive')}>{t('Mark false positive')}</Button>
                </>
              )}
              {(f.status === 'resolved' || f.status === 'false_positive') && <Button onClick={() => setStatus('open')}>{t('Reopen')}</Button>}
              <a href={`#/logs`} className="ml-auto self-center text-xs text-accent-2 hover:underline">
                {t('Open Log Explorer →')}
              </a>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

function RuleEditor({ rule, onClose, onSaved }: { rule: Rule; onClose: () => void; onSaved: () => void }) {
  const [severity, setSeverity] = useState(rule.severity);
  const [params, setParams] = useState<Record<string, string>>(Object.fromEntries(Object.entries(rule.params).map(([k, v]) => [k, String(v)])));
  return (
    <FormModal
      title={ruleName(rule.id, rule.name)}
      onClose={onClose}
      onSubmit={async () => {
        await api.put(`/security/rules/${rule.id}`, { severity, params: Object.fromEntries(Object.entries(params).map(([k, v]) => [k, Number(v)])) });
        onSaved();
      }}
    >
      <p className="text-sm text-muted">{ruleDesc(rule.id, rule.description)}</p>
      <Field label={t('Severity')}>
        <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {['low', 'medium', 'high', 'critical'].map((s) => (
            <option key={s} value={s}>{sevLabel(s)}</option>
          ))}
        </Select>
      </Field>
      {rule.paramKeys.map((k) => (
        <Field key={k} label={paramLabel(k)}>
          <Input type="number" min={1} value={params[k]} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />
        </Field>
      ))}
    </FormModal>
  );
}

/** Action bar for the selected findings: acknowledge / resolve / false positive in one go. */
function BulkBar({ ids, onDone }: { ids: number[]; onDone: () => void }) {
  const [action, setAction] = useState<null | 'resolved' | 'false_positive'>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function apply(status: string, n?: string) {
    setBusy(true);
    setErr(null);
    try {
      await api.post('/security/findings/bulk-status', { ids, status, note: n });
      setAction(null);
      setNote('');
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2 border-b border-line bg-panel-2/60 px-4 py-3 text-sm">
      <ErrorNote error={err} />
      {action ? (
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            void apply(action, note.trim());
          }}
        >
          <Field label={`${t('{n} selected', { n: ids.length })} — ${action === 'false_positive' ? t('Why is this a false positive? (future matches of the same pattern are suppressed)') : t('How was it resolved?')}`}>
            <Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} autoFocus />
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={() => setAction(null)}>
              {t('Cancel')}
            </Button>
            <Button variant="primary" disabled={!note.trim() || busy}>
              {t('Confirm')}
            </Button>
          </div>
        </form>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <span className="mr-2 font-medium">{t('{n} selected', { n: ids.length })}</span>
          <Button disabled={busy} onClick={() => void apply('acknowledged')}>
            {t('Acknowledge')}
          </Button>
          <Button variant="primary" disabled={busy} onClick={() => setAction('resolved')}>
            {t('Resolve')}
          </Button>
          <Button disabled={busy} onClick={() => setAction('false_positive')}>
            {t('Mark false positive')}
          </Button>
          <button type="button" className="ml-auto text-xs text-muted hover:underline" onClick={onDone}>
            {t('Clear selection')}
          </button>
        </div>
      )}
    </div>
  );
}

type SortKey = 'recent' | 'sev_desc' | 'sev_asc';
const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Severity order with the most recent first inside each level; "recent" keeps the server's newest-first order. */
function sortFindings(list: Finding[], sort: SortKey): Finding[] {
  if (sort === 'recent') return list;
  const dir = sort === 'sev_desc' ? -1 : 1;
  return [...list].sort((a, b) => dir * ((SEV_RANK[a.severity] ?? 0) - (SEV_RANK[b.severity] ?? 0)) || b.lastSeen - a.lastSeen);
}

export default function SecurityPage({ selectedId, go }: { selectedId: number | null; go: (p: string) => void }) {
  useTick();
  const [tab, setTab] = useState<'findings' | 'rules'>('findings');
  const [status, setStatus] = useState('active');
  const [severity, setSeverity] = useState('');
  const { data, error } = useApi(() => api.get<{ findings: Finding[] }>(`/security/findings?status=${status}${severity ? `&severity=${severity}` : ''}&limit=300`), [status, severity], ['findings']);
  const rules = useApi(() => api.get<{ rules: Rule[] }>('/security/rules'), [], ['findings']);
  const [editRule, setEditRule] = useState<Rule | null>(null);
  const [sort, setSortState] = useState<SortKey>(() => {
    try {
      const v = localStorage.getItem('sentinel.findingSort');
      return v === 'sev_desc' || v === 'sev_asc' ? v : 'recent';
    } catch {
      return 'recent';
    }
  });
  const setSort = (v: SortKey) => {
    setSortState(v);
    try {
      localStorage.setItem('sentinel.findingSort', v);
    } catch {
      /* storage unavailable — the choice just isn't remembered */
    }
  };
  const findings = useMemo(() => sortFindings(data?.findings ?? [], sort), [data, sort]);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  // Only findings still shown count as selected (filters or live updates may drop some).
  const selected = findings.filter((f) => picked.has(f.id)).map((f) => f.id);
  const allSelected = findings.length > 0 && selected.length === findings.length;
  const toggle = (id: number) =>
    setPicked((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <>
      <PageHeader title={t('Security Center')} subtitle={t('Rule-based detections from Windows security logs and website checks — every finding links to its evidence')} />
      <ErrorNote error={error} />
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'findings', label: t('Findings') },
          { value: 'rules', label: t('Detection rules ({n} on)', { n: rules.data?.rules.filter((r) => r.enabled).length ?? '…' }) },
        ]}
      />

      {tab === 'findings' ? (
        <Card
          pad={false}
          title={t('Findings')}
          right={
            <div className="flex flex-wrap gap-2">
              <select className="rounded-lg border border-line bg-panel-2 px-2 py-1 text-xs" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="active">{t('Open & acknowledged')}</option>
                <option value="open">{t('state.open')}</option>
                <option value="resolved">{t('state.resolved')}</option>
                <option value="false_positive">{t('state.false_positive')}</option>
                <option value="all">{t('All')}</option>
              </select>
              <select className="rounded-lg border border-line bg-panel-2 px-2 py-1 text-xs" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">{t('All severities')}</option>
                {['critical', 'high', 'medium', 'low'].map((s) => (
                  <option key={s} value={s}>{sevLabel(s)}</option>
                ))}
              </select>
              <select className="rounded-lg border border-line bg-panel-2 px-2 py-1 text-xs" value={sort} onChange={(e) => setSort(e.target.value as SortKey)} aria-label={t('Sort')}>
                <option value="recent">{t('Newest first')}</option>
                <option value="sev_desc">{t('Severity: high → low')}</option>
                <option value="sev_asc">{t('Severity: low → high')}</option>
              </select>
            </div>
          }
        >
          {selected.length > 0 && <BulkBar ids={selected} onDone={() => setPicked(new Set())} />}
          {!findings.length ? (
            <Empty>{t('No findings for this filter.')}</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-line">
                  <tr>
                    <Th className="w-8">
                      <input
                        type="checkbox"
                        className="size-4 cursor-pointer accent-[var(--color-accent)]"
                        aria-label={t('Select all')}
                        checked={allSelected}
                        ref={(el) => {
                          if (el) el.indeterminate = selected.length > 0 && !allSelected;
                        }}
                        onChange={() => setPicked(allSelected ? new Set() : new Set(findings.map((f) => f.id)))}
                      />
                    </Th>
                    <Th>
                      <button
                        type="button"
                        className="inline-flex items-center gap-1 hover:text-text"
                        title={t('Sort')}
                        onClick={() => setSort(sort === 'sev_desc' ? 'sev_asc' : 'sev_desc')}
                      >
                        {t('Severity')}
                        <span aria-hidden>{sort === 'sev_desc' ? '↓' : sort === 'sev_asc' ? '↑' : '↕'}</span>
                      </button>
                    </Th>
                    <Th>{t('Finding')}</Th>
                    <Th>{t('Asset')}</Th>
                    <Th>{t('Events')}</Th>
                    <Th>{t('Last seen')}</Th>
                    <Th>{t('Status')}</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {findings.map((f) => (
                    <tr key={f.id} className={`cursor-pointer hover:bg-panel-2/60 ${picked.has(f.id) ? 'bg-panel-2/40' : ''}`} onClick={() => go(`security/${f.id}`)}>
                      <Td className="w-8">
                        <input
                          type="checkbox"
                          className="size-4 cursor-pointer accent-[var(--color-accent)]"
                          aria-label={t('Select')}
                          checked={picked.has(f.id)}
                          onClick={(e) => e.stopPropagation()}
                          onChange={() => toggle(f.id)}
                        />
                      </Td>
                      <Td>
                        <SevBadge sev={f.severity} />
                      </Td>
                      <Td>
                        <div>{findingText(f, getLang()).title}</div>
                        <div className="max-w-xl truncate text-xs text-muted">{findingText(f, getLang()).summary}</div>
                      </Td>
                      <Td className="text-xs text-muted">{f.assetName}</Td>
                      <Td className="text-xs">{f.count}</Td>
                      <Td className="whitespace-nowrap text-xs text-muted">{ago(f.lastSeen)}</Td>
                      <Td>
                        <StateBadge state={f.status} />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : (
        <Card pad={false}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line">
                <tr>
                  <Th>{t('On')}</Th>
                  <Th>{t('Rule')}</Th>
                  <Th>{t('Severity')}</Th>
                  <Th>{t('Parameters')}</Th>
                  <Th>{t('Findings (30d)')}</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rules.data?.rules.map((r) => (
                  <tr key={r.id}>
                    <Td>
                      <Toggle
                        checked={r.enabled}
                        onChange={async (v) => {
                          await api.put(`/security/rules/${r.id}`, { enabled: v });
                          rules.reload();
                        }}
                      />
                    </Td>
                    <Td>
                      <div>{ruleName(r.id, r.name)}</div>
                      <div className="max-w-xl text-xs text-muted">{ruleDesc(r.id, r.description)}</div>
                    </Td>
                    <Td>
                      <SevBadge sev={r.severity} />
                    </Td>
                    <Td className="text-xs text-muted">{r.paramKeys.length ? r.paramKeys.map((k) => `${paramLabel(k)}: ${r.params[k]}`).join(' · ') : '—'}</Td>
                    <Td className="text-xs">{r.findings30d}</Td>
                    <Td className="text-right">
                      <Button variant="ghost" onClick={() => setEditRule(r)}>
                        {t('Tune')}
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      {selectedId && <FindingDetail id={selectedId} onClose={() => go('security')} />}
      {editRule && <RuleEditor rule={editRule} onClose={() => setEditRule(null)} onSaved={rules.reload} />}
    </>
  );
}
