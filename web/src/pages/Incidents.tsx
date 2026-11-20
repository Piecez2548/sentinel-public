import { useState } from 'react';
import { Button, Card, Empty, ErrorNote, Field, FormModal, Input, PageHeader, Select, SevBadge, StateBadge, Td, Textarea, Th } from '../components/ui';
import { api, type Asset, type Incident } from '../lib/api';
import { ago, duration, SEV_COLOR, sevLabel, stamp, stateLabel } from '../lib/format';
import { t, tk } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';

type Detail = {
  incident: Incident;
  timeline: { id: number; type: string; fromStatus: string | null; toStatus: string | null; message: string | null; ts: number }[];
  links: { kind: 'alert' | 'finding'; refId: number; reason: string | null; linkedAt: number; title: string; severity: string | null; status: string | null; ts: number | null; detail: string | null }[];
  hint: string | null;
  allowedTransitions: string[];
};

type AiSummary = {
  summary: string;
  timeline: { text: string; evidence: string[] }[];
  likely_cause: { text: string; evidence: string[]; confidence: 'low' | 'medium' | 'high' };
  recommended_actions: { action: string; why: string; evidence: string[] }[];
  unknowns: string[];
  invalidCitations: string[];
  evidence: { id: string; kind: string; title: string }[];
  model: string;
  createdAt: number;
};

function Cites({ ids, evidence }: { ids: string[]; evidence: AiSummary['evidence'] }) {
  if (!ids.length) return <span className="ml-1 text-[11px] text-warn">[{t('no evidence cited')}]</span>;
  return (
    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
      {ids.map((id) => {
        const ev = evidence.find((x) => x.id === id);
        return (
          <span key={id} title={ev ? `${ev.kind}: ${ev.title}` : id} className="cursor-help rounded bg-accent/20 px-1 text-[10px] font-medium text-violet-300">
            {id}
          </span>
        );
      })}
    </span>
  );
}

function AiPanel({ incidentId, timeline, onDone }: { incidentId: number; timeline: Detail['timeline']; onDone: () => void }) {
  const status = useApi(() => api.get<{ enabled: boolean; model: string }>('/ai/status'), []);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const last = [...timeline].reverse().find((e) => e.type === 'ai_summary');
  let s: AiSummary | null = null;
  try {
    s = last?.message ? (JSON.parse(last.message) as AiSummary) : null;
  } catch {
    s = null;
  }
  const conf = { low: t('low confidence'), medium: t('medium confidence'), high: t('high confidence') };
  return (
    <Card
      title={t('AI summary')}
      right={
        status.data?.enabled && (
          <Button
            variant="primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setErr(null);
              try {
                await api.post(`/incidents/${incidentId}/ai-summary`);
                onDone();
              } catch (e) {
                setErr(e instanceof Error ? t(e.message) : t('Failed'));
              }
              setBusy(false);
            }}
          >
            {busy ? t('Analysing evidence…') : s ? t('Summarise again') : t('Summarise with AI')}
          </Button>
        )
      }
    >
      <ErrorNote error={err} />
      {status.data && !status.data.enabled ? (
        <p className="text-sm text-muted">{t('AI_OFF_HELP')}</p>
      ) : !s ? (
        <p className="text-sm text-muted">{t('AI_INTRO')}</p>
      ) : (
        <div className="space-y-3 text-sm">
          <p>{s.summary}</p>
          {s.timeline.length > 0 && (
            <div>
              <div className="mb-1 text-xs font-semibold text-muted">{t('What happened')}</div>
              <ol className="list-decimal space-y-1 pl-5">
                {s.timeline.map((x, k) => (
                  <li key={k}>
                    {x.text}
                    <Cites ids={x.evidence} evidence={s!.evidence} />
                  </li>
                ))}
              </ol>
            </div>
          )}
          <div>
            <div className="mb-1 text-xs font-semibold text-muted">
              {t('Likely cause')} · {conf[s.likely_cause.confidence]}
            </div>
            <p>
              {s.likely_cause.text}
              <Cites ids={s.likely_cause.evidence} evidence={s.evidence} />
            </p>
          </div>
          {s.recommended_actions.length > 0 && (
            <div>
              <div className="mb-1 text-xs font-semibold text-muted">{t('Recommended actions')}</div>
              <ul className="space-y-1.5">
                {s.recommended_actions.map((a, k) => (
                  <li key={k} className="rounded-lg bg-panel-2 px-3 py-2">
                    <div className="font-medium">{a.action}</div>
                    <div className="text-xs text-muted">
                      {a.why}
                      <Cites ids={a.evidence} evidence={s!.evidence} />
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {s.unknowns.length > 0 && (
            <div>
              <div className="mb-1 text-xs font-semibold text-muted">{t('Not known from the evidence')}</div>
              <ul className="list-disc pl-5 text-muted">
                {s.unknowns.map((u, k) => (
                  <li key={k}>{u}</li>
                ))}
              </ul>
            </div>
          )}
          {s.invalidCitations.length > 0 && <p className="text-xs text-warn">{t('Removed citations to evidence that does not exist: {ids}', { ids: s.invalidCitations.join(', ') })}</p>}
          <p className="text-[11px] text-muted">{t('Generated by {model} {ago}. Advisory only — verify against the evidence before acting.', { model: s.model, ago: ago(s.createdAt) })}</p>
        </div>
      )}
    </Card>
  );
}

const TRANSITION_LABEL: Record<string, string> = { acknowledged: 'Acknowledge', investigating: 'Start investigating', resolved: 'Resolve', closed: 'Close', open: 'Reopen' };
const transitionLabel = (s: string) => t(TRANSITION_LABEL[s] ?? s);

function NewIncident({ onClose, onCreated }: { onClose: () => void; onCreated: (id: number) => void }) {
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [summary, setSummary] = useState('');
  const [assetId, setAssetId] = useState('');
  const { data } = useApi(() => api.get<{ assets: Asset[] }>('/assets'), []);
  return (
    <FormModal
      title={t('New incident')}
      submitLabel={t('Open incident')}
      onClose={onClose}
      onSubmit={async () => {
        const r = await api.post<{ id: number }>('/incidents', { title, severity, summary, assetId: assetId ? Number(assetId) : null });
        onCreated(r.id);
      }}
    >
      <Field label={t('Title')}>
        <Input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label={t('Severity')}>
          <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {['low', 'medium', 'high', 'critical'].map((s) => (
              <option key={s} value={s}>{sevLabel(s)}</option>
            ))}
          </Select>
        </Field>
        <Field label={t('Asset')}>
          <Select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
            <option value="">—</option>
            {data?.assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <Field label={t('What happened?')}>
        <Textarea rows={3} value={summary} onChange={(e) => setSummary(e.target.value)} />
      </Field>
    </FormModal>
  );
}

function IncidentDetail({ id, go }: { id: number; go: (p: string) => void }) {
  useTick();
  const { data, error, reload } = useApi(() => api.get<Detail>(`/incidents/${id}`), [id], ['incidents', 'alerts', 'findings']);
  const [transition, setTransition] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [linkForm, setLinkForm] = useState(false);
  const [owner, setOwner] = useState<string | null>(null);
  const i = data?.incident;

  if (error) return <ErrorNote error={error} />;
  if (!data || !i) return <Empty>{t('Loading…')}</Empty>;

  return (
    <>
      <PageHeader
        title={`#${i.id} ${i.title}`}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SevBadge sev={i.severity} /> <StateBadge state={i.status} /> {t('opened {date}', { date: stamp(i.openedAt) })} ({ago(i.openedAt)}) · {i.source === 'correlation' ? t('auto-correlated') : t('manual')}
            {i.assetName && <> · {t('asset')} {i.assetName}</>}
          </span>
        }
        actions={<Button onClick={() => go('incidents')}>← {t('All incidents')}</Button>}
      />
      {data.hint && <div className="mb-4 rounded-xl border border-ok/40 bg-ok/10 px-4 py-2.5 text-sm text-ok">{t(data.hint)}</div>}

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card title={t('Status & ownership')}>
            <div className="grid gap-2 text-xs sm:grid-cols-4">
              {[
                [t('Time to acknowledge'), i.acknowledgedAt ? duration(i.acknowledgedAt - i.openedAt) : '—'],
                [t('Time to resolve'), i.resolvedAt ? duration(i.resolvedAt - i.openedAt) : i.status === 'closed' ? '—' : t('{d} so far', { d: duration(Date.now() - i.openedAt) })],
                [t('Owner'), i.assignee ?? t('(unassigned)')],
                [t('Linked evidence'), String(data.links.length)],
              ].map(([k, v]) => (
                <div key={k} className="rounded-lg bg-panel-2 px-3 py-2">
                  <div className="text-muted">{k}</div>
                  <div className="text-sm font-medium">{v}</div>
                </div>
              ))}
            </div>
            {i.summary && <p className="mt-3 text-sm text-slate-300">{i.summary}</p>}
            {i.resolution && (
              <p className="mt-2 rounded-lg bg-ok/10 px-3 py-2 text-sm text-ok">
                <b>{t('Resolution')}:</b> {i.resolution}
              </p>
            )}
            <div className="mt-4 flex flex-wrap gap-2">
              {data.allowedTransitions.map((s) => (
                <Button key={s} variant={s === 'resolved' ? 'primary' : 'default'} onClick={() => (s === 'resolved' || s === 'open' ? setTransition(s) : api.post(`/incidents/${i.id}/status`, { status: s }).then(reload))}>
                  {transitionLabel(s)}
                </Button>
              ))}
              <Button variant="ghost" onClick={() => setOwner(i.assignee ?? '')}>
                {t('Set owner')}
              </Button>
            </div>
          </Card>

          <AiPanel incidentId={i.id} timeline={data.timeline} onDone={reload} />

          <Card title={t('Linked alerts & findings')} right={<Button variant="ghost" onClick={() => setLinkForm(true)}>{t('+ Link evidence')}</Button>}>
            {!data.links.length ? (
              <Empty>{t('No linked evidence yet.')}</Empty>
            ) : (
              <ul className="space-y-2">
                {data.links.map((l) => (
                  <li key={`${l.kind}${l.refId}`} className="rounded-lg bg-panel-2 px-3 py-2 text-sm">
                    <div className="flex items-start justify-between gap-2">
                      <a href={l.kind === 'finding' ? `#/security/${l.refId}` : '#/alerts'} className="hover:underline">
                        <span className="text-xs uppercase text-muted">{t(l.kind)} #{l.refId} · </span>
                        {l.title}
                      </a>
                      <span className="flex shrink-0 gap-1">
                        {l.severity && <SevBadge sev={l.severity} />}
                        {l.status && <StateBadge state={l.status} />}
                      </span>
                    </div>
                    {l.detail && <div className="mt-1 text-xs text-muted">{l.detail}</div>}
                    <div className="mt-1 flex justify-between gap-2 text-[11px] text-muted/80">
                      <span>{t('Why linked')}: {l.reason ? t(l.reason) : ''}</span>
                      <button
                        className="shrink-0 hover:text-bad"
                        onClick={async () => {
                          await api.del(`/incidents/${i.id}/links/${l.kind}/${l.refId}`);
                          reload();
                        }}
                      >
                        {t('unlink')}
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-[11px] text-muted">{t('Correlation links signals by asset and time proximity. It shows that things happened together — confirm the actual cause from the evidence.')}</p>
          </Card>
        </div>

        <Card title={t('Timeline')}>
          <form
            className="mb-4 flex gap-2"
            onSubmit={async (e) => {
              e.preventDefault();
              if (!note.trim()) return;
              await api.post(`/incidents/${i.id}/notes`, { message: note });
              setNote('');
              reload();
            }}
          >
            <Input placeholder={t('Add a note (what you checked, what you found)…')} value={note} onChange={(e) => setNote(e.target.value)} />
            <Button disabled={!note.trim()}>{t('Add')}</Button>
          </form>
          <ol className="relative ml-2 space-y-3 border-l border-line pl-4">
            {[...data.timeline].reverse().map((e) => (
              <li key={e.id} className="relative text-sm">
                <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full" style={{ background: e.type === 'status_change' ? '#8b5cf6' : e.type === 'note' ? '#38bdf8' : e.type === 'created' ? SEV_COLOR[i.severity] : '#475569' }} />
                <div className="text-xs text-muted">
                  {stamp(e.ts)} · {tk(`event.${e.type}`, e.type.replace('_', ' '))}
                  {e.type === 'status_change' && (
                    <>
                      {' '}
                      {e.fromStatus ? stateLabel(e.fromStatus) : ''} → <b className="text-slate-200">{e.toStatus ? stateLabel(e.toStatus) : ''}</b>
                    </>
                  )}
                </div>
                {e.message && <div className="mt-0.5 whitespace-pre-wrap">{e.type === 'ai_summary' ? t('AI summary created (see the AI summary card).') : e.message}</div>}
              </li>
            ))}
          </ol>
        </Card>
      </div>

      {transition && (
        <FormModal
          title={transition === 'resolved' ? t('Resolve incident') : t('Reopen incident')}
          submitLabel={transitionLabel(transition)}
          onClose={() => {
            setTransition(null);
            setReason('');
          }}
          onSubmit={async () => {
            await api.post(`/incidents/${i.id}/status`, { status: transition, reason });
            setReason('');
            reload();
          }}
        >
          <Field label={transition === 'resolved' ? t('Resolution — what was the cause and what fixed it?') : t('Why reopen?')}>
            <Textarea rows={4} value={reason} onChange={(e) => setReason(e.target.value)} autoFocus />
          </Field>
        </FormModal>
      )}
      {owner !== null && (
        <FormModal
          title={t('Set owner')}
          onClose={() => setOwner(null)}
          onSubmit={async () => {
            await api.put(`/incidents/${i.id}`, { assignee: owner });
            reload();
          }}
        >
          <Field label={t('Owner (free text)')}>
            <Input value={owner} onChange={(e) => setOwner(e.target.value)} autoFocus />
          </Field>
        </FormModal>
      )}
      {linkForm && <LinkEvidence incidentId={i.id} onClose={() => setLinkForm(false)} onDone={reload} />}
    </>
  );
}

function LinkEvidence({ incidentId, onClose, onDone }: { incidentId: number; onClose: () => void; onDone: () => void }) {
  const [kind, setKind] = useState<'finding' | 'alert'>('finding');
  const [refId, setRefId] = useState('');
  const findings = useApi(() => api.get<{ findings: { id: number; title: string; severity: string }[] }>('/security/findings?status=all&limit=100'), []);
  const alerts = useApi(() => api.get<{ events: { id: number; title: string; severity: string }[] }>('/alerts/events?status=all&limit=100'), []);
  const options = kind === 'finding' ? findings.data?.findings ?? [] : alerts.data?.events ?? [];
  return (
    <FormModal
      title={t('Link evidence')}
      submitLabel={t('Link')}
      onClose={onClose}
      onSubmit={async () => {
        await api.post(`/incidents/${incidentId}/links`, { kind, refId: Number(refId), reason: 'Linked manually by admin' });
        onDone();
      }}
    >
      <Field label={t('Type')}>
        <Select
          value={kind}
          onChange={(e) => {
            setKind(e.target.value as 'finding' | 'alert');
            setRefId('');
          }}
        >
          <option value="finding">{t('Security finding')}</option>
          <option value="alert">{t('Alert')}</option>
        </Select>
      </Field>
      <Field label={t('Item')}>
        <Select value={refId} onChange={(e) => setRefId(e.target.value)}>
          <option value="">{t('Choose…')}</option>
          {options.map((o) => (
            <option key={o.id} value={o.id}>
              #{o.id} [{sevLabel(o.severity)}] {o.title}
            </option>
          ))}
        </Select>
      </Field>
    </FormModal>
  );
}

/** Action bar for the selected incidents: acknowledge or resolve several at once. */
function IncidentBulkBar({ ids, onDone }: { ids: number[]; onDone: () => void }) {
  const [resolving, setResolving] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [skipped, setSkipped] = useState(0);

  async function apply(status: string, r?: string) {
    setBusy(true);
    setErr(null);
    try {
      const res = await api.post<{ updated: number; skipped: number }>('/incidents/bulk-status', { ids, status, reason: r });
      setResolving(false);
      setReason('');
      setSkipped(res.skipped);
      if (!res.skipped) onDone();
    } catch (e) {
      setErr(e instanceof Error ? t(e.message) : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fade-in space-y-2 border-b border-line bg-panel-2/60 px-4 py-3 text-sm">
      <ErrorNote error={err} />
      {skipped > 0 && <div className="text-xs text-warn">{t('{n} could not take this step (already further along) and were left as they are.', { n: skipped })}</div>}
      {resolving ? (
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            void apply('resolved', reason.trim());
          }}
        >
          <Field label={`${t('{n} selected', { n: ids.length })} — ${t('How was it resolved?')}`}>
            <Textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} autoFocus placeholder={t('e.g. False alarm — the PC was busy, the sites were fine')} />
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={() => setResolving(false)}>
              {t('Cancel')}
            </Button>
            <Button variant="primary" disabled={!reason.trim() || busy}>
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
          <Button variant="primary" disabled={busy} onClick={() => setResolving(true)}>
            {t('Resolve')}
          </Button>
          <button type="button" className="ml-auto text-xs text-muted hover:underline" onClick={onDone}>
            {t('Clear selection')}
          </button>
        </div>
      )}
    </div>
  );
}

export default function IncidentsPage({ selectedId, go }: { selectedId: number | null; go: (p: string) => void }) {
  useTick();
  const [status, setStatus] = useState('active');
  const [create, setCreate] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const { data, error } = useApi(() => api.get<{ incidents: Incident[] }>(`/incidents?status=${status}`), [status], ['incidents']);
  const visible = data?.incidents ?? [];
  // Keep only selections that are still in the list (an incident may move out of this filter).
  const ids = visible.filter((i) => selected.has(i.id)).map((i) => i.id);
  const allOn = visible.length > 0 && ids.length === visible.length;
  const toggle = (id: number) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  if (selectedId) return <IncidentDetail id={selectedId} go={go} />;

  return (
    <>
      <PageHeader title={t('Incidents')} subtitle={t('Open → Acknowledged → Investigating → Resolved → Closed, with evidence and a full timeline')} actions={<Button variant="primary" onClick={() => setCreate(true)}>{t('+ New incident')}</Button>} />
      <ErrorNote error={error} />
      <Card
        pad={false}
        title={t('Incidents')}
        right={
          <select className="rounded-lg border border-line bg-panel-2 px-2 py-1 text-xs" value={status} onChange={(e) => { setStatus(e.target.value); setSelected(new Set()); }}>
            <option value="active">{t('Active')}</option>
            <option value="resolved">{t('state.resolved')}</option>
            <option value="closed">{t('state.closed')}</option>
            <option value="all">{t('All')}</option>
          </select>
        }
      >
        {!data?.incidents.length ? (
          <Empty>{t('No incidents for this filter.')}</Empty>
        ) : (
          <div className="overflow-x-auto">
            {ids.length > 0 && <IncidentBulkBar ids={ids} onDone={() => setSelected(new Set())} />}
            <table className="w-full text-sm">
              <thead className="border-b border-line">
                <tr>
                  <Th className="w-8">
                    <input type="checkbox" aria-label={t('Select all')} checked={allOn} onChange={() => setSelected(allOn ? new Set() : new Set(visible.map((i) => i.id)))} className="h-4 w-4 cursor-pointer" />
                  </Th>
                  <Th>{t('Severity')}</Th>
                  <Th>{t('Incident')}</Th>
                  <Th>{t('Status')}</Th>
                  <Th>{t('Evidence')}</Th>
                  <Th>{t('Opened')}</Th>
                  <Th>{t('Duration')}</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.incidents.map((i) => (
                  <tr key={i.id} className={`cursor-pointer hover:bg-panel-2/60 ${selected.has(i.id) ? 'bg-accent/5' : ''}`} onClick={() => go(`incidents/${i.id}`)}>
                    <Td className="w-8">
                      <input type="checkbox" aria-label={`#${i.id}`} checked={selected.has(i.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(i.id)} className="h-4 w-4 cursor-pointer" />
                    </Td>
                    <Td>
                      <SevBadge sev={i.severity} />
                    </Td>
                    <Td>
                      <div>
                        #{i.id} {i.title}
                      </div>
                      <div className="text-xs text-muted">
                        {i.source === 'correlation' ? t('auto-correlated') : t('manual')}
                        {i.assignee ? ` · ${t('owner')} ${i.assignee}` : ''}
                      </div>
                    </Td>
                    <Td>
                      <StateBadge state={i.status} />
                    </Td>
                    <Td className="text-xs">{i.linkCount ?? 0}</Td>
                    <Td className="whitespace-nowrap text-xs text-muted">{ago(i.openedAt)}</Td>
                    <Td className="whitespace-nowrap text-xs">{duration((i.resolvedAt ?? Date.now()) - i.openedAt)}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {create && <NewIncident onClose={() => setCreate(false)} onCreated={(id) => go(`incidents/${id}`)} />}
    </>
  );
}
