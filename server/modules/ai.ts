import Anthropic from '@anthropic-ai/sdk';
import { betaZodOutputFormat } from '@anthropic-ai/sdk/helpers/beta/zod';
import { Router } from 'express';
import { z } from 'zod';
import { all, get } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { clientIp, HttpError, idParam } from '../lib/http.js';
import { parseJson } from '../lib/util.js';
import { event } from './incidents.js';

/**
 * AI-assisted investigation (Blueprint Phase 4). Off unless ANTHROPIC_API_KEY is set.
 * Claude only reads the evidence SENTINEL already holds for one incident and must cite
 * evidence ids for every statement; ids it cites that do not exist are removed and reported.
 * The result is advisory: it is stored in the incident timeline, nothing is changed automatically.
 */

const MODEL = 'claude-opus-5-5';
const MAX_EVENTS = 40;

export const aiEnabled = () => !!process.env.ANTHROPIC_API_KEY;

let client: Anthropic | null = null;
const getClient = () => (client ??= new Anthropic());

const Cited = z.object({ text: z.string(), evidence: z.array(z.string()) });
const SummarySchema = z.object({
  summary: z.string(),
  timeline: z.array(Cited),
  likely_cause: z.object({ text: z.string(), evidence: z.array(z.string()), confidence: z.enum(['low', 'medium', 'high']) }),
  recommended_actions: z.array(z.object({ action: z.string(), why: z.string(), evidence: z.array(z.string()) })),
  unknowns: z.array(z.string()),
});
export type AiSummary = z.infer<typeof SummarySchema>;

type EvidenceItem = { id: string; kind: string; ts: number | null; title: string; detail: string };

/** Collect everything SENTINEL knows about the incident, each item with a citable id. */
function collectEvidence(incidentId: number) {
  const i = get<{ id: number; title: string; severity: string; status: string; summary: string | null; opened_at: number; asset_name: string | null; source: string }>(
    'SELECT i.*, a.name AS asset_name FROM incidents i LEFT JOIN assets a ON a.id = i.asset_id WHERE i.id = ?', incidentId,
  );
  if (!i) throw new HttpError(404, 'Not found');
  const items: EvidenceItem[] = [];
  const links = all<{ kind: string; ref_id: number }>('SELECT kind, ref_id FROM incident_links WHERE incident_id = ? ORDER BY linked_at', incidentId);
  const logIds = new Set<number>();
  for (const l of links) {
    if (l.kind === 'alert') {
      const a = get<{ title: string; detail: string | null; severity: string; status: string; triggered_at: number; resolved_at: number | null }>('SELECT * FROM alert_events WHERE id = ?', l.ref_id);
      if (a) items.push({ id: `A${l.ref_id}`, kind: 'alert', ts: a.triggered_at, title: `[${a.severity}] ${a.title} (${a.status})`, detail: `${a.detail ?? ''}${a.resolved_at ? ` · resolved at ${new Date(a.resolved_at).toISOString()}` : ''}` });
    } else {
      const f = get<{ title: string; summary: string; severity: string; status: string; first_seen: number; last_seen: number; count: number; evidence: string; rule_id: string }>('SELECT * FROM security_findings WHERE id = ?', l.ref_id);
      if (!f) continue;
      const ev = parseJson<{ eventIds?: number[]; condition?: string }>(f.evidence, {});
      items.push({ id: `F${l.ref_id}`, kind: 'finding', ts: f.last_seen, title: `[${f.severity}] ${f.title} (rule ${f.rule_id}, ${f.status})`, detail: `${f.summary} · condition: ${ev.condition ?? '-'} · ${f.count} event(s), first ${new Date(f.first_seen).toISOString()}` });
      for (const id of ev.eventIds ?? []) logIds.add(id);
    }
  }
  const logs = logIds.size
    ? all<{ id: number; ts: number; event_id: number; channel: string; summary: string }>(
        `SELECT id, ts, event_id, channel, summary FROM log_events WHERE id IN (${[...logIds].slice(-MAX_EVENTS).map(() => '?').join(',')}) ORDER BY ts`,
        ...[...logIds].slice(-MAX_EVENTS),
      )
    : [];
  for (const e of logs) items.push({ id: `E${e.id}`, kind: 'log event', ts: e.ts, title: `Windows event ${e.event_id} (${e.channel})`, detail: e.summary });
  const notes = all<{ id: number; ts: number; type: string; message: string | null }>("SELECT id, ts, type, message FROM incident_events WHERE incident_id = ? AND type IN ('note','status_change','created') ORDER BY ts", incidentId);
  for (const n of notes) if (n.message) items.push({ id: `T${n.id}`, kind: `timeline ${n.type}`, ts: n.ts, title: n.type, detail: n.message });
  return { incident: i, items };
}

const SYSTEM = `You help the single administrator of a home security monitoring system (SENTINEL) understand one incident.
You receive the incident and a list of evidence items, each with an id such as A12 (alert), F5 (security finding), E301 (Windows log event) or T7 (timeline note).
Rules:
- Use only the evidence given. Do not invent events, hosts, users or causes. If the evidence does not show something, say it is unknown.
- Every statement in timeline, likely_cause and recommended_actions must cite the ids it relies on in its evidence array. Cite only ids from the list.
- Correlation in SENTINEL means signals happened close together on the same machine; it is not proof that one caused another. Keep that distinction.
- Write all text in Thai, plain and practical, for a non-specialist. Keep technical names (event ids, file paths, service names) as they are.
- Recommended actions must be safe, concrete steps the owner can do themselves (check, verify, change a setting). Never suggest anything destructive without saying to back up first.`;

export const aiRouter = Router();

aiRouter.get('/ai/status', (_req, res) => res.json({ enabled: aiEnabled(), model: MODEL }));

aiRouter.post('/incidents/:id/ai-summary', async (req, res) => {
  if (!aiEnabled()) throw new HttpError(503, 'AI summary is off: set ANTHROPIC_API_KEY in .env and restart SENTINEL');
  const id = idParam(req);
  const { incident, items } = collectEvidence(id);
  if (!items.length) throw new HttpError(400, 'This incident has no evidence to summarise yet');

  const evidenceText = items
    .map((x) => `${x.id} | ${x.kind} | ${x.ts ? new Date(x.ts).toISOString() : '-'} | ${x.title} | ${x.detail}`.slice(0, 1200))
    .join('\n');
  const prompt = `Incident #${incident.id}: ${incident.title}
Severity: ${incident.severity} · status: ${incident.status} · asset: ${incident.asset_name ?? '-'} · opened ${new Date(incident.opened_at).toISOString()} (${incident.source})
${incident.summary ? `Description: ${incident.summary}\n` : ''}
Evidence (id | kind | time UTC | title | detail):
${evidenceText}`;

  let parsed: AiSummary;
  try {
    const response = await getClient().beta.messages.parse({
      model: MODEL,
      max_tokens: 16000,
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      output_config: { effort: 'medium', format: betaZodOutputFormat(SummarySchema) },
      system: SYSTEM,
      messages: [{ role: 'user', content: prompt }],
    });
    if (response.stop_reason === 'refusal') throw new HttpError(502, 'Claude declined to summarise this incident');
    if (response.stop_reason === 'max_tokens' || !response.parsed_output) throw new HttpError(502, 'The AI response was incomplete; try again');
    parsed = response.parsed_output;
  } catch (e) {
    if (e instanceof HttpError) throw e;
    if (e instanceof Anthropic.AuthenticationError) throw new HttpError(502, 'Anthropic API key was rejected — check ANTHROPIC_API_KEY');
    if (e instanceof Anthropic.RateLimitError) throw new HttpError(429, 'Anthropic rate limit reached — try again in a minute');
    if (e instanceof Anthropic.APIError) throw new HttpError(502, `Anthropic API error ${e.status ?? ''}: ${e.message}`.trim());
    throw new HttpError(502, `AI request failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Keep only citations that point at real evidence; report the rest.
  const known = new Set(items.map((x) => x.id));
  const invalid = new Set<string>();
  const clean = (ids: string[]) => ids.filter((x) => (known.has(x) ? true : (invalid.add(x), false)));
  parsed.timeline.forEach((t) => (t.evidence = clean(t.evidence)));
  parsed.likely_cause.evidence = clean(parsed.likely_cause.evidence);
  parsed.recommended_actions.forEach((a) => (a.evidence = clean(a.evidence)));

  const result = { ...parsed, invalidCitations: [...invalid], evidence: items.map(({ id: eid, kind, title }) => ({ id: eid, kind, title })), model: MODEL, createdAt: Date.now() };
  event(id, 'ai_summary', JSON.stringify(result));
  audit('incident.ai_summary', { ip: clientIp(req), resourceType: 'incident', resourceId: id, detail: { model: MODEL, evidenceItems: items.length, invalidCitations: invalid.size } });
  publish('incidents');
  res.json(result);
});
