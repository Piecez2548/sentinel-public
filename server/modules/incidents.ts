import { Router } from 'express';
import { all, get, run, tx } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { body, clientIp, HttpError, idParam, num, oneOf, str } from '../lib/http.js';
import { escHtml, fmtDuration, HOUR, maxSeverity, MIN, parseJson, SEVERITIES, sevRank } from '../lib/util.js';
import { alertTitleText, L, ruleText, sevText } from '../lib/i18n.js';
import { enqueue } from './notify.js';

/** Incident lifecycle (FR-13/15) and evidence-based correlation (FR-14). */

export const STATUSES = ['open', 'acknowledged', 'investigating', 'resolved', 'closed'] as const;
type Status = (typeof STATUSES)[number];

const TRANSITIONS: Record<Status, Status[]> = {
  open: ['acknowledged', 'investigating', 'resolved'],
  acknowledged: ['investigating', 'resolved'],
  investigating: ['resolved'],
  resolved: ['closed', 'open'],
  closed: ['open'],
};

type IncidentRow = {
  id: number; title: string; severity: string; status: Status; summary: string | null; assignee: string | null; source: string;
  asset_id: number | null; opened_at: number; acknowledged_at: number | null; resolved_at: number | null; closed_at: number | null;
  resolution: string | null; asset_name?: string | null;
};

export function event(incidentId: number, type: string, message: string | null, from?: string, to?: string) {
  run('INSERT INTO incident_events (incident_id, type, from_status, to_status, message, ts) VALUES (?, ?, ?, ?, ?, ?)', incidentId, type, from ?? null, to ?? null, message, Date.now());
}

function createIncident(opts: { title: string; severity: string; summary?: string | null; assetId?: number | null; source: 'manual' | 'correlation' }): number {
  const now = Date.now();
  const r = run(
    'INSERT INTO incidents (title, severity, status, summary, source, asset_id, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    opts.title, opts.severity, 'open', opts.summary ?? null, opts.source, opts.assetId ?? null, now,
  );
  const id = Number(r.lastInsertRowid);
  event(id, 'created', opts.source === 'correlation' ? 'Opened automatically by correlation' : 'Opened manually', undefined, 'open');
  return id;
}

function link(incidentId: number, kind: 'alert' | 'finding', refId: number, reason: string) {
  const r = run('INSERT OR IGNORE INTO incident_links (incident_id, kind, ref_id, reason, linked_at) VALUES (?, ?, ?, ?, ?)', incidentId, kind, refId, reason, Date.now());
  if (r.changes) event(incidentId, 'link', `Linked ${kind} #${refId}: ${reason}`);
  return r.changes > 0;
}

/* ---------- correlation ---------- */

const CORRELATION_WINDOW = 30 * MIN;
const ATTACH_WINDOW = 6 * HOUR;

type Signal = { kind: 'alert' | 'finding'; id: number; rule: string; assetId: number | null; assetName: string | null; ts: number; severity: string; title: string };

/** One line per signal for chat: the finding's plain-language headline when it has one, else rule name / title. */
function headline(s: Signal, th: boolean): string {
  if (s.kind !== 'finding') return th ? alertTitleText(s.title) : s.title;
  const ev = get<{ evidence: string }>('SELECT evidence FROM security_findings WHERE id = ?', s.id)?.evidence;
  const d = parseJson<{ details?: { headlineTh?: string; headlineEn?: string } }>(ev ?? '{}', {}).details;
  const h = th ? d?.headlineTh : d?.headlineEn;
  if (h) return h;
  const ruleId = s.rule.replace(/^finding:/, '');
  return th ? `${ruleText(ruleId, ruleId)}: ${s.title}` : s.title;
}

/**
 * Groups recent alerts/findings that are not yet part of an incident.
 * Rule: same asset + within 30 minutes. Opens an incident when signals come
 * from ≥ 2 different rules, or any single critical one. Proximity is recorded as the
 * reason — it is NOT presented as proof of cause.
 */
export function correlate() {
  const since = Date.now() - CORRELATION_WINDOW;
  const signals: Signal[] = [
    ...all<{ id: number; rule_id: number | null; asset_id: number | null; asset_name: string | null; triggered_at: number; severity: string; title: string }>(
      `SELECT e.id, e.rule_id, e.asset_id, a.name AS asset_name, e.triggered_at, e.severity, e.title FROM alert_events e LEFT JOIN assets a ON a.id = e.asset_id
       WHERE e.triggered_at > ? AND e.asset_id IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM incident_links l WHERE l.kind = 'alert' AND l.ref_id = e.id)`,
      since,
    ).map((r) => ({ kind: 'alert' as const, id: r.id, rule: `alert:${r.rule_id}`, assetId: r.asset_id, assetName: r.asset_name, ts: r.triggered_at, severity: r.severity, title: r.title })),
    ...all<{ id: number; rule_id: string; asset_id: number | null; asset_name: string | null; last_seen: number; severity: string; title: string }>(
      `SELECT f.id, f.rule_id, f.asset_id, a.name AS asset_name, f.last_seen, f.severity, f.title FROM security_findings f LEFT JOIN assets a ON a.id = f.asset_id
       WHERE f.last_seen > ? AND f.asset_id IS NOT NULL AND f.status IN ('open','acknowledged') AND f.severity != 'low'
         AND NOT EXISTS (SELECT 1 FROM incident_links l WHERE l.kind = 'finding' AND l.ref_id = f.id)`,
      since,
    ).map((r) => ({ kind: 'finding' as const, id: r.id, rule: `finding:${r.rule_id}`, assetId: r.asset_id, assetName: r.asset_name, ts: r.last_seen, severity: r.severity, title: r.title })),
  ];
  if (!signals.length) return;

  const byAsset = new Map<number, Signal[]>();
  for (const s of signals) byAsset.set(s.assetId!, [...(byAsset.get(s.assetId!) ?? []), s]);

  for (const [assetId, group] of byAsset) {
    group.sort((a, b) => a.ts - b.ts);
    // Attach only to an incident that is still "active in time": opened within ATTACH_WINDOW
    // AND its newest linked signal is within the correlation window of this group.
    const open = get<IncidentRow>(
      `SELECT i.* FROM incidents i
       WHERE i.asset_id = ? AND i.status IN ('open','acknowledged','investigating') AND i.opened_at > ?
         AND COALESCE((SELECT MAX(linked_at) FROM incident_links l WHERE l.incident_id = i.id), i.opened_at) > ?
       ORDER BY i.opened_at DESC LIMIT 1`,
      assetId, Date.now() - ATTACH_WINDOW, group[0].ts - CORRELATION_WINDOW,
    );
    const hasCritical = group.some((s) => s.severity === 'critical');
    // Several hits of the SAME rule (e.g. two services installed by one installer) are not an incident by themselves.
    const distinctRules = new Set(group.map((s) => s.rule)).size;
    if (!open && distinctRules < 2 && !hasCritical) continue;

    tx(() => {
      let incidentId: number;
      let anchor: number;
      if (open) {
        incidentId = open.id;
        anchor = open.opened_at;
      } else {
        const top = [...group].sort((a, b) => sevRank(b.severity) - sevRank(a.severity))[0];
        const severity = group.reduce((m, s) => maxSeverity(m, s.severity), 'low');
        incidentId = createIncident({
          title: `${group[0].assetName}: ${top.title}${group.length > 1 ? ` (+${group.length - 1} related)` : ''}`,
          severity,
          assetId,
          source: 'correlation',
          summary: `Correlated ${group.length} signal(s) on the same asset within ${CORRELATION_WINDOW / MIN} minutes. Correlation shows co-occurrence only; confirm the cause from the evidence.`,
        });
        anchor = group[0].ts;
        const ordered = [...group].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
        const list = (th: boolean) => ordered.slice(0, 6).map((s) => `• ${escHtml(headline(s, th))}`).join('\n') + (ordered.length > 6 ? `\n• … +${ordered.length - 6}` : '');
        const asset = escHtml(group[0].assetName ?? '');
        // A single alert/finding already sent its own message; an incident message would only repeat it.
        if (group.length > 1) enqueue('incident', `incident:${incidentId}`, L(
          `🚨 <b>Incident opened [${sevText(severity)}] — ${asset}</b>\n${group.length > 1 ? `${group.length} things happened together on this machine:` : 'Serious issue found:'}\n${list(false)}\n\n👉 Details and resolution notes: <b>Incidents</b> page`,
          `🚨 <b>เปิดเหตุการณ์ [${sevText(severity)}] — ${asset}</b>\n${group.length > 1 ? `มี ${group.length} เรื่องเกิดพร้อมกันบนเครื่องนี้:` : 'พบเรื่องร้ายแรง:'}\n${list(true)}\n\n👉 ดูรายละเอียดและบันทึกการแก้ไขในหน้า <b>เหตุการณ์</b>`,
        ));
      }
      for (const s of group) {
        const delta = Math.abs(s.ts - anchor);
        link(incidentId, s.kind, s.id, `Same asset "${s.assetName}", ${fmtDuration(delta)} ${s.ts >= anchor ? 'after' : 'before'} the first signal (time + asset proximity, not proof of cause)`);
        if (open && sevRank(s.severity) > sevRank(open.severity)) {
          run('UPDATE incidents SET severity = ? WHERE id = ?', s.severity, incidentId);
          event(incidentId, 'severity', `Severity raised to ${s.severity} by ${s.kind} #${s.id}`);
        }
      }
    });
    publish('incidents');
  }
}

/* ---------- API ---------- */

export const incidentsRouter = Router();

const dto = (i: IncidentRow) => ({
  id: i.id,
  title: i.title,
  severity: i.severity,
  status: i.status,
  summary: i.summary,
  assignee: i.assignee,
  source: i.source,
  assetId: i.asset_id,
  assetName: i.asset_name ?? null,
  openedAt: i.opened_at,
  acknowledgedAt: i.acknowledged_at,
  resolvedAt: i.resolved_at,
  closedAt: i.closed_at,
  resolution: i.resolution,
});

const SELECT = 'SELECT i.*, a.name AS asset_name FROM incidents i LEFT JOIN assets a ON a.id = i.asset_id';

incidentsRouter.get('/', (req, res) => {
  const status = String(req.query.status ?? 'all');
  const where = status === 'active' ? "WHERE i.status IN ('open','acknowledged','investigating')" : (STATUSES as readonly string[]).includes(status) ? 'WHERE i.status = ?' : '';
  const params = where.includes('?') ? [status] : [];
  const rows = all<IncidentRow>(`${SELECT} ${where} ORDER BY i.opened_at DESC LIMIT ?`, ...params, Math.min(Number(req.query.limit) || 100, 500));
  const counts = new Map(all<{ incident_id: number; n: number }>('SELECT incident_id, COUNT(*) AS n FROM incident_links GROUP BY incident_id').map((r) => [r.incident_id, r.n]));
  res.json({ incidents: rows.map((r) => ({ ...dto(r), linkCount: counts.get(r.id) ?? 0 })) });
});

incidentsRouter.get('/:id', (req, res) => {
  const i = get<IncidentRow>(`${SELECT} WHERE i.id = ?`, idParam(req));
  if (!i) throw new HttpError(404, 'Not found');
  const events = all<{ id: number; type: string; from_status: string | null; to_status: string | null; message: string | null; ts: number }>(
    'SELECT * FROM incident_events WHERE incident_id = ? ORDER BY ts, id', i.id,
  );
  const links = all<{ kind: string; ref_id: number; reason: string | null; linked_at: number }>('SELECT * FROM incident_links WHERE incident_id = ? ORDER BY linked_at', i.id);
  const items = links.map((l) => {
    if (l.kind === 'alert') {
      const a = get<{ title: string; severity: string; status: string; triggered_at: number; resolved_at: number | null; detail: string | null }>('SELECT title, severity, status, triggered_at, resolved_at, detail FROM alert_events WHERE id = ?', l.ref_id);
      return { kind: 'alert', refId: l.ref_id, reason: l.reason, linkedAt: l.linked_at, title: a?.title ?? '(deleted)', severity: a?.severity ?? null, status: a?.status ?? null, ts: a?.triggered_at ?? null, detail: a?.detail ?? null };
    }
    const f = get<{ title: string; severity: string; status: string; last_seen: number; summary: string }>('SELECT title, severity, status, last_seen, summary FROM security_findings WHERE id = ?', l.ref_id);
    return { kind: 'finding', refId: l.ref_id, reason: l.reason, linkedAt: l.linked_at, title: f?.title ?? '(deleted)', severity: f?.severity ?? null, status: f?.status ?? null, ts: f?.last_seen ?? null, detail: f?.summary ?? null };
  });
  const allAlertsResolved = items.filter((x) => x.kind === 'alert').every((x) => x.status === 'resolved');
  res.json({
    incident: dto(i),
    timeline: events.map((e) => ({ id: e.id, type: e.type, fromStatus: e.from_status, toStatus: e.to_status, message: e.message, ts: e.ts })),
    links: items,
    hint: ['open', 'acknowledged', 'investigating'].includes(i.status) && items.some((x) => x.kind === 'alert') && allAlertsResolved ? 'All linked alerts have recovered — consider resolving this incident.' : null,
    allowedTransitions: TRANSITIONS[i.status],
  });
});

incidentsRouter.post('/', (req, res) => {
  const b = body(req);
  const assetId = b.assetId ? num(b.assetId, 'Asset', { int: true })! : null;
  const id = createIncident({
    title: str(b.title, 'Title', { min: 3, max: 200 })!,
    severity: oneOf(b.severity ?? 'medium', 'Severity', SEVERITIES)!,
    summary: str(b.summary, 'Summary', { optional: true, max: 4000 }) ?? null,
    assetId,
    source: 'manual',
  });
  audit('incident.created', { ip: clientIp(req), resourceType: 'incident', resourceId: id });
  publish('incidents');
  res.status(201).json({ id });
});

incidentsRouter.put('/:id', (req, res) => {
  const id = idParam(req);
  const i = get<IncidentRow>('SELECT * FROM incidents WHERE id = ?', id);
  if (!i) throw new HttpError(404, 'Not found');
  const b = body(req);
  const title = str(b.title, 'Title', { optional: true, min: 3, max: 200 }) ?? i.title;
  const severity = b.severity !== undefined ? oneOf(b.severity, 'Severity', SEVERITIES)! : i.severity;
  const summary = b.summary !== undefined ? (str(b.summary, 'Summary', { optional: true, max: 4000 }) ?? null) : i.summary;
  const assignee = b.assignee !== undefined ? (str(b.assignee, 'Assignee', { optional: true, max: 80 }) ?? null) : i.assignee;
  run('UPDATE incidents SET title = ?, severity = ?, summary = ?, assignee = ? WHERE id = ?', title, severity, summary, assignee, id);
  if (severity !== i.severity) event(id, 'severity', `Severity changed ${i.severity} → ${severity}`);
  if (assignee !== i.assignee) event(id, 'assignee', `Owner set to ${assignee ?? '(none)'}`);
  audit('incident.updated', { ip: clientIp(req), resourceType: 'incident', resourceId: id, detail: { title, severity, assignee } });
  publish('incidents');
  res.json({ ok: true });
});

function readIncidentStatus(b: Record<string, unknown>) {
  const to = oneOf(b.status, 'Status', STATUSES)!;
  const reason = str(b.reason, 'Reason', { optional: true, max: 2000 });
  if ((to === 'resolved' || to === 'open') && !reason) throw new HttpError(400, to === 'resolved' ? 'Describe the resolution' : 'Explain why you are reopening');
  return { to, reason };
}

/** Moves one incident to `to`; false when that step is not allowed from its current state. */
function changeIncidentStatus(i: IncidentRow, to: Status, reason: string | null | undefined, ip: string): boolean {
  if (!TRANSITIONS[i.status].includes(to)) return false;
  const id = i.id;
  const now = Date.now();
  tx(() => {
    run(
      `UPDATE incidents SET status = ?,
         acknowledged_at = CASE WHEN ? IN ('acknowledged','investigating') AND acknowledged_at IS NULL THEN ? ELSE acknowledged_at END,
         resolved_at = CASE WHEN ? = 'resolved' THEN ? WHEN ? = 'open' THEN NULL ELSE resolved_at END,
         closed_at = CASE WHEN ? = 'closed' THEN ? WHEN ? = 'open' THEN NULL ELSE closed_at END,
         resolution = CASE WHEN ? = 'resolved' THEN ? ELSE resolution END
       WHERE id = ?`,
      to, to, now, to, now, to, to, now, to, to, reason ?? null, id,
    );
    event(id, 'status_change', reason ?? null, i.status, to);
  });
  audit('incident.status', { ip, resourceType: 'incident', resourceId: id, detail: { from: i.status, to, reason } });
  return true;
}

export const AUTO_RESOLVE_QUIET = 30 * MIN;

/**
 * Closes auto-correlated incidents that recovered on their own: every linked signal is an alert, every one
 * of them has resolved, and nothing new happened for 30 minutes (e.g. "site down" while the PC was busy).
 * Anything with a security finding, anything the owner is investigating, and manual incidents are left alone.
 */
export function autoResolveRecovered(now = Date.now()): number {
  const candidates = all<IncidentRow>(
    `SELECT i.* FROM incidents i
      WHERE i.source = 'correlation' AND i.status IN ('open', 'acknowledged')
        AND EXISTS (SELECT 1 FROM incident_links l WHERE l.incident_id = i.id)
        AND NOT EXISTS (SELECT 1 FROM incident_links l WHERE l.incident_id = i.id AND l.kind != 'alert')
        AND NOT EXISTS (SELECT 1 FROM incident_links l JOIN alert_events e ON e.id = l.ref_id
                         WHERE l.incident_id = i.id AND l.kind = 'alert' AND e.status != 'resolved')`,
  );
  let n = 0;
  for (const i of candidates) {
    const last = get<{ t: number | null }>(
      `SELECT MAX(MAX(COALESCE(e.resolved_at, 0)), MAX(l.linked_at)) AS t FROM incident_links l JOIN alert_events e ON e.id = l.ref_id WHERE l.incident_id = ?`,
      i.id,
    )?.t;
    if (last == null || now - last < AUTO_RESOLVE_QUIET) continue;
    const reason = L(
      `Closed automatically: every linked alert recovered on its own and nothing new happened for ${AUTO_RESOLVE_QUIET / MIN} minutes.`,
      `ปิดอัตโนมัติ — การแจ้งเตือนทุกรายการกลับมาปกติเอง และไม่มีอะไรเกิดซ้ำอีก ${AUTO_RESOLVE_QUIET / MIN} นาที`,
    );
    if (changeIncidentStatus(i, 'resolved', reason, 'system')) n++;
  }
  if (n) publish('incidents');
  return n;
}

incidentsRouter.post('/:id/status', (req, res) => {
  const id = idParam(req);
  const i = get<IncidentRow>('SELECT * FROM incidents WHERE id = ?', id);
  if (!i) throw new HttpError(404, 'Not found');
  const { to, reason } = readIncidentStatus(body(req));
  if (!changeIncidentStatus(i, to, reason, clientIp(req))) throw new HttpError(409, `Cannot go from ${i.status} to ${to}`);
  publish('incidents');
  res.json({ ok: true });
});

/** Several incidents at once (e.g. acknowledge or resolve a burst of false alarms). Ones that cannot take the step are skipped. */
incidentsRouter.post('/bulk-status', (req, res) => {
  const b = body(req);
  const { to, reason } = readIncidentStatus(b);
  const raw = b.ids;
  if (!Array.isArray(raw) || !raw.length || raw.length > 500 || !raw.every((x) => Number.isInteger(x) && x > 0)) {
    throw new HttpError(400, 'ids must be a list of 1–500 incident ids');
  }
  const ip = clientIp(req);
  let updated = 0;
  for (const id of new Set(raw as number[])) {
    const i = get<IncidentRow>('SELECT * FROM incidents WHERE id = ?', id);
    if (i && changeIncidentStatus(i, to, reason, ip)) updated++;
  }
  if (updated) publish('incidents');
  res.json({ ok: true, updated, skipped: raw.length - updated });
});

incidentsRouter.post('/:id/notes', (req, res) => {
  const id = idParam(req);
  if (!get('SELECT id FROM incidents WHERE id = ?', id)) throw new HttpError(404, 'Not found');
  event(id, 'note', str(body(req).message, 'Note', { min: 1, max: 4000 })!);
  audit('incident.note', { ip: clientIp(req), resourceType: 'incident', resourceId: id });
  publish('incidents');
  res.json({ ok: true });
});

incidentsRouter.post('/:id/links', (req, res) => {
  const id = idParam(req);
  if (!get('SELECT id FROM incidents WHERE id = ?', id)) throw new HttpError(404, 'Not found');
  const b = body(req);
  const kind = oneOf(b.kind, 'Kind', ['alert', 'finding'] as const)!;
  const refId = num(b.refId, 'Reference', { int: true, min: 1 })!;
  const exists = kind === 'alert' ? get('SELECT id FROM alert_events WHERE id = ?', refId) : get('SELECT id FROM security_findings WHERE id = ?', refId);
  if (!exists) throw new HttpError(404, `${kind} #${refId} not found`);
  link(id, kind, refId, str(b.reason, 'Reason', { optional: true, max: 500 }) ?? 'Linked manually');
  audit('incident.link', { ip: clientIp(req), resourceType: 'incident', resourceId: id, detail: { kind, refId } });
  publish('incidents');
  res.json({ ok: true });
});

incidentsRouter.delete('/:id/links/:kind/:refId', (req, res) => {
  const id = idParam(req);
  const kind = oneOf(req.params.kind, 'Kind', ['alert', 'finding'] as const)!;
  const refId = Number(req.params.refId);
  const r = run('DELETE FROM incident_links WHERE incident_id = ? AND kind = ? AND ref_id = ?', id, kind, refId);
  if (r.changes) event(id, 'unlink', `Unlinked ${kind} #${refId}`);
  audit('incident.unlink', { ip: clientIp(req), resourceType: 'incident', resourceId: id, detail: { kind, refId } });
  publish('incidents');
  res.json({ ok: true });
});
