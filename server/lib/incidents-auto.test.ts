import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

// The modules open the database on import: point it at a throwaway folder first.
const dir = mkdtempSync(join(tmpdir(), 'sentinel-inc-'));
process.env.DATA_DIR = dir;
const { db, get, migrate, run } = await import('../db.js');
migrate();
const { autoResolveRecovered, AUTO_RESOLVE_QUIET } = await import('../modules/incidents.js');
after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const now = Date.now();
const MIN = 60_000;
let fp = 0;

function incident(opts: { source?: string; status?: string; alerts?: { resolvedAgo: number | null }[]; finding?: boolean }) {
  const id = Number(run('INSERT INTO incidents (title, severity, status, source, opened_at) VALUES (?, ?, ?, ?, ?)', 't', 'critical', opts.status ?? 'open', opts.source ?? 'correlation', now - 2 * 60 * MIN).lastInsertRowid);
  for (const a of opts.alerts ?? []) {
    const aid = Number(
      run(
        'INSERT INTO alert_events (fingerprint, status, severity, title, triggered_at, resolved_at) VALUES (?, ?, ?, ?, ?, ?)',
        `fp${fp++}`, a.resolvedAgo == null ? 'firing' : 'resolved', 'critical', 'Site is DOWN', now - 2 * 60 * MIN, a.resolvedAgo == null ? null : now - a.resolvedAgo,
      ).lastInsertRowid,
    );
    run("INSERT INTO incident_links (incident_id, kind, ref_id, linked_at) VALUES (?, 'alert', ?, ?)", id, aid, now - 2 * 60 * MIN);
  }
  if (opts.finding) run("INSERT INTO incident_links (incident_id, kind, ref_id, linked_at) VALUES (?, 'finding', 999, ?)", id, now - 2 * 60 * MIN);
  return id;
}
const status = (id: number) => get<{ status: string; resolution: string | null }>('SELECT status, resolution FROM incidents WHERE id = ?', id)!;

test('an incident whose alerts all recovered 30+ minutes ago closes itself', () => {
  const recovered = incident({ alerts: [{ resolvedAgo: 40 * MIN }, { resolvedAgo: 35 * MIN }] });
  const tooRecent = incident({ alerts: [{ resolvedAgo: 40 * MIN }, { resolvedAgo: AUTO_RESOLVE_QUIET - MIN }] });
  const stillFiring = incident({ alerts: [{ resolvedAgo: 40 * MIN }, { resolvedAgo: null }] });
  const withFinding = incident({ alerts: [{ resolvedAgo: 40 * MIN }], finding: true });
  const investigating = incident({ status: 'investigating', alerts: [{ resolvedAgo: 40 * MIN }] });
  const manual = incident({ source: 'manual', alerts: [{ resolvedAgo: 40 * MIN }] });

  assert.equal(autoResolveRecovered(now), 1);
  assert.equal(status(recovered).status, 'resolved');
  assert.match(status(recovered).resolution ?? '', /ปิดอัตโนมัติ|Closed automatically/);
  for (const id of [tooRecent, stillFiring, withFinding, investigating, manual]) assert.notEqual(status(id).status, 'resolved', `incident ${id} stays open`);
  assert.equal(get<{ n: number }>("SELECT COUNT(*) AS n FROM incident_events WHERE incident_id = ? AND to_status = 'resolved'", recovered)!.n, 1, 'timeline records it');
});
