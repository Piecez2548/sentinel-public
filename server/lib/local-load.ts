import { get, all } from '../db.js';
import { MIN } from './util.js';

/**
 * When the PC SENTINEL runs on is maxed out (e.g. a game plus a test run), its own web checks
 * time out and every site looks "down" at once. These helpers let the HTTP monitor tell
 * "the site is down" apart from "this PC is too busy to check".
 */

export const OVERLOAD_PCT = 95;
/** How long a no-response failure is held back while the PC is overloaded before it counts anyway. */
export const OVERLOAD_HOLD_MS = 10 * MIN;

export type Load = { cpu: number; mem: number };

/** Latest local CPU/memory if either was ≥ 95% in the last two samples (within 3 minutes); else null. */
export function localOverload(now = Date.now()): Load | null {
  const rows = all<{ cpu_pct: number | null; mem_pct: number | null }>(
    `SELECT m.cpu_pct, m.mem_pct FROM host_metrics m JOIN host_info h ON h.asset_id = m.asset_id
      WHERE h.collector = 'local' AND m.ts > ? AND m.ts <= ? ORDER BY m.ts DESC LIMIT 2`,
    now - 3 * MIN, now,
  );
  const hit = rows.find((r) => (r.cpu_pct ?? 0) >= OVERLOAD_PCT || (r.mem_pct ?? 0) >= OVERLOAD_PCT);
  return hit ? { cpu: Math.round(hit.cpu_pct ?? 0), mem: Math.round(hit.mem_pct ?? 0) } : null;
}

/** Time of the first failed check since the site's last success (null = no failure yet). */
export function failingSince(assetId: number): number | null {
  return (
    get<{ t: number | null }>(
      `SELECT MIN(ts) AS t FROM check_results WHERE asset_id = ? AND ok = 0
         AND ts > COALESCE((SELECT MAX(ts) FROM check_results WHERE asset_id = ? AND ok = 1), 0)`,
      assetId, assetId,
    )?.t ?? null
  );
}

/** Local metrics are late: the collector itself is starved, which only happens when the PC is choking. */
export function collectorStale(now = Date.now()): boolean {
  const last = get<{ t: number | null }>(
    "SELECT MAX(m.ts) AS t FROM host_metrics m JOIN host_info h ON h.asset_id = m.asset_id WHERE h.collector = 'local' AND m.ts <= ?", now,
  )?.t;
  return last != null && now - last > 150_000;
}

/** Other sites that also got no answer at all in the last 3 minutes. Unrelated sites failing together = this PC's problem. */
export function othersNoResponse(assetId: number, now = Date.now()): number {
  return (
    get<{ n: number }>(
      'SELECT COUNT(DISTINCT asset_id) AS n FROM check_results WHERE asset_id != ? AND ok = 0 AND status_code IS NULL AND ts > ? AND ts <= ?',
      assetId, now - 3 * MIN, now,
    )?.n ?? 0
  );
}

/** Why this PC looks like the problem right now, or null. */
export function localTrouble(assetId: number, now = Date.now()): 'busy' | 'stale' | 'many' | null {
  if (localOverload(now)) return 'busy';
  if (collectorStale(now)) return 'stale';
  if (othersNoResponse(assetId, now) >= 1) return 'many';
  return null;
}

/**
 * Hold back a "down" verdict? Only for failures with no HTTP response at all (timeout, connection
 * error) — a real 500 or a missing keyword is the site's fault — and only for a limited time,
 * so a site that is really down while the PC stays busy is still reported.
 */
export function shouldHold(o: { noResponse: boolean; overloaded: boolean; failingSince: number | null; now: number }): boolean {
  if (!o.noResponse || !o.overloaded) return false;
  return o.failingSince == null || o.now - o.failingSince < OVERLOAD_HOLD_MS;
}
