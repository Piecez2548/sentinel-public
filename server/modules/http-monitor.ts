import { all, get, run, tx } from '../db.js';
import { publish } from '../lib/bus.js';
import { checkUrl, getCertExpiry } from '../lib/checker.js';
import { registerComponent, reportOk } from '../lib/health.js';
import { failingSince, localTrouble, shouldHold } from '../lib/local-load.js';
import { HOUR } from '../lib/util.js';
import { evaluateWebHeaders } from './detection.js';

/** HTTP/TLS checks for website assets (ADR-006). */

const FAIL_THRESHOLD = 2; // consecutive failures before an "up" site is declared down
const MAX_CONCURRENT = 5;
const TLS_RECHECK_MS = 6 * HOUR;
const HEADERS_RECHECK_MS = 6 * HOUR;

registerComponent('http', 'Website checks', 5_000);

type Row = {
  asset_id: number;
  url: string;
  status: string;
  status_since: number | null;
  interval_sec: number;
  keyword: string | null;
  expected_status: string | null;
  consecutive_failures: number;
  tls_checked_at: number | null;
  headers_checked_at: number | null;
};

const inflight = new Set<number>();
let checksSinceReport = 0;

function load(assetId: number) {
  return get<Row>(
    `SELECT h.asset_id, a.target AS url, a.status, a.status_since, h.interval_sec, h.keyword, h.expected_status, h.consecutive_failures,
            h.tls_checked_at, h.headers_checked_at
       FROM http_checks h JOIN assets a ON a.id = h.asset_id WHERE h.asset_id = ? AND a.type = 'website'`,
    assetId,
  );
}

export async function runHttpCheck(assetId: number): Promise<void> {
  if (inflight.has(assetId)) return;
  inflight.add(assetId);
  try {
    const site = load(assetId);
    if (!site || !site.url) return;
    const res = await checkUrl(site.url, site.keyword, site.expected_status);
    const now = Date.now();

    tx(() => {
      run(
        'INSERT INTO check_results (asset_id, ts, ok, status_code, latency_ms, error) VALUES (?, ?, ?, ?, ?, ?)',
        assetId, now, res.ok ? 1 : 0, res.statusCode, res.latencyMs, res.error,
      );
      const failures = res.ok ? 0 : site.consecutive_failures + 1;
      let status = site.status;
      if (res.ok) status = 'up';
      else if (site.status !== 'down' && failures >= (site.status === 'up' ? FAIL_THRESHOLD : 1)) {
        // No answer at all while this PC is choking (busy, its own metrics late, or other sites failing too)
        // → most likely the PC, not the site: wait a bit.
        const held = shouldHold({ noResponse: res.statusCode == null, overloaded: localTrouble(assetId, now) != null, failingSince: failingSince(assetId), now });
        if (!held) status = 'down';
      }
      run(
        `UPDATE http_checks SET consecutive_failures = ?, last_checked_at = ?, last_latency_ms = ?, last_status_code = ?, last_error = ?
         WHERE asset_id = ?`,
        failures, now, res.latencyMs, res.statusCode, res.error, assetId,
      );
      if (status !== site.status) {
        run('UPDATE assets SET status = ?, status_since = ? WHERE id = ?', status, now, assetId);
        publish('assets');
      }
    });

    // Security headers snapshot (feeds the web_security_headers detection rule).
    if (res.headers && res.statusCode && res.statusCode < 400 && (!site.headers_checked_at || now - site.headers_checked_at > HEADERS_RECHECK_MS)) {
      run('UPDATE http_checks SET headers = ?, headers_checked_at = ? WHERE asset_id = ?', JSON.stringify(res.headers), now, assetId);
      evaluateWebHeaders(assetId, site.url, res.headers);
    }

    if (site.url.toLowerCase().startsWith('https://') && (!site.tls_checked_at || now - site.tls_checked_at > TLS_RECHECK_MS)) {
      const u = new URL(site.url);
      const exp = await getCertExpiry(u.hostname.replace(/^\[|\]$/g, ''), Number(u.port) || 443);
      run('UPDATE http_checks SET tls_expires_at = ?, tls_checked_at = ? WHERE asset_id = ?', exp, now, assetId);
    }
    checksSinceReport++;
    publish('checks');
  } finally {
    inflight.delete(assetId);
  }
}

export function httpTick() {
  const due = all<{ asset_id: number }>(
    `SELECT h.asset_id FROM http_checks h JOIN assets a ON a.id = h.asset_id
     WHERE a.enabled = 1 AND a.type = 'website'
       AND (h.last_checked_at IS NULL OR h.last_checked_at + h.interval_sec * 1000 <= ?)`,
    Date.now(),
  );
  for (const { asset_id } of due) {
    if (inflight.size >= MAX_CONCURRENT) break;
    void runHttpCheck(asset_id).catch((e) => console.error('[http] check failed', e));
  }
  const total = get<{ n: number }>("SELECT COUNT(*) AS n FROM assets WHERE type = 'website' AND enabled = 1")?.n ?? 0;
  reportOk('http', `${total} website(s) monitored`, { checksSinceStart: checksSinceReport });
}
