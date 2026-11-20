import { getHealth, registerComponent, reportError, reportOk } from '../lib/health.js';

/**
 * Dead man's switch: SENTINEL cannot report its own death, so it pings an external
 * monitor (e.g. healthchecks.io) every few minutes. If the pings stop — laptop off,
 * battery dead, process hung — that service alerts the admin.
 *
 * HEARTBEAT_URL is a secret (anyone holding it can send fake pings): read from .env only,
 * never logged, never returned by the API.
 *
 * When one of SENTINEL's own components is failing, the ping goes to `<url>/fail` with a
 * short plain-text reason (component names only), so the external monitor flags it too.
 */

export const HEARTBEAT_EVERY_MS = 5 * 60_000;
const url = (process.env.HEARTBEAT_URL ?? '').trim();

export function heartbeatConfigured() {
  return !!url;
}

/** Validated once at startup; a bad value is reported, not thrown. */
function target(): URL | null {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && !u.username && !u.password ? u : null;
  } catch {
    return null;
  }
}

if (url) registerComponent('heartbeat', 'External heartbeat', HEARTBEAT_EVERY_MS);

/** The URL to ping for the current health (exported for tests). */
export function pingUrl(base: URL, failing: string[]): string {
  if (!failing.length) return base.href;
  const u = new URL(base.href);
  u.pathname = `${u.pathname.replace(/\/+$/, '')}/fail`;
  return u.href;
}

export async function sendHeartbeat(): Promise<void> {
  if (!url) return;
  const base = target();
  if (!base) {
    reportError('heartbeat', 'HEARTBEAT_URL must be an https:// URL without credentials');
    return;
  }
  const failing = getHealth()
    .filter((c) => !c.ok && c.name !== 'heartbeat')
    .map((c) => c.label);
  try {
    const r = await fetch(pingUrl(base, failing), {
      method: 'POST',
      headers: { 'content-type': 'text/plain; charset=utf-8', 'user-agent': 'SENTINEL-heartbeat' },
      body: failing.length ? `Failing: ${failing.join(', ')}` : 'OK',
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) throw new Error(`monitor answered HTTP ${r.status}`);
    reportOk('heartbeat', failing.length ? `Pinged (reported ${failing.length} failing component(s))` : `Pinged ${base.host}`);
  } catch (e) {
    // Never include the URL: it is the secret.
    const msg = e instanceof Error ? (e.name === 'TimeoutError' ? 'timed out' : e.message.split('\n')[0]) : String(e);
    reportError('heartbeat', `Ping to ${base.host} failed: ${msg.replaceAll(url, '<HEARTBEAT_URL>')}`);
  }
}
