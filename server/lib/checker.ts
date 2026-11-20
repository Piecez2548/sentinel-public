import tls from 'node:tls';
import { Agent, fetch } from 'undici';
import { assertUrlAllowed, safeLookup } from './ssrf.js';

const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;

const agent = new Agent({
  connect: { lookup: safeLookup as never, timeout: TIMEOUT_MS },
});

export type CheckResult = {
  ok: boolean;
  statusCode: number | null;
  latencyMs: number | null;
  error: string | null;
  /** Security-relevant response headers of the final response (null = header absent). */
  headers?: Record<string, string | null>;
};

export const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'server',
  'x-powered-by',
] as const;

function pickHeaders(h: Headers): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const name of SECURITY_HEADERS) out[name] = h.get(name)?.slice(0, 300) ?? null;
  return out;
}

function describeError(e: unknown): string {
  if (e instanceof Error) {
    const cause = (e as Error & { cause?: { code?: string; message?: string } }).cause;
    if (e.name === 'TimeoutError' || e.name === 'AbortError') return `Timeout after ${TIMEOUT_MS / 1000}s`;
    return cause?.code ?? cause?.message ?? e.message;
  }
  return String(e);
}

/** GET the URL, following redirects manually so each hop is SSRF-validated. */
async function readCapped(res: Awaited<ReturnType<typeof fetch>>, maxBytes: number): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  let bytes = 0;
  while (bytes < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    text += decoder.decode(value, { stream: true });
  }
  await reader.cancel().catch(() => {});
  return text;
}

/**
 * Expected status spec: comma-separated codes or ranges, e.g. "401" or "200-299,401".
 * Returns null for an invalid spec. Used for API/backend probes where e.g. 401 means "up".
 */
export function parseStatusSpec(spec: string): [number, number][] | null {
  const parts = spec.split(',').map((p) => p.trim()).filter(Boolean);
  if (!parts.length || parts.length > 10) return null;
  const out: [number, number][] = [];
  for (const p of parts) {
    const m = /^(\d{3})(?:-(\d{3}))?$/.exec(p);
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = Number(m[2] ?? m[1]);
    if (lo < 100 || hi > 599 || lo > hi) return null;
    out.push([lo, hi]);
  }
  return out;
}

export const statusMatches = (status: number, spec: [number, number][]) => spec.some(([lo, hi]) => status >= lo && status <= hi);

export async function checkUrl(rawUrl: string, keyword?: string | null, expectedStatus?: string | null): Promise<CheckResult> {
  const expect = expectedStatus ? parseStatusSpec(expectedStatus) : null;
  const started = performance.now();
  const deadline = AbortSignal.timeout(TIMEOUT_MS);
  try {
    let current = assertUrlAllowed(rawUrl);
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        dispatcher: agent,
        signal: deadline,
        headers: { 'user-agent': 'SENTINEL-Lite/0.1 (uptime monitor)' },
      });
      const location = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && location && !(expect && statusMatches(res.status, expect))) {
        await res.body?.cancel().catch(() => {});
        current = assertUrlAllowed(new URL(location, current));
        continue;
      }
      const latencyMs = Math.round(performance.now() - started);
      const headers = pickHeaders(res.headers as unknown as Headers);
      if (expect ? !statusMatches(res.status, expect) : res.status >= 400) {
        await res.body?.cancel().catch(() => {});
        return { ok: false, statusCode: res.status, latencyMs, error: expect ? `HTTP ${res.status} (expected ${expectedStatus})` : `HTTP ${res.status}`, headers };
      }
      if (keyword) {
        const body = await readCapped(res, 1_000_000);
        if (!body.toLowerCase().includes(keyword.toLowerCase())) {
          return { ok: false, statusCode: res.status, latencyMs, error: `Keyword "${keyword}" not found`, headers };
        }
      } else {
        await res.body?.cancel().catch(() => {});
      }
      return { ok: true, statusCode: res.status, latencyMs, error: null, headers };
    }
    return { ok: false, statusCode: null, latencyMs: null, error: 'Too many redirects' };
  } catch (e) {
    return { ok: false, statusCode: null, latencyMs: null, error: describeError(e) };
  }
}

/** Read the TLS certificate expiry (works even if the cert is already expired). */
export function getCertExpiry(hostname: string, port: number): Promise<number | null> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      lookup: safeLookup as never,
      rejectUnauthorized: false,
      timeout: 8000,
    });
    const done = (value: number | null) => {
      socket.destroy();
      resolve(value);
    };
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      const t = cert?.valid_to ? Date.parse(cert.valid_to) : NaN;
      done(Number.isNaN(t) ? null : t);
    });
    socket.once('timeout', () => done(null));
    socket.once('error', () => done(null));
  });
}
