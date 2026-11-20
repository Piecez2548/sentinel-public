export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** Set by <StepUpPrompt>: asks for the 6-digit code when a change needs an unlocked session (HTTP 423). */
let stepUpPrompt: (() => Promise<boolean>) | null = null;
export const setStepUpPrompt = (p: (() => Promise<boolean>) | null) => {
  stepUpPrompt = p;
};

async function request<T>(method: string, path: string, body?: unknown, retried = false): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new Event('sentinel:unauthorized'));
  // The app PIN is needed again (the app was left or went quiet): the PIN screen takes over.
  if (res.status === 428) window.dispatchEvent(new Event('sentinel:pin'));
  if (res.status === 423 && !retried && stepUpPrompt && (await stepUpPrompt())) return request<T>(method, path, body, true);
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string }).error ?? `Request failed (${res.status})`);
  return data as T;
}

export const api = {
  get: <T>(p: string) => request<T>('GET', p),
  post: <T = { ok: boolean }>(p: string, b: unknown = {}) => request<T>('POST', p, b),
  put: <T = { ok: boolean }>(p: string, b: unknown) => request<T>('PUT', p, b),
  del: <T = { ok: boolean }>(p: string) => request<T>('DELETE', p),
};

/* ---------- shared types ---------- */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type DiskSample = { mount: string; total: number; free: number; usedPct: number };

export type Asset = {
  id: number;
  name: string;
  type: 'host' | 'website';
  environment: string;
  target: string | null;
  tags: string[];
  enabled: boolean;
  status: 'up' | 'down' | 'unknown' | 'paused';
  statusSince: number | null;
  sloTarget: number;
  notes: string | null;
  createdAt: number;
  activeAlerts: number;
  openFindings: number;
  website?: {
    intervalSec: number;
    keyword: string | null;
    expectedStatus: string | null;
    lastCheckedAt: number | null;
    lastLatencyMs: number | null;
    lastStatusCode: number | null;
    lastError: string | null;
    tlsExpiresAt: number | null;
    headers: Record<string, string | null> | null;
    uptime24h: number | null;
    uptime30d: number | null;
    avgLatency24h: number | null;
  };
  host?: {
    hostname: string | null;
    os: string | null;
    cpuModel: string | null;
    cores: number | null;
    memTotal: number | null;
    collector: string;
    bootAt: number | null;
    lastSeenAt: number | null;
    latest: { ts: number; cpuPct: number | null; memPct: number | null; memUsed: number | null; memTotal: number | null; disks: DiskSample[]; netRxBps: number | null; netTxBps: number | null; batteryPct: number | null; onAc: boolean | null } | null;
    securityEvents24h: number;
  };
};

export type AlertEvent = {
  id: number;
  ruleId: number | null;
  ruleName: string | null;
  ruleType: string | null;
  assetId: number | null;
  assetName: string | null;
  status: 'firing' | 'acknowledged' | 'resolved';
  severity: Severity;
  title: string;
  detail: string | null;
  value: number | null;
  triggeredAt: number;
  acknowledgedAt: number | null;
  resolvedAt: number | null;
};

export type Finding = {
  id: number;
  ruleId: string;
  ruleName: string;
  assetId: number | null;
  assetName: string | null;
  severity: Severity;
  title: string;
  summary: string;
  status: 'open' | 'acknowledged' | 'resolved' | 'false_positive';
  firstSeen: number;
  lastSeen: number;
  count: number;
  resolvedAt: number | null;
  note: string | null;
  plainTh?: PlainText | null;
};

/** Plain Thai wording the server adds to findings (shown in the Thai UI). */
export type PlainText = { title: string; summary: string; fix?: string };

/** Title/summary to show: plain Thai in the Thai UI when available, otherwise the technical text. */
export function findingText(f: { title: string; summary?: string; plainTh?: PlainText | null }, lang: string): { title: string; summary: string; fix?: string; plain: boolean } {
  if (lang === 'th' && f.plainTh) return { ...f.plainTh, plain: true };
  return { title: f.title, summary: f.summary ?? '', plain: false };
}

export type LogEvent = {
  id: number;
  assetId: number;
  channel: string;
  eventId: number;
  recordId: number;
  ts: number;
  level: string;
  category: string;
  summary: string;
  fields: Record<string, string>;
};

export type Incident = {
  id: number;
  title: string;
  severity: Severity;
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'closed';
  summary: string | null;
  assignee: string | null;
  source: string;
  assetId: number | null;
  assetName: string | null;
  openedAt: number;
  acknowledgedAt: number | null;
  resolvedAt: number | null;
  closedAt: number | null;
  resolution: string | null;
  linkCount?: number;
};

export type ComponentHealth = {
  name: string;
  label: string;
  ok: boolean;
  message: string;
  lastRunAt: number | null;
  lastOkAt: number | null;
  errorSince: number | null;
};
