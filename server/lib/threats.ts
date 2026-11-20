/**
 * Threat history: what Microsoft Defender found on this PC, where, and whether it dealt with it.
 * Built from Defender's own events that the event log collector stores:
 * 1116 detected, 1117 action taken, 1118 action failed, 1119 critical error while acting.
 */

export const THREAT_EVENT_IDS = [1116, 1117, 1118, 1119] as const;

export type ThreatRow = { event_id: number; ts: number; fields: Record<string, string> };

export type ThreatStatus = 'handled' | 'allowed' | 'failed' | 'pending';

export type Threat = {
  name: string;
  severity: string;
  category: string;
  paths: string[];
  firstAt: number;
  lastAt: number;
  /** Defender's action name of the newest action event, e.g. "Quarantine", "Remove". */
  action: string;
  status: ThreatStatus;
  /** How many times it was detected (1116) in the window. */
  detections: number;
};

/** A detection with no action event after this long is worth a look. */
export const PENDING_AFTER_MS = 15 * 60_000;

/** Defender writes paths as "file:_C:\x.dll; file:_D:\y.exe" (also containerfile:_ / process:_ / regkey:_). */
export function cleanPaths(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(';')
    .map((p) => p.trim().replace(/^[a-z]+:_/i, ''))
    .filter(Boolean);
}

/** Allow / no action means the threat is still on the PC on purpose (or by mistake). */
const ALLOWED = /allow|no action/i;

/** Groups Defender threat events by threat + location, newest first. Pure; exported for tests. */
export function threatHistory(rows: ThreatRow[]): Threat[] {
  const byKey = new Map<string, Threat & { lastActionAt: number; lastDetectAt: number }>();
  for (const r of [...rows].sort((a, b) => a.ts - b.ts)) {
    const f = r.fields;
    const name = f['Threat Name'] || 'Unknown threat';
    const paths = cleanPaths(f.Path);
    const key = `${name}|${[...paths].sort().join('|').toLowerCase()}`;
    const t =
      byKey.get(key) ??
      { name, severity: '', category: '', paths, firstAt: r.ts, lastAt: r.ts, action: '', status: 'pending' as ThreatStatus, detections: 0, lastActionAt: 0, lastDetectAt: 0 };
    t.severity = f['Severity Name'] || t.severity;
    t.category = f['Category Name'] || t.category;
    t.lastAt = r.ts;
    if (r.event_id === 1116) {
      t.detections += 1;
      t.lastDetectAt = r.ts;
    } else {
      t.lastActionAt = r.ts;
      t.action = f['Action Name'] || t.action;
      t.status = r.event_id === 1117 ? (ALLOWED.test(t.action) ? 'allowed' : 'handled') : 'failed';
    }
    byKey.set(key, t);
  }
  return [...byKey.values()]
    .map(({ lastActionAt, lastDetectAt, ...t }) => {
      // Detected again after the last action, and nothing since: Defender has not reported dealing with it yet.
      // (A fresh detection gets its action event within seconds, so needsAttention waits PENDING_AFTER_MS.)
      if (lastDetectAt > lastActionAt && t.status !== 'failed') t.status = 'pending';
      return t;
    })
    .sort((a, b) => b.lastAt - a.lastAt);
}

/** True when something needs the owner: Defender failed, the threat was allowed, or no action was reported. */
export const needsAttention = (t: Threat, now = Date.now()) => t.status === 'failed' || t.status === 'allowed' || (t.status === 'pending' && now - t.lastAt >= PENDING_AFTER_MS);
