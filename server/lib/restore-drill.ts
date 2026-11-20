/**
 * Monthly restore test of the encrypted cloud copy (owner asked 2026-11-17): a backup only counts if it can be
 * restored. Pure rules here; modules/backup.ts reads, decrypts and opens the copy.
 */

export type DrillResult = {
  at: number;
  reason: 'scheduled' | 'manual';
  ok: boolean;
  /** Nothing to test (no cloud folder or not encrypted yet): not a failure, no alert. */
  skipped?: boolean;
  problems: string[];
  name?: string;
  createdAt?: number;
  bytes?: number;
  counts?: Record<string, number>;
  ms?: number;
};

export const DRILL_EVERY_MS = 30 * 86_400_000;
/** After a failure, try again daily (the next day's backup may fix it) instead of waiting a month. */
export const DRILL_RETRY_MS = 86_400_000;
/** The newest cloud copy should be from the last two nightly backups. */
export const MAX_COPY_AGE_MS = 2 * 86_400_000 + 6 * 3_600_000;

export function drillDue(last: DrillResult | null, now: number): boolean {
  if (!last) return true;
  const wait = last.ok || last.skipped ? DRILL_EVERY_MS : DRILL_RETRY_MS;
  return now - last.at >= wait;
}

export type DrillFacts = {
  name: string;
  createdAt: number;
  bytes: number;
  files: string[];
  integrity: string | null;
  counts: Record<string, number> | null;
  manifestCounts: Record<string, number> | null;
  masterMatches: boolean;
};

/** What is wrong with a restored copy; empty = it would restore fine. */
export function drillProblems(f: DrillFacts, now: number): string[] {
  const p: string[] = [];
  for (const need of ['sentinel.db', 'master.key', 'manifest.json']) if (!f.files.includes(need)) p.push(`${need} is missing from the copy`);
  if (f.files.includes('sentinel.db') && f.integrity !== 'ok') p.push(`Database check failed: ${f.integrity ?? 'could not open it'}`);
  if (f.counts && f.manifestCounts) {
    // The manifest is counted just after the snapshot while logging goes on, so small differences are normal.
    // A table that lost a real share of its rows means the copy is not what was backed up.
    const off = Object.entries(f.manifestCounts).filter(([t, n]) => (f.counts![t] ?? 0) < n * 0.9 - 10).map(([t]) => t);
    if (off.length) p.push(`Rows missing compared with the backup's own record: ${off.join(', ')}`);
  }
  if (f.files.includes('master.key') && !f.masterMatches) p.push("master.key in the copy is not this PC's key — saved passwords and tokens would not open");
  if (Number.isFinite(f.createdAt) && now - f.createdAt > MAX_COPY_AGE_MS) p.push(`Newest cloud copy is ${Math.floor((now - f.createdAt) / 86_400_000)} days old — copying has stopped`);
  return p;
}
