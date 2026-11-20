/** Health of SENTINEL's own components (self-monitoring, ADR-009). */
export type ComponentHealth = {
  name: string;
  label: string;
  ok: boolean;
  message: string;
  lastRunAt: number | null;
  lastOkAt: number | null;
  errorSince: number | null;
  info?: Record<string, unknown>;
};

type Entry = ComponentHealth & { expectEveryMs: number | null; registeredAt: number };

const components = new Map<string, Entry>();

/** A component is "stalled" when it has not reported for this many expected intervals. */
const STALL_FACTOR = 3;
const MIN_STALL_MS = 2 * 60_000;

/**
 * @param expectEveryMs how often the component normally reports; enables stall detection
 *   (a job that hangs or silently stops is reported as failing instead of staying "OK").
 */
export function registerComponent(name: string, label: string, expectEveryMs: number | null = null) {
  if (!components.has(name)) {
    components.set(name, { name, label, ok: true, message: 'Starting…', lastRunAt: null, lastOkAt: null, errorSince: null, expectEveryMs, registeredAt: Date.now() });
  }
}

export function reportOk(name: string, message = 'OK', info?: Record<string, unknown>) {
  const c = components.get(name);
  if (!c) return;
  const now = Date.now();
  Object.assign(c, { ok: true, message, lastRunAt: now, lastOkAt: now, errorSince: null, info: info ?? c.info });
}

export function reportError(name: string, message: string, info?: Record<string, unknown>) {
  const c = components.get(name);
  if (!c) return;
  const now = Date.now();
  Object.assign(c, { ok: false, message, lastRunAt: now, errorSince: c.errorSince ?? now, info: info ?? c.info });
}

/** Called by the job scheduler when a job throws; only affects registered components. */
export function reportJobError(name: string, e: unknown) {
  if (components.has(name)) reportError(name, `Job crashed: ${e instanceof Error ? e.message : String(e)}`);
}

export function getHealth(now = Date.now()): ComponentHealth[] {
  return [...components.values()].map(({ expectEveryMs, registeredAt, ...c }) => {
    if (!expectEveryMs) return c;
    const limit = Math.max(expectEveryMs * STALL_FACTOR, MIN_STALL_MS);
    const last = c.lastRunAt ?? registeredAt;
    if (now - last <= limit) return c;
    const mins = Math.round((now - last) / 60_000);
    return {
      ...c,
      ok: false,
      message: c.lastRunAt ? `No report for ${mins} min — job stalled or stopped` : `Never reported in ${mins} min since start — job not running`,
      errorSince: c.errorSince ?? last + expectEveryMs,
    };
  });
}
