import { EventEmitter } from 'node:events';

/** In-process change notifications, fanned out to browsers over SSE. */
export type Topic = 'assets' | 'metrics' | 'checks' | 'logs' | 'findings' | 'alerts' | 'incidents' | 'notifications' | 'settings' | 'health' | 'device' | 'power';

const emitter = new EventEmitter();
emitter.setMaxListeners(50);

let pending = new Set<Topic>();
let timer: NodeJS.Timeout | null = null;

/** Debounced: many writes within 500 ms become one SSE message. */
export function publish(...topics: Topic[]) {
  for (const t of topics) pending.add(t);
  if (timer) return;
  timer = setTimeout(() => {
    const batch = [...pending];
    pending = new Set();
    timer = null;
    emitter.emit('change', batch);
  }, 500);
}

export function subscribe(fn: (topics: Topic[]) => void): () => void {
  emitter.on('change', fn);
  return () => emitter.off('change', fn);
}
