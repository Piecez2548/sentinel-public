import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';

/* ---------- live updates over SSE ---------- */

export type Topic = 'assets' | 'metrics' | 'checks' | 'logs' | 'findings' | 'alerts' | 'incidents' | 'notifications' | 'settings' | 'health' | 'device' | 'power';

type Listener = (topics: Topic[]) => void;
export class LiveBus {
  private listeners = new Set<Listener>();
  private es: EventSource | null = null;
  connected = false;
  onStatus?: (connected: boolean) => void;

  start() {
    if (this.es) return;
    const es = new EventSource('/api/stream');
    es.onopen = () => {
      this.connected = true;
      this.onStatus?.(true);
    };
    es.onerror = () => {
      this.connected = false;
      this.onStatus?.(false);
    };
    es.onmessage = (m) => {
      try {
        const { topics } = JSON.parse(m.data) as { topics: Topic[] };
        for (const l of this.listeners) l(topics);
      } catch {
        /* ignore */
      }
    };
    this.es = es;
  }
  stop() {
    this.es?.close();
    this.es = null;
  }
  on(l: Listener) {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }
}

export const LiveContext = createContext<LiveBus | null>(null);

/**
 * Fetch data and refetch when any of `topics` changes on the server
 * (SSE), plus a slow fallback poll. Keeps showing old data while reloading.
 */
export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[], topics: Topic[] = [], pollMs = 60_000) {
  const live = useContext(LiveContext);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fetchRef = useRef(fetcher);
  fetchRef.current = fetcher;
  const seq = useRef(0);

  const reload = useCallback(async () => {
    const my = ++seq.current;
    try {
      const d = await fetchRef.current();
      if (my === seq.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (my === seq.current) setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const topicKey = topics.join(',');
  useEffect(() => {
    if (!live || !topicKey) return;
    let t: ReturnType<typeof setTimeout> | null = null;
    const off = live.on((changed) => {
      if (!changed.some((c) => topicKey.split(',').includes(c))) return;
      if (t) clearTimeout(t);
      t = setTimeout(() => void reload(), 300);
    });
    return () => {
      off();
      if (t) clearTimeout(t);
    };
  }, [live, topicKey, reload]);

  useEffect(() => {
    if (!pollMs) return;
    const i = setInterval(() => void reload(), pollMs);
    return () => clearInterval(i);
  }, [pollMs, reload]);

  return { data, error, loading, reload, setData };
}

/** Re-render periodically so relative times stay fresh. */
export function useTick(ms = 15_000) {
  const [, set] = useState(0);
  useEffect(() => {
    const t = setInterval(() => set((n) => n + 1), ms);
    return () => clearInterval(t);
  }, [ms]);
}

/* ---------- hash router ---------- */

export function useRoute(): [string[], (path: string) => void] {
  const parse = () => (window.location.hash.replace(/^#\/?/, '') || 'overview').split('?')[0].split('/').filter(Boolean);
  const [parts, setParts] = useState(parse);
  useEffect(() => {
    const on = () => setParts(parse());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  const go = useCallback((path: string) => {
    window.location.hash = `#/${path}`;
  }, []);
  return [parts, go];
}

export function useLocalState<T>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const s = localStorage.getItem(`sentinel:${key}`);
      return s ? (JSON.parse(s) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = useCallback(
    (nv: T) => {
      setV(nv);
      try {
        localStorage.setItem(`sentinel:${key}`, JSON.stringify(nv));
      } catch {
        /* ignore */
      }
    },
    [key],
  );
  return [v, set];
}
