import { locale, t } from './i18n';

export function ago(ts: number | null | undefined): string {
  if (!ts) return '—';
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 0) return t('just now');
  if (s < 60) return t('{n}s ago', { n: s });
  if (s < 3600) return t('{n}m ago', { n: Math.floor(s / 60) });
  if (s < 86400) return t('{n}h ago', { n: Math.floor(s / 3600) });
  return t('{n}d ago', { n: Math.floor(s / 86400) });
}

export function duration(ms: number | null | undefined): string {
  if (ms == null) return '—';
  const s = Math.max(0, Math.round(ms / 1000));
  const u = { s: t('unit.s'), m: t('unit.m'), h: t('unit.h'), d: t('unit.d') };
  if (s < 60) return `${s}${u.s}`;
  if (s < 3600) return `${Math.floor(s / 60)}${u.m} ${s % 60}${u.s}`;
  if (s < 86400) return `${Math.floor(s / 3600)}${u.h} ${Math.floor((s % 3600) / 60)}${u.m}`;
  return `${Math.floor(s / 86400)}${u.d} ${Math.floor((s % 86400) / 3600)}${u.h}`;
}

export const pct = (v: number | null | undefined, digits = 2) =>
  v == null ? '—' : `${v >= 99.995 || v === 0 || v === 100 ? v.toFixed(0) : v.toFixed(digits)}%`;

export function bytes(n: number | null | undefined): string {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

export const bps = (n: number | null | undefined) => (n == null ? '—' : `${bytes(n)}/s`);

export const stamp = (ts: number | null | undefined) =>
  ts ? new Date(ts).toLocaleString(locale(), { dateStyle: 'medium', timeStyle: 'short' }) : '—';
export const clock = (ts: number) => new Date(ts).toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit', second: '2-digit' });
export const fullDate = (ts: number) => new Date(ts).toLocaleString(locale());

export const SEV_STYLE: Record<string, string> = {
  critical: 'bg-bad/15 text-bad ring-bad/30',
  high: 'bg-orange-500/15 text-orange-400 ring-orange-500/30',
  medium: 'bg-warn/15 text-warn ring-warn/30',
  low: 'bg-accent-2/15 text-accent-2 ring-accent-2/30',
};
export const SEV_COLOR: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#38bdf8' };

/** Display label for a severity (translated). */
export const sevLabel = (s: string) => (t(`sev.${s}`) === `sev.${s}` ? s : t(`sev.${s}`));

export const STATUS_DOT: Record<string, string> = {
  up: 'bg-ok shadow-[0_0_8px] shadow-ok/60',
  down: 'bg-bad shadow-[0_0_8px] shadow-bad/60 animate-pulse',
  unknown: 'bg-warn',
  paused: 'bg-muted',
};
const STATUS_EN: Record<string, string> = { up: 'Up', down: 'Down', unknown: 'Pending', paused: 'Paused' };
/** Translated asset status label. */
export const statusLabel = (s: string) => t(STATUS_EN[s] ?? s);

/** Translated label for workflow states (firing, open, resolved, …). */
export const stateLabel = (s: string) => (t(`state.${s}`) === `state.${s}` ? s.replace('_', ' ') : t(`state.${s}`));

export const host = (url: string | null) => (url ?? '').replace(/^https?:\/\//, '').replace(/\/$/, '');
