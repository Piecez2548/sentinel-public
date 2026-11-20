import { useSyncExternalStore } from 'react';
import { TH, TH_PATTERNS } from './th';

/**
 * Minimal i18n: English source strings are the keys, Thai lives in ./th.ts.
 * A missing translation falls back to English, so nothing ever shows a raw key.
 * Placeholders use {name}: t('{n} failed logons', { n: 3 }).
 */

export type Lang = 'th' | 'en';
const KEY = 'sentinel.lang';

function load(): Lang {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'th' || v === 'en') return v;
  } catch {
    /* storage blocked */
  }
  return 'th';
}

let lang: Lang = load();
const listeners = new Set<() => void>();
document.documentElement.lang = lang;

export const getLang = () => lang;

export function setLang(l: Lang) {
  lang = l;
  document.documentElement.lang = l;
  try {
    localStorage.setItem(KEY, l);
  } catch {
    /* ignore */
  }
  listeners.forEach((f) => f());
}

export function useLang(): Lang {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => lang,
  );
}

/** English text for the few symbolic keys (units, severities, states). */
const EN: Record<string, string> = {
  'unit.s': 's', 'unit.m': 'm', 'unit.h': 'h', 'unit.d': 'd',
  'sev.critical': 'critical', 'sev.high': 'high', 'sev.medium': 'medium', 'sev.low': 'low',
  'state.firing': 'firing', 'state.open': 'open', 'state.acknowledged': 'acknowledged', 'state.investigating': 'investigating',
  'state.resolved': 'resolved', 'state.closed': 'closed', 'state.false_positive': 'false positive', 'state.sent': 'sent',
  'state.pending': 'pending', 'state.failed': 'failed',
  AI_OFF_HELP: 'Off. To turn it on, put ANTHROPIC_API_KEY=… in SENTINEL’s .env file and restart (npm run service:stop, then service:start). Each summary is a paid Claude API call.',
  AI_INTRO: 'Claude reads only the evidence linked to this incident and explains what happened, citing every point. Evidence text (event summaries, user names, IPs) is sent to Anthropic.',
};

export function t(s: string, vars?: Record<string, string | number | null | undefined>): string {
  let tmpl = (lang === 'th' ? TH[s] : undefined) ?? EN[s] ?? s;
  if (lang === 'th' && tmpl === s && !vars) {
    const p = TH_PATTERNS.find(([re]) => re.test(s));
    if (p) tmpl = s.replace(p[0], p[1]);
  }
  return vars ? tmpl.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k] ?? '') : m)) : tmpl;
}

/** Translate a symbolic key (e.g. `rule.brute_force`), falling back to server-provided text. */
export function tk(key: string, fallback: string): string {
  const v = t(key);
  return v === key ? fallback : v;
}

/** Locale for Intl/Date formatting. */
export const locale = () => (lang === 'th' ? 'th-TH' : undefined);
