/**
 * Phone / tablet check-in (added 2026-11-21). Android and iOS do not let any app inspect the system, so
 * SENTINEL learns only what the browser tells it each time SENTINEL is opened on the device: OS and browser
 * versions, battery (Android), whether it runs as a home-screen app. The one thing worth an alert is an OS
 * that no longer gets security updates — keeping the OS updated is the protection that matters most on a phone.
 */

/**
 * Oldest major versions still getting security updates. Update these once a year.
 * As of 2026-11: Android 14 and newer get monthly patches; Apple patches the current iOS and iOS 18.
 */
export const MIN_ANDROID = 14;
export const MIN_IOS = 18;

export type PhoneHints = {
  /** Chrome client hints (navigator.userAgentData): the real Android version and model, which the UA string hides. */
  platformVersion?: string;
  model?: string;
  /** iPadOS Safari sends a Mac user agent; the page tells the two apart by touch support. */
  touch?: boolean;
  battery?: { level?: number; charging?: boolean } | null;
  standalone?: boolean;
};

export type PhoneInfo = {
  platform: 'android' | 'ios' | 'ipados';
  os: string;
  osMajor: number | null;
  /** iOS 26 Safari freezes the OS token at 18_6, so a reading of 18.6 can also mean "newer". */
  osAtLeast: boolean;
  browser: string;
  browserVersion: string | null;
  model: string | null;
};

const num = (s: string | undefined) => (s && /^\d+/.test(s) ? Number(/^\d+/.exec(s)![0]) : null);

/** null = not a phone or tablet (a PC check-in is ignored). */
export function parsePhone(ua: string, h: PhoneHints = {}): PhoneInfo | null {
  const browser = /EdgA?\/|EdgiOS/.test(ua) ? 'Edge' : /SamsungBrowser\//.test(ua) ? 'Samsung Internet' : /Firefox\/|FxiOS/.test(ua) ? 'Firefox' : /CriOS|Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'browser';
  const bv = /(?:EdgA?|EdgiOS|SamsungBrowser|Firefox|FxiOS|CriOS|Chrome)\/([\d.]+)/.exec(ua)?.[1] ?? /Version\/([\d.]+)/.exec(ua)?.[1] ?? null;
  if (/Android/i.test(ua)) {
    // Chrome's reduced UA always says "Android 10; K"; the client hint carries the real version.
    const hinted = h.platformVersion && /^\d/.test(h.platformVersion) ? h.platformVersion : null;
    const fromUa = /Android ([\d.]+)/i.exec(ua)?.[1] ?? null;
    const reduced = fromUa === '10' && /Android 10; K\)/.test(ua);
    const os = hinted ?? (reduced ? null : fromUa);
    const model = h.model?.trim() || (/Android [\d.]+; ([^;)]+)\)/.exec(ua)?.[1]?.trim() ?? null);
    return { platform: 'android', os: os ? `Android ${os.replace(/\.0(\.0)?$/, '')}` : 'Android (version hidden)', osMajor: num(os ?? undefined), osAtLeast: false, browser, browserVersion: bv, model: model && model !== 'K' ? model : null };
  }
  const iDevice = /iPhone|iPad|iPod/.exec(ua)?.[0];
  const ipadAsMac = !iDevice && /Macintosh/.test(ua) && h.touch === true;
  if (!iDevice && !ipadAsMac) return null;
  const platform = iDevice === 'iPhone' || iDevice === 'iPod' ? 'ios' : 'ipados';
  // OS token (frozen at 18_6 from iOS 26 on) vs Safari's own version, which follows iOS (Safari 26 = iOS 26).
  const osToken = /OS (\d+)[_.](\d+)/.exec(ua);
  const tokenMajor = osToken && !ipadAsMac ? Number(osToken[1]) : null;
  const safariMajor = browser === 'Safari' ? num(/Version\/([\d.]+)/.exec(ua)?.[1]) : null;
  const major = Math.max(tokenMajor ?? 0, safariMajor ?? 0) || null;
  const frozen = !safariMajor && osToken?.[1] === '18' && osToken[2] === '6';
  const name = platform === 'ios' ? 'iOS' : 'iPadOS';
  const os = major ? `${name} ${major}${frozen ? '+' : ''}` : `${name} (version hidden)`;
  return { platform, os, osMajor: major, osAtLeast: frozen, browser, browserVersion: bv, model: platform === 'ios' ? 'iPhone' : 'iPad' };
}

export type PhoneVerdict = { status: 'ok' | 'old' | 'unknown'; detail: string };

export function judgePhone(p: PhoneInfo): PhoneVerdict {
  const min = p.platform === 'android' ? MIN_ANDROID : MIN_IOS;
  if (p.osMajor == null) return { status: 'unknown', detail: `${p.os}: open SENTINEL in Chrome or Safari to see the version` };
  if (p.osMajor < min && !p.osAtLeast) return { status: 'old', detail: `${p.os} no longer gets security updates (needs ${p.platform === 'android' ? 'Android' : 'iOS/iPadOS'} ${min} or newer)` };
  return { status: 'ok', detail: `${p.os} still gets security updates` };
}

/* ---------- stored devices ---------- */

export type PhoneRecord = PhoneInfo & {
  id: string;
  label: string;
  status: PhoneVerdict['status'];
  detail: string;
  firstSeen: number;
  lastSeen: number;
  battery: number | null;
  charging: boolean | null;
  standalone: boolean;
};

export const PHONE_ID = /^[a-z0-9-]{8,64}$/i;
export const MAX_PHONES = 10;
/** A phone not seen for this long is shown as "not opened lately" (no alert: it may simply be unused). */
export const STALE_MS = 14 * 86_400_000;

export function phoneLabel(p: PhoneInfo): string {
  return p.model && p.platform === 'android' ? `${p.model} (Android)` : p.platform === 'ios' ? 'iPhone' : p.platform === 'ipados' ? 'iPad' : 'Phone';
}

/** Merge a check-in into the stored list (newest first, at most MAX_PHONES). */
export function mergeCheckin(list: PhoneRecord[], id: string, info: PhoneInfo, h: PhoneHints, now: number): { list: PhoneRecord[]; rec: PhoneRecord; before: PhoneRecord | undefined } {
  const before = list.find((r) => r.id === id);
  const v = judgePhone(info);
  const level = typeof h.battery?.level === 'number' && h.battery.level >= 0 && h.battery.level <= 1 ? Math.round(h.battery.level * 100) : null;
  const rec: PhoneRecord = {
    ...info,
    id,
    label: phoneLabel(info),
    status: v.status,
    detail: v.detail,
    firstSeen: before?.firstSeen ?? now,
    lastSeen: now,
    battery: level,
    charging: typeof h.battery?.charging === 'boolean' ? h.battery.charging : null,
    standalone: h.standalone === true,
  };
  const rest = list.filter((r) => r.id !== id);
  return { list: [rec, ...rest].slice(0, MAX_PHONES), rec, before };
}
