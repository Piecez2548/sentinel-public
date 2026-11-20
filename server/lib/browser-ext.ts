import { compose, SEV_ICON, type Msg } from './device-messages.js';

/**
 * Browser extensions (added 2026-11-17). A fake or hijacked extension can read every page, steal
 * logged-in sessions and passwords, and Defender rarely sees it. Chromium browsers (Chrome, Brave, Edge,
 * Vivaldi, Opera) keep each profile's extensions in "Secure Preferences" / "Preferences"; the module reads
 * those files and these pure helpers decide what is new and how risky it is.
 */

export type Ext = {
  browser: string;
  profile: string;
  id: string;
  name: string;
  version?: string;
  /** Chromium's Manifest::Location: 1 store/user, 2 external pref, 3 external registry, 4 unpacked, 5 component, 6 default app, 7 policy download, 8 command line, 9 policy, 10 external component. */
  location: number;
  fromStore: boolean;
  apis: string[];
  hosts: string[];
  installedAt?: number;
};

/** One browser profile: `ok` false = its files could not be read this time (keep what we knew). */
export type ExtProfile = { browser: string; profile: string; ok: boolean; exts: Ext[] };

export type Manifest = { name?: string; version?: string; permissions?: unknown[]; host_permissions?: unknown[] };

type Setting = {
  location?: number;
  from_webstore?: boolean;
  path?: string;
  manifest?: Manifest;
  install_time?: string;
  first_install_time?: string;
  granted_permissions?: { api?: unknown[]; explicit_host?: unknown[]; scriptable_host?: unknown[] };
  active_permissions?: { api?: unknown[]; explicit_host?: unknown[]; scriptable_host?: unknown[] };
};

const strs = (a: unknown[] | undefined) => (Array.isArray(a) ? a.filter((x): x is string => typeof x === 'string') : []);
/** Chromium stores times as microseconds since 1601-01-01. */
const chromeTime = (t: string | undefined) => {
  const n = Number(t);
  return n > 0 ? Math.round(n / 1000 - 11_644_473_600_000) : undefined;
};

/** Built into the browser itself (PDF viewer, Web Store, …): not something anyone installs. */
const BUILT_IN = new Set([5, 10]);

/**
 * Extensions of one profile from its preference files (later files fill gaps of earlier ones).
 * `manifestOf` reads `Extensions/<path>/manifest.json` when the preferences don't carry the manifest.
 */
export function parseProfile(browser: string, profile: string, prefs: unknown[], manifestOf: (path: string) => Manifest | null): Ext[] {
  const settings: Record<string, Setting> = {};
  for (const p of prefs) {
    const s = (p as { extensions?: { settings?: Record<string, Setting> } } | null)?.extensions?.settings;
    if (!s || typeof s !== 'object') continue;
    for (const [id, v] of Object.entries(s)) if (v && typeof v === 'object') settings[id] = { ...v, ...settings[id] };
  }
  const out: Ext[] = [];
  for (const [id, s] of Object.entries(settings)) {
    // Leftover entries of removed extensions have no location/path.
    if (typeof s.location !== 'number' || BUILT_IN.has(s.location)) continue;
    if (!s.path && !s.manifest) continue;
    const m = s.manifest?.name ? s.manifest : (s.path ? manifestOf(s.path) : null) ?? s.manifest ?? {};
    const perm = s.granted_permissions ?? s.active_permissions ?? {};
    const apis = [...new Set([...strs(perm.api), ...strs(m.permissions).filter((p) => !p.includes('://') && p !== '<all_urls>')])];
    const hosts = [...new Set([...strs(perm.explicit_host), ...strs(perm.scriptable_host), ...strs(m.host_permissions), ...strs(m.permissions).filter((p) => p.includes('://') || p === '<all_urls>')])];
    const name = typeof m.name === 'string' && m.name.trim() && !/^__MSG_/.test(m.name) ? m.name.trim() : id;
    out.push({ browser, profile, id, name, version: m.version, location: s.location, fromStore: s.from_webstore === true, apis, hosts, installedAt: chromeTime(s.first_install_time ?? s.install_time) });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export const extKey = (e: Pick<Ext, 'browser' | 'profile' | 'id'>) => `${e.browser}|${e.profile}|${e.id}`;
export const profileKey = (p: Pick<ExtProfile, 'browser' | 'profile'>) => `${p.browser}|${p.profile}`;

/** Host patterns that mean "every website". */
const ALL_SITES_RE = /^(?:<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/|https?:\/\/\*\/|file:\/\/\/\*)$/;
/** Permissions that let an extension take over the browser, not just one site. */
export const RISKY_APIS = ['debugger', 'proxy', 'nativeMessaging', 'cookies', 'management', 'webRequestBlocking', 'desktopCapture', 'clipboardRead', 'privacy'];

/** What makes this extension powerful, as stable labels: `all sites` plus the risky permissions it holds. */
export function riskyPowers(e: Pick<Ext, 'apis' | 'hosts'>): string[] {
  const out = e.hosts.some((h) => ALL_SITES_RE.test(h)) ? ['all sites'] : [];
  return [...out, ...RISKY_APIS.filter((a) => e.apis.includes(a))];
}

/** Not from the Web Store: put there by a program, a registry key, a policy or a developer folder. */
const SIDELOAD: Record<number, string> = { 2: 'a program (external preferences)', 3: 'a program (registry)', 4: 'a folder on disk (developer mode)', 7: 'a policy', 8: 'the command line', 9: 'a policy' };

export type ExtVerdict = { severity: 'low' | 'medium' | 'high'; reason: 'sideloaded' | 'policy' | 'powerful' | 'store' | 'gained'; detail: string; powers: string[]; gained?: string[] };

export function judgeExt(e: Ext): ExtVerdict {
  const powers = riskyPowers(e);
  if (e.location === 7 || e.location === 9) return { severity: 'high', reason: 'policy', detail: 'installed by a policy, so it cannot be removed from the browser', powers };
  if (!e.fromStore && (SIDELOAD[e.location] || e.location === 1)) return { severity: 'high', reason: 'sideloaded', detail: `not from the Web Store: added by ${SIDELOAD[e.location] ?? 'a file'}`, powers };
  if (powers.length) return { severity: 'medium', reason: 'powerful', detail: `from the Web Store; can use: ${powers.join(', ')}`, powers };
  return { severity: 'low', reason: 'store', detail: 'from the Web Store, no broad permissions', powers };
}

/** Baseline: profiles seen, and each extension's name plus its risky powers (to notice an update that adds some). */
export type ExtBaseline = { profiles: string[]; exts: Record<string, { name: string; powers: string[] }> };

export type ExtChange =
  | { kind: 'added'; ext: Ext; verdict: ExtVerdict }
  | { kind: 'gained'; ext: Ext; verdict: ExtVerdict }
  | { kind: 'removed'; key: string; name: string; browser: string };

/**
 * Compare this run with the baseline. Unreadable profiles change nothing; a profile seen for the first
 * time is recorded silently (its extensions came with it); a profile that is gone counts as removed.
 */
export function diffExtensions(profiles: ExtProfile[], base: ExtBaseline | null): { changes: ExtChange[]; next: ExtBaseline } {
  const next: ExtBaseline = { profiles: [], exts: {} };
  const changes: ExtChange[] = [];
  const known = new Set(base?.profiles ?? []);
  const seenProfiles = new Set(profiles.map(profileKey));
  for (const p of profiles) {
    const pk = profileKey(p);
    next.profiles.push(pk);
    if (!p.ok) {
      for (const [k, v] of Object.entries(base?.exts ?? {})) if (k.startsWith(pk + '|')) next.exts[k] = v;
      continue;
    }
    const now = new Set<string>();
    for (const e of p.exts) {
      const k = extKey(e);
      now.add(k);
      const v = judgeExt(e);
      next.exts[k] = { name: e.name, powers: v.powers };
      if (!base || !known.has(pk)) continue;
      const old = base.exts[k];
      if (!old) changes.push({ kind: 'added', ext: e, verdict: v });
      else {
        const gained = v.powers.filter((x) => !old.powers.includes(x));
        if (gained.length) changes.push({ kind: 'gained', ext: e, verdict: { ...v, severity: v.severity === 'high' ? 'high' : 'medium', reason: 'gained', detail: `an update added: ${gained.join(', ')}`, gained } });
      }
    }
    if (base && known.has(pk))
      for (const [k, v] of Object.entries(base.exts)) if (k.startsWith(pk + '|') && !now.has(k)) changes.push({ kind: 'removed', key: k, name: v.name, browser: p.browser });
  }
  // Whole profile (or browser) gone.
  if (base)
    for (const [k, v] of Object.entries(base.exts)) {
      const pk = k.split('|').slice(0, 2).join('|');
      if (!seenProfiles.has(pk)) changes.push({ kind: 'removed', key: k, name: v.name, browser: k.split('|')[0] });
    }
  return { changes, next };
}

const PAGE: Record<string, string> = { Chrome: 'chrome://extensions', Brave: 'brave://extensions', Edge: 'edge://extensions', Vivaldi: 'vivaldi://extensions', Opera: 'opera://extensions' };
export const extensionsPage = (browser: string) => PAGE[browser] ?? 'chrome://extensions';

const POWER_TH: Record<string, string> = {
  'all sites': 'อ่านและแก้ทุกเว็บที่เปิด',
  debugger: 'ควบคุมแท็บได้ทั้งหมด (debugger)',
  proxy: 'เปลี่ยนเส้นทางอินเทอร์เน็ต (proxy)',
  nativeMessaging: 'คุยกับโปรแกรมบนเครื่อง',
  cookies: 'อ่านคุกกี้/ล็อกอิน',
  management: 'จัดการส่วนขยายอื่น',
  webRequestBlocking: 'ดักและแก้ข้อมูลเว็บ',
  desktopCapture: 'จับภาพหน้าจอ',
  clipboardRead: 'อ่านคลิปบอร์ด',
  privacy: 'เปลี่ยนการตั้งค่าความเป็นส่วนตัว',
};
export const powersTh = (p: string[]) => p.map((x) => POWER_TH[x] ?? x).join(', ');

export function extensionMessage(e: Ext, v: ExtVerdict, asset: string): Msg {
  const where = `${e.browser}${e.profile !== 'Default' ? ` (${e.profile})` : ''}`;
  const page = extensionsPage(e.browser);
  const fixTh = `ถ้าไม่ได้ติดตั้งเอง: เปิด ${page} ใน ${e.browser} → "${e.name}" → นำออก แล้วเปลี่ยนรหัสผ่านเว็บสำคัญ`;
  const fixEn = `If you didn't add it: open ${page} in ${e.browser} → "${e.name}" → Remove, then change important passwords`;
  const parts = {
    policy: {
      th: { head: `ส่วนขยายที่ถูกบังคับติดตั้งใน ${where}: ${e.name}`, why: 'ติดตั้งผ่าน policy จึงลบจากเบราว์เซอร์ไม่ได้ — เครื่องส่วนตัวไม่ควรมี เป็นวิธีที่มัลแวร์ใช้', fix: `แจ้งผม หรือดู ${page.replace('extensions', 'policy')} ว่าใครตั้ง แล้วสแกน Full scan` },
      en: { head: `Extension forced in by a policy in ${where}: ${e.name}`, why: 'Installed through a policy, so it cannot be removed from the browser — a personal PC should have none; malware uses this.', fix: `Check ${page.replace('extensions', 'policy')} for who set it, then run a Full scan` },
    },
    sideloaded: {
      th: { head: `ส่วนขยายที่ไม่ได้มาจาก Web Store ใน ${where}: ${e.name}`, why: 'ถูกโปรแกรมหรือไฟล์บนเครื่องใส่เข้ามา ไม่ผ่านการตรวจของ Store — ลักษณะของส่วนขยายขโมยข้อมูล', fix: `${fixTh} และสแกน Full scan` },
      en: { head: `Extension not from the Web Store in ${where}: ${e.name}`, why: 'Put there by a program or a file on the PC, never reviewed by the store — typical of data-stealing extensions.', fix: `${fixEn}, and run a Full scan` },
    },
    powerful: {
      th: { head: `ติดตั้งส่วนขยายใหม่ใน ${where}: ${e.name}`, why: `มาจาก Web Store แต่มีสิทธิ์สูง: ${powersTh(v.powers)}`, fix: fixTh },
      en: { head: `New extension in ${where}: ${e.name}`, why: `From the Web Store, with broad powers: ${v.powers.join(', ')}.`, fix: fixEn },
    },
    gained: {
      th: { head: `ส่วนขยายได้สิทธิ์เพิ่มหลังอัปเดต: ${e.name}`, why: `ใน ${where} ได้สิทธิ์ใหม่: ${powersTh(v.gained ?? [])} — ส่วนขยายที่ถูกขายต่อมักถูกแก้แบบนี้`, fix: `ถ้าไม่ได้ใช้ฟีเจอร์ใหม่: เปิด ${page} → "${e.name}" → นำออก` },
      en: { head: `Extension gained permissions in an update: ${e.name}`, why: `In ${where}, ${v.detail} — sold-off extensions are often changed this way.`, fix: `If you don't need it: open ${page} → "${e.name}" → Remove` },
    },
    store: {
      th: { head: `ติดตั้งส่วนขยายใหม่ใน ${where}: ${e.name}`, why: 'มาจาก Web Store และไม่ได้ขอสิทธิ์กว้าง', fix: fixTh },
      en: { head: `New extension in ${where}: ${e.name}`, why: 'From the Web Store, no broad permissions.', fix: fixEn },
    },
  }[v.reason];
  const icon = SEV_ICON[v.severity] ?? '🟡';
  return { th: compose(icon, parts.th, asset, true), en: compose(icon, parts.en, asset, false), headlineTh: parts.th.head, headlineEn: parts.en.head };
}

export type ExtEvent = { kind: 'added' | 'removed' | 'gained'; name: string; browser: string; at: number; severity?: string; reason?: ExtVerdict['reason']; powers?: string[] };
const KEEP_MS = 90 * 86_400_000;
export const trimExtEvents = (ev: ExtEvent[], now: number) => ev.filter((e) => now - e.at < KEEP_MS).slice(-200);
