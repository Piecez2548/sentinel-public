import { compose, SEV_ICON, type Msg } from './device-messages.js';

/**
 * New programs installed on the PC (cracked software can sit on a PC for months unnoticed). The device-health script lists installed programs from the registry's
 * Uninstall keys; anything not seen on the previous run is "new" and its main program file's signature
 * is checked. Pure helpers here; the module (device-health.ts) does the I/O.
 */

export type App = { name: string; version?: string; publisher?: string; location?: string; icon?: string; uninstall?: string; date?: string };

/** Version numbers, architectures and language tags change with every update; leave them out of the identity. */
export function normName(name: string): string {
  return name
    .toLowerCase()
    .replace(/\((?:x64|x86|64-bit|32-bit|amd64|arm64|64 bit|32 bit)\)/g, ' ')
    .replace(/\((?:[a-z]{2}-[a-z]{2}|user|machine)\)/g, ' ')
    .replace(/\bv?\d+(?:\.\d+)+[a-z0-9]*\b/g, ' ')
    .replace(/\s+-\s*$/, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[\s-]+$/, '');
}

export const appKey = (a: App) => `${normName(a.name)}|${(a.publisher ?? '').toLowerCase().trim()}`;

/** One entry per program (the same program can be listed under HKLM and HKCU). */
export function uniqueApps(apps: App[]): App[] {
  const m = new Map<string, App>();
  for (const a of apps) if (a.name?.trim() && !m.has(appKey(a))) m.set(appKey(a), a);
  return [...m.values()];
}

/** Programs present now that were not there last time. */
export const newApps = (apps: App[], baseline: Set<string>) => uniqueApps(apps).filter((a) => !baseline.has(appKey(a)));

/** Programs that were there last time and are gone now (uninstalled). */
export const removedKeys = (apps: App[], baseline: Set<string>) => {
  const now = new Set(uniqueApps(apps).map(appKey));
  return [...baseline].filter((k) => !now.has(k));
};

/** Words that only show up in pirated / cracked software and the groups that repack it. */
const CRACK_RE = /\b(?:crack(?:ed)?|keygen|kmspico|kms ?auto|activator|pre-?activated|repack(?:ed)?|amtemu|m0nkrus|kpojiuk|xatab|fitgirl|dodi|elchupacabra|diakov|by tnt)\b/i;
export const crackHint = (a: App) => [a.name, a.publisher, a.location].map((s) => CRACK_RE.exec(s ?? '')?.[0]).find(Boolean) ?? null;

/** DisplayIcon is often the program itself: `"C:\x\app.exe",0` → `C:\x\app.exe`. Only .exe counts. */
export function iconExe(icon: string | undefined): string | null {
  if (!icon) return null;
  const s = icon.trim().replace(/^"([^"]+)".*$/, '$1').replace(/,\s*-?\d+$/, '').replace(/"/g, '').trim();
  return /^[a-z]:\\.+\.exe$/i.test(s) ? s : null;
}

/** From the files in the install folder, the ones most likely to be the program (not its uninstaller or updater). */
export function pickExes(files: { name: string; size: number }[], max = 2): string[] {
  return files
    .filter((f) => /\.exe$/i.test(f.name) && !/unins|uninst|setup|update|updater|crash|helper|report|elevat|install/i.test(f.name))
    .sort((a, b) => b.size - a.size)
    .slice(0, max)
    .map((f) => f.name);
}

export type Sig = { state: 'signed'; signer: string; path: string } | { state: 'unsigned' | 'invalid'; detail: string; path: string } | { state: 'unknown'; detail: string; path: string | null };

export type AppVerdict = { severity: 'low' | 'medium' | 'high'; reason: 'crack' | 'tampered' | 'unsigned' | 'signed' | 'unknown'; detail: string; signer?: string; file?: string };

/** Worst finding wins: crack words → tampered signature (e.g. HashMismatch) → unsigned → signed → not checkable. */
export function judgeApp(a: App, sigs: Sig[]): AppVerdict {
  const crack = crackHint(a);
  const bad = sigs.find((s) => s.state === 'invalid');
  const unsigned = sigs.find((s) => s.state === 'unsigned');
  const signed = sigs.find((s): s is Extract<Sig, { state: 'signed' }> => s.state === 'signed');
  if (crack) return { severity: 'high', reason: 'crack', detail: `"${crack}" is a word used by pirated software`, file: bad?.path ?? undefined };
  if (bad && bad.state === 'invalid') return { severity: 'high', reason: 'tampered', detail: `${bad.path}: ${bad.detail}`, file: bad.path };
  if (unsigned && unsigned.state === 'unsigned') return { severity: 'medium', reason: 'unsigned', detail: `${unsigned.path}: ${unsigned.detail}`, file: unsigned.path };
  if (signed) return { severity: 'low', reason: 'signed', detail: `signed by ${signed.signer}`, signer: signed.signer, file: signed.path };
  return { severity: 'low', reason: 'unknown', detail: sigs.length ? 'signature could not be checked' : 'no program file found to check' };
}

const label = (a: App) => `${a.name}${a.version && !a.name.includes(a.version) ? ` ${a.version}` : ''}`;
const shortPath = (p: string) => p.replace(/^[a-z]:\\users\\[^\\]+\\/i, '');

export function programMessage(a: App, v: AppVerdict, asset: string): Msg {
  const n = label(a);
  const by = a.publisher ? ` (${a.publisher})` : '';
  const fixTh = `ถ้าไม่ได้ติดตั้งเอง: Settings → Apps → Installed apps → "${a.name}" → Uninstall แล้วสแกน Full scan`;
  const fixEn = `If you didn't install it: Settings → Apps → Installed apps → "${a.name}" → Uninstall, then run a Full scan`;
  const f = v.file ? shortPath(v.file) : '';
  const parts = {
    crack: {
      th: { head: `ติดตั้งโปรแกรมที่น่าจะเป็นตัวแคร็ก: ${n}`, why: `พบคำว่า "${crackHint(a)}"${by} — ตัวแคร็กมักแฝงมัลแวร์ และไม่ได้รับอัปเดตความปลอดภัย`, fix: `ถอนออก: Settings → Apps → Installed apps → "${a.name}" → Uninstall แล้วสแกน Full scan` },
      en: { head: `Probably cracked software installed: ${n}`, why: `Contains "${crackHint(a)}"${by} — cracks often carry malware and never get security updates.`, fix: `Remove it: Settings → Apps → Installed apps → "${a.name}" → Uninstall, then run a Full scan` },
    },
    tampered: {
      th: { head: `ติดตั้งโปรแกรมที่ไฟล์ถูกดัดแปลง: ${n}`, why: `ลายเซ็นของ ${f} ไม่ตรงกับไฟล์ — ไฟล์ถูกแก้หลังผู้ผลิตเซ็น ซึ่งเป็นลักษณะของตัวแคร็ก`, fix: `ถอนออก: Settings → Apps → Installed apps → "${a.name}" → Uninstall แล้วสแกน Full scan` },
      en: { head: `Installed program with a modified file: ${n}`, why: `${f} no longer matches its signature — it was changed after the publisher signed it, typical of cracks.`, fix: `Remove it: Settings → Apps → Installed apps → "${a.name}" → Uninstall, then run a Full scan` },
    },
    unsigned: {
      th: { head: `ติดตั้งโปรแกรมใหม่ที่ไม่มีลายเซ็น: ${n}`, why: `${f} ไม่มีลายเซ็นดิจิทัล จึงไม่รู้ว่าใครสร้าง${by}`, fix: fixTh },
      en: { head: `New unsigned program installed: ${n}`, why: `${f} is not digitally signed, so nobody vouches for it${by}.`, fix: fixEn },
    },
    signed: {
      th: { head: `ติดตั้งโปรแกรมใหม่: ${n}`, why: `มีลายเซ็นจาก ${v.signer ?? '?'} — ปกติเป็นโปรแกรมที่คุณติดตั้ง`, fix: fixTh },
      en: { head: `New program installed: ${n}`, why: `Signed by ${v.signer ?? '?'} — usually something you installed.`, fix: fixEn },
    },
    unknown: {
      th: { head: `ติดตั้งโปรแกรมใหม่: ${n}`, why: `ตรวจลายเซ็นไม่ได้${by}`, fix: fixTh },
      en: { head: `New program installed: ${n}`, why: `Signature could not be checked${by}.`, fix: fixEn },
    },
  }[v.reason];
  const icon = SEV_ICON[v.severity] ?? '🟡';
  return { th: compose(icon, parts.th, asset, true), en: compose(icon, parts.en, asset, false), headlineTh: parts.th.head, headlineEn: parts.en.head };
}

/** Install / uninstall history kept for the Device page and the weekly summary. */
export type ProgramEvent = { kind: 'added' | 'removed'; name: string; version?: string; publisher?: string; at: number; severity?: string; reason?: AppVerdict['reason']; signer?: string };
export const KEEP_EVENTS_MS = 90 * 86_400_000;
export const trimEvents = (ev: ProgramEvent[], now: number) => ev.filter((e) => now - e.at < KEEP_EVENTS_MS).slice(-200);
