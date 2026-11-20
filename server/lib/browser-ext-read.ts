import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseProfile, type ExtProfile, type Manifest } from './browser-ext.js';

/** Where each Chromium browser keeps its profiles, under a user's folder. Read-only. */
const BROWSERS: { browser: string; dir: string; single?: boolean }[] = [
  { browser: 'Chrome', dir: 'AppData\\Local\\Google\\Chrome\\User Data' },
  { browser: 'Brave', dir: 'AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data' },
  { browser: 'Edge', dir: 'AppData\\Local\\Microsoft\\Edge\\User Data' },
  { browser: 'Vivaldi', dir: 'AppData\\Local\\Vivaldi\\User Data' },
  { browser: 'Opera', dir: 'AppData\\Roaming\\Opera Software\\Opera Stable', single: true },
];

const SKIP_USERS = new Set(['all users', 'default', 'default user', 'public']);
const PREF_FILES = ['Secure Preferences', 'Preferences'];

const readJson = (f: string): unknown => {
  try {
    return JSON.parse(readFileSync(f, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return undefined;
  }
};

/** manifest.json of an installed extension, with `__MSG_name__` looked up in its _locales. */
function manifestReader(profileDir: string) {
  return (path: string): Manifest | null => {
    const dir = /^[a-z]:\\/i.test(path) ? path : join(profileDir, 'Extensions', path);
    const m = readJson(join(dir, 'manifest.json')) as (Manifest & { default_locale?: string }) | undefined;
    if (!m || typeof m !== 'object') return null;
    const msg = typeof m.name === 'string' ? /^__MSG_(.+)__$/.exec(m.name)?.[1] : undefined;
    if (msg) {
      for (const loc of [m.default_locale, 'en', 'en_US'].filter(Boolean) as string[]) {
        const j = readJson(join(dir, '_locales', loc, 'messages.json')) as Record<string, { message?: string }> | undefined;
        const hit = j && Object.entries(j).find(([k]) => k.toLowerCase() === msg.toLowerCase())?.[1]?.message;
        if (hit) return { ...m, name: hit };
      }
    }
    return m;
  };
}

/** Every Chromium profile of every user on this PC with its extensions. */
export function readBrowserExtensions(usersRoot = 'C:\\Users'): ExtProfile[] {
  let users: string[] = [];
  try {
    users = readdirSync(usersRoot, { withFileTypes: true }).filter((d) => d.isDirectory() && !SKIP_USERS.has(d.name.toLowerCase())).map((d) => d.name);
  } catch {
    return [];
  }
  const found: { user: string; browser: string; profile: string; dir: string; files: string[] }[] = [];
  for (const user of users)
    for (const b of BROWSERS) {
      const root = join(usersRoot, user, b.dir);
      if (!existsSync(root)) continue;
      let profiles: string[] = [];
      try {
        profiles = b.single ? [''] : readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory() && /^(?:Default|Profile \d+)$/.test(d.name)).map((d) => d.name);
      } catch {
        continue;
      }
      for (const p of profiles) {
        const dir = join(root, p);
        const files = PREF_FILES.map((f) => join(dir, f)).filter(existsSync);
        if (files.length) found.push({ user, browser: b.browser, profile: p || 'Default', dir, files });
      }
    }
  // Name the Windows user only when more than one has a browser.
  const many = new Set(found.map((f) => f.user)).size > 1;
  return found.map((f) => {
    const prefs = f.files.map(readJson);
    const name = many ? `${f.user}/${f.profile}` : f.profile;
    const ok = prefs.some((x) => x !== undefined);
    return { browser: f.browser, profile: name, ok, exts: ok ? parseProfile(f.browser, name, prefs, manifestReader(f.dir)) : [] };
  });
}
