import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { Router } from 'express';
import { getJsonSetting, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { body, clientIp, HttpError } from '../lib/http.js';
import { L } from '../lib/i18n.js';
import { escHtml } from '../lib/util.js';
import { requireStepUp, userAgentOf } from './auth.js';
import { deviceLabel } from './login-watch.js';
import { enqueue } from './notify.js';
import { dryRun } from './power.js';

/**
 * Open an app on the PC from the phone. Only Start-menu and desktop shortcuts (.lnk) can be opened —
 * nobody can type a path or a command — and opening one needs the unlocked Power page (2FA).
 * The shortcut is handed to explorer.exe, so the app starts as the signed-in user on the normal desktop.
 */

export type App = { id: string; name: string; folder: string | null };

function roots(): { key: string; dir: string }[] {
  const env = process.env;
  const list = [
    { key: 'user', dir: env.APPDATA && join(env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs') },
    { key: 'common', dir: env.ProgramData && join(env.ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs') },
    { key: 'desktop', dir: env.USERPROFILE && join(env.USERPROFILE, 'Desktop') },
    { key: 'pubdesktop', dir: env.PUBLIC && join(env.PUBLIC, 'Desktop') },
  ];
  if (env.SENTINEL_TEST_LAUNCH_DIR) return [{ key: 'test', dir: env.SENTINEL_TEST_LAUNCH_DIR }];
  return list.filter((r): r is { key: string; dir: string } => !!r.dir);
}

/** Uninstallers, help files, readmes and the like are not apps. */
const JUNK = /uninstall|ถอนการติดตั้ง|คู่มือ|วิธีใช้|สิ่งใหม่|deinstall|remove |readme|release notes|help|manual|license|documentation|website|support|debug|safe mode|module docs|pydoc|report a problem|telemetry/i;

/** System and admin tools are never offered: opening them remotely is no use and only adds risk. */
const SYSTEM =
  /^(command prompt|windows powershell|powershell|run|registry editor|task scheduler|services|computer management|component services|control panel|event viewer|system configuration|system information|performance monitor|resource monitor|task manager|disk cleanup|dfrgui|recoverydrive|memory diagnostics tool|iscsi initiator|odbc data sources|windows defender firewall|administrative tools|git cmd|git bash|node\.js command prompt|mysql .*command line client|mysql shell|wsl|steps recorder|on-screen keyboard|narrator|magnify|voiceaccess|character map|remote desktop connection|install additional tools|python \d|idle |node\.js$)/i;

const idOf = (key: string, rel: string) => createHash('sha1').update(`${key}:${rel.toLowerCase()}`).digest('hex').slice(0, 16);

function walk(dir: string, depth: number, out: string[]) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (depth < 3 && !/^startup$/i.test(e.name)) walk(p, depth + 1, out);
    } else if (e.isFile() && /\.lnk$/i.test(e.name)) out.push(p);
  }
}

let cache: { at: number; apps: (App & { path: string })[] } | null = null;

/** Every shortcut, de-duplicated by name (first root wins), sorted by name. */
export function listApps(now = Date.now()): (App & { path: string })[] {
  if (cache && now - cache.at < 60_000) return cache.apps;
  const seen = new Set<string>();
  const apps: (App & { path: string })[] = [];
  for (const r of roots()) {
    const files: string[] = [];
    walk(r.dir, 0, files);
    for (const f of files) {
      const rel = relative(r.dir, f);
      const name = rel.split(sep).pop()!.replace(/\.lnk$/i, '').trim();
      if (!name || JUNK.test(name) || SYSTEM.test(name) || seen.has(name.toLowerCase())) continue;
      seen.add(name.toLowerCase());
      const parts = rel.split(sep);
      apps.push({ id: idOf(r.key, rel), name, folder: parts.length > 1 ? parts[0] : null, path: resolve(f) });
    }
  }
  apps.sort((a, b) => a.name.localeCompare(b.name, 'th'));
  cache = { at: now, apps };
  return apps;
}

export const clearAppCache = () => {
  cache = null;
};

/** Favourites shown as big buttons. First time: guess the common ones. */
export function getFavourites(apps = listApps()): string[] {
  const saved = getJsonSetting<string[] | null>('launcher_favourites', null);
  if (saved) return saved.filter((id) => apps.some((a) => a.id === id));
  const guess = /^(discord|steam|fc online.*|brave|line|spotify|epic games launcher|visual studio code|notion)$/i;
  return apps.filter((a) => guess.test(a.name)).map((a) => a.id).slice(0, 8);
}

function open(path: string) {
  if (dryRun()) {
    console.log(`[launcher] dry run: would open ${path}`);
    return;
  }
  // explorer.exe passes the shortcut to the running shell: the app starts as the user, not elevated.
  execFile('explorer.exe', [path], { windowsHide: true, timeout: 30_000 }, () => undefined);
}

/* ---------- remote screen (RustDesk) ---------- */

/**
 * The phone controls the screen with RustDesk, connecting straight to this PC's Tailscale IP
 * (RustDesk itself enforces its password, 2FA and IP whitelist). SENTINEL only reports where to
 * connect and whether RustDesk is ready; it never handles the RustDesk password.
 */
export type RemoteScreen = { target: string | null; installed: boolean; running: boolean; listening: boolean };

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
let remoteCache: { at: number; v: RemoteScreen } | null = null;

const run = (file: string, args: string[]) =>
  new Promise<string>((res) => execFile(file, args, { windowsHide: true, timeout: 10_000 }, (_e, out) => res(String(out ?? ''))));

export async function remoteScreen(now = Date.now()): Promise<RemoteScreen> {
  if (remoteCache && now - remoteCache.at < 30_000) return remoteCache.v;
  const env = process.env.SENTINEL_TEST_REMOTE;
  if (env) return JSON.parse(env) as RemoteScreen;
  const tsExe = ['C:\\Program Files\\Tailscale\\tailscale.exe'].find((p) => existsSync(p)) ?? 'tailscale';
  const [ip, sc, net] = await Promise.all([run(tsExe, ['ip', '-4']), run('sc.exe', ['query', 'RustDesk']), run('netstat.exe', ['-an'])]);
  const target = ip.split(/\s+/).find((x) => IPV4.test(x)) ?? null;
  const v: RemoteScreen = {
    target,
    installed: /SERVICE_NAME/i.test(sc),
    running: /STATE\s*:\s*4\s+RUNNING/i.test(sc),
    // RustDesk's direct-IP port (it binds [::], which also covers IPv4).
    listening: /TCP\s+\S+:21118\s+\S+\s+LISTENING/i.test(net),
  };
  remoteCache = { at: now, v };
  return v;
}

/* ---------- API ---------- */

export const launcherRouter = Router();

launcherRouter.get('/', (_req, res) => {
  const apps = listApps();
  res.json({ apps: apps.map(({ id, name, folder }) => ({ id, name, folder })), favourites: getFavourites(apps), dryRun: dryRun() });
});

// Only for an unlocked Power page (owner's choice): the RustDesk hand-off is not shown before the 6-digit code.
launcherRouter.get('/remote', async (req, res) => {
  requireStepUp(req, undefined);
  res.json(await remoteScreen());
});

launcherRouter.put('/favourites', (req, res) => {
  const ids = body(req).ids;
  if (!Array.isArray(ids) || ids.length > 24 || !ids.every((x) => typeof x === 'string' && /^[0-9a-f]{16}$/.test(x))) throw new HttpError(400, 'Up to 24 apps');
  const known = new Set(listApps().map((a) => a.id));
  const clean = [...new Set(ids as string[])].filter((id) => known.has(id));
  setSetting('launcher_favourites', JSON.stringify(clean));
  publish('power');
  res.json({ ok: true, favourites: clean });
});

launcherRouter.post('/open', (req, res) => {
  const b = body(req);
  const app = listApps().find((a) => a.id === b.id);
  if (!app) throw new HttpError(404, 'App not found — refresh the list');
  requireStepUp(req, b.code);
  // The path came from our own directory walk, but check it still is a shortcut inside a known folder.
  if (!/\.lnk$/i.test(app.path) || !roots().some((r) => app.path.toLowerCase().startsWith(resolve(r.dir).toLowerCase() + sep))) throw new HttpError(400, 'App not found — refresh the list');
  try {
    statSync(app.path);
  } catch {
    clearAppCache();
    throw new HttpError(404, 'App not found — refresh the list');
  }
  open(app.path);
  const device = deviceLabel(userAgentOf(req));
  audit('app.open', { ip: clientIp(req), detail: { name: app.name, device, dryRun: dryRun() } });
  enqueue('system', 'process', `▶️ <b>${escHtml(L(`Opened from ${device}: ${app.name}`, `เปิดแอปจาก ${device}: ${app.name}`))}</b>`);
  res.json({ ok: true, name: app.name, dryRun: dryRun() });
});
