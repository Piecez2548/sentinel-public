import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Router } from 'express';
import { get, getJsonSetting, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { body, clientIp, HttpError } from '../lib/http.js';
import { L } from '../lib/i18n.js';
import { escHtml } from '../lib/util.js';
import { requireStepUp, userAgentOf } from './auth.js';
import { getLocalAssetId } from './host-collector.js';
import { deviceLabel } from './login-watch.js';
import { enqueue } from './notify.js';
import { dryRun } from './power.js';

/**
 * Which programs use this PC: a snapshot of the heaviest processes, grouped by program
 * (Brave's 20 processes count as one "Brave"). Used to
 *  - name the culprit in CPU / memory alerts,
 *  - let the owner close a program from the phone (2FA, never system/SENTINEL/Tailscale processes),
 *  - game mode: no CPU/memory alerts while a listed game is running.
 * The snapshot is taken on demand and when the PC is busy, never on every minute tick.
 */

const exec = promisify(execFile);

export type ProcGroup = { name: string; label: string; title: string | null; company: string | null; path: string | null; cpu: number; memMB: number; count: number };
export type Snapshot = { at: number; groups: ProcGroup[]; running: string[] };
type Raw = { pid: number; name: string; cpu: number; mem: number; title?: string | null; company?: string | null; path?: string | null };

/** Never offered for closing: Windows itself, security software, the remote-access path, SENTINEL's own runtime. */
export const PROTECTED = new Set([
  'system', 'idle', 'registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'svchost', 'fontdrvhost',
  'dwm', 'memory compression', 'secure system', 'msmpeng', 'nissrv', 'securityhealthservice', 'securityhealthsystray', 'mssense',
  'sgrmbroker', 'explorer', 'sihost', 'ctfmon', 'taskhostw', 'runtimebroker', 'searchindexer', 'spoolsv', 'audiodg', 'wudfhost',
  'tailscaled', 'tailscale-ipn', 'tailscale', 'node', 'powershell', 'pwsh', 'conhost',
  'wmiprvse', 'dllhost', 'dashost', 'smartscreen', 'searchhost', 'startmenuexperiencehost', 'shellexperiencehost', 'textinputhost',
  'lockapp', 'applicationframehost', 'useroobebroker', 'wlanext', 'unsecapp', 'msedgewebview2',
]);

export const normName = (n: string) => n.toLowerCase().replace(/\.exe$/, '').replace(/#\d+$/, '').trim();
export const isProtected = (name: string) => PROTECTED.has(normName(name));

/** Sum per program and sort by the chosen resource. */
export function groupProcesses(rows: Raw[]): ProcGroup[] {
  const map = new Map<string, ProcGroup>();
  for (const r of rows) {
    const key = normName(r.name);
    if (!key || key === 'idle' || key === '_total') continue;
    const g = map.get(key) ?? { name: key, label: r.name.replace(/.exe$/i, '').replace(/#d+$/, ''), title: null, company: null, path: null, cpu: 0, memMB: 0, count: 0 };
    g.cpu += r.cpu;
    g.memMB += r.mem;
    g.count += 1;
    g.title ||= r.title || null;
    g.company ||= r.company || null;
    g.path ||= r.path || null;
    map.set(key, g);
  }
  return [...map.values()].map((g) => ({ ...g, cpu: Math.round(g.cpu * 10) / 10, memMB: Math.round(g.memMB) }));
}

/** "FC Online 45% · Brave 20%" (cpu) or "FC Online 3.1 GB · Brave 1.2 GB" (memory). */
export function culpritText(groups: ProcGroup[], by: 'cpu' | 'mem', n = 3): string {
  const top = [...groups].sort((a, b) => (by === 'cpu' ? b.cpu - a.cpu : b.memMB - a.memMB)).filter((g) => (by === 'cpu' ? g.cpu >= 1 : g.memMB >= 100)).slice(0, n);
  return top.map((g) => `${g.title || g.label} ${by === 'cpu' ? `${Math.round(g.cpu)}%` : g.memMB >= 1024 ? `${(g.memMB / 1024).toFixed(1)} GB` : `${g.memMB} MB`}`).join(' · ');
}

/* ---------- taking the snapshot ---------- */

const PS = `
$ErrorActionPreference = 'SilentlyContinue'
$n = [Environment]::ProcessorCount
$rows = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' } | ForEach-Object {
  [pscustomobject]@{ pid = [int]$_.IDProcess; name = $_.Name; cpu = [math]::Round($_.PercentProcessorTime / $n, 1); mem = [math]::Round($_.WorkingSetPrivate / 1MB, 1) }
}
$names = @(Get-Process | ForEach-Object { $_.ProcessName.ToLower() } | Sort-Object -Unique)
$top = @($rows | Sort-Object cpu -Descending | Select-Object -First 25) + @($rows | Sort-Object mem -Descending | Select-Object -First 25)
$seen = @{}
$all = foreach ($r in $rows) {
  $o = [ordered]@{ pid = $r.pid; name = $r.name; cpu = $r.cpu; mem = $r.mem }
  if (($top | Where-Object { $_.pid -eq $r.pid }) -and -not $seen[$r.pid]) {
    $seen[$r.pid] = 1
    $p = Get-Process -Id $r.pid
    if ($p) { $o.name = $p.ProcessName; $o.title = $p.Description; $o.company = $p.Company; $o.path = $p.Path }
  }
  [pscustomobject]$o
}
[pscustomobject]@{ rows = @($all); names = $names } | ConvertTo-Json -Compress -Depth 3
`;

let latest: Snapshot | null = null;
let inflight: Promise<Snapshot | null> | null = null;

export function takeSnapshot(): Promise<Snapshot | null> {
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      let parsed: { rows: Raw[]; names: string[] };
      if (process.env.SENTINEL_TEST_PROCESSES) parsed = JSON.parse(process.env.SENTINEL_TEST_PROCESSES);
      else {
        const { stdout } = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS], { timeout: 30_000, windowsHide: true, maxBuffer: 8 * 1024 * 1024 });
        parsed = JSON.parse(stdout);
      }
      latest = { at: Date.now(), groups: groupProcesses(parsed.rows ?? []), running: (parsed.names ?? []).map(normName) };
      return latest;
    } catch (e) {
      console.error('[processes] snapshot failed:', e instanceof Error ? e.message.split('\n')[0] : e);
      return latest;
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

export const latestSnapshot = (maxAgeMs = 5 * 60_000, now = Date.now()) => (latest && now - latest.at <= maxAgeMs ? latest : null);

/** Called after each host sample: refresh the snapshot only while the PC is busy (that is when alerts need it). */
export function refreshIfBusy() {
  const id = getLocalAssetId();
  if (id == null) return;
  const m = get<{ cpu_pct: number | null; mem_pct: number | null }>('SELECT cpu_pct, mem_pct FROM host_metrics WHERE asset_id = ? ORDER BY ts DESC LIMIT 1', id);
  if (!m || ((m.cpu_pct ?? 0) < 70 && (m.mem_pct ?? 0) < 85)) return;
  if (latest && Date.now() - latest.at < 2 * 60_000) return;
  void takeSnapshot();
}

/* ---------- game mode ---------- */

export type GameMode = { enabled: boolean; processes: string[] };
export const getGameMode = (): GameMode => {
  const g = getJsonSetting<GameMode>('game_mode', { enabled: true, processes: ['fczf'] });
  return { enabled: g.enabled !== false, processes: (g.processes ?? []).map(normName).filter(Boolean) };
};

/** The game that is running right now (from a recent snapshot), or null. */
export function runningGame(snap: Snapshot | null = latestSnapshot(), mode = getGameMode()): ProcGroup | { name: string; title: null } | null {
  if (!snap || !mode.enabled || !mode.processes.length) return null;
  const hit = mode.processes.find((p) => snap.running.includes(p));
  if (!hit) return null;
  return snap.groups.find((g) => g.name === hit) ?? { name: hit, title: null };
}

/* ---------- closing a program ---------- */

async function killProgram(name: string): Promise<number> {
  const own = [process.pid, process.ppid];
  const script = `
$own = @(${own.join(',')})
$chain = @($own)
foreach ($id in $own) { $p = Get-CimInstance Win32_Process -Filter "ProcessId=$id"; while ($p -and $p.ParentProcessId -and $chain -notcontains $p.ParentProcessId) { $chain += $p.ParentProcessId; $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" } }
$targets = @(Get-Process -Name '${name.replace(/'/g, "''")}' -ErrorAction SilentlyContinue | Where-Object { $chain -notcontains $_.Id })
$targets | Stop-Process -Force -ErrorAction SilentlyContinue
$targets.Count`;
  if (dryRun()) {
    console.log(`[processes] dry run: would close ${name}`);
    return 1;
  }
  const { stdout } = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { timeout: 30_000, windowsHide: true });
  return Number(stdout.trim()) || 0;
}

/* ---------- API ---------- */

export const processesRouter = Router();

processesRouter.get('/', async (req, res) => {
  const snap = req.query.cached === '1' ? latestSnapshot() ?? (await takeSnapshot()) : await takeSnapshot();
  const mode = getGameMode();
  const game = runningGame(snap, mode);
  res.json({
    at: snap?.at ?? null,
    groups: (snap?.groups ?? [])
      .filter((g) => g.cpu >= 0.5 || g.memMB >= 150)
      .sort((a, b) => b.cpu - a.cpu || b.memMB - a.memMB)
      .slice(0, 25)
      .map((g) => ({ ...g, protected: isProtected(g.name), isGame: mode.processes.includes(g.name) })),
    gameMode: mode,
    gameRunning: game ? { name: game.name, title: game.title } : null,
    dryRun: dryRun(),
  });
});

processesRouter.post('/kill', async (req, res) => {
  const b = body(req);
  const name = normName(String(b.name ?? ''));
  if (!/^[\w .()+-]{1,80}$/.test(name)) throw new HttpError(400, 'Unknown program');
  if (isProtected(name)) throw new HttpError(400, 'This is part of Windows, security software or SENTINEL itself — it cannot be closed from here');
  requireStepUp(req, b.code);
  const title = latest?.groups.find((g) => g.name === name)?.title || name;
  const closed = await killProgram(name);
  const device = deviceLabel(userAgentOf(req));
  audit('process.kill', { ip: clientIp(req), detail: { name, closed, device, dryRun: dryRun() } });
  enqueue('system', 'process', `✖ <b>${escHtml(L(`Closed from ${device}: ${title}`, `ปิดโปรแกรมจาก ${device}: ${title}`))}</b>\n${escHtml(L(`${closed} process(es) stopped`, `หยุดไป ${closed} โปรเซส`))}`);
  void takeSnapshot().then(() => publish('power'));
  res.json({ ok: true, closed, dryRun: dryRun() });
});

processesRouter.put('/game-mode', (req, res) => {
  const b = body(req);
  const raw = Array.isArray(b.processes) ? b.processes : [];
  if (raw.length > 30 || !raw.every((x) => typeof x === 'string' && x.length <= 80)) throw new HttpError(400, 'Up to 30 program names');
  const mode: GameMode = { enabled: b.enabled !== false, processes: [...new Set((raw as string[]).map(normName).filter(Boolean))] };
  setSetting('game_mode', JSON.stringify(mode));
  audit('settings.game_mode', { ip: clientIp(req), detail: mode });
  publish('power');
  res.json({ ok: true, gameMode: mode });
});
