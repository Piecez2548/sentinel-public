import { execFile } from 'node:child_process';
import { statfs } from 'node:fs/promises';
import os from 'node:os';
import { promisify } from 'node:util';
import { get, getSetting, run } from '../db.js';
import { publish } from '../lib/bus.js';
import { registerComponent, reportError, reportOk } from '../lib/health.js';

/** Local host metrics collector (ADR-005): CPU, RAM, disks, network of the PC SENTINEL runs on. */

const exec = promisify(execFile);
registerComponent('host', 'Host metrics collector', 60_000);

export type DiskSample = { mount: string; total: number; free: number; usedPct: number };

let localAssetId: number | null = null;
let prevCpu: { idle: number; total: number } | null = null;
let prevNet: { rx: number; tx: number; at: number } | null = null;
let drives: string[] = [];
let drivesScannedAt = 0;

export function localCollectorEnabled() {
  return getSetting('local_collector_enabled') !== 'false';
}

/** Find (or create) the asset that represents this PC. */
export function ensureLocalHost(): number | null {
  if (!localCollectorEnabled()) return null;
  const existing = get<{ asset_id: number }>("SELECT asset_id FROM host_info WHERE collector = 'local' LIMIT 1");
  if (existing) {
    localAssetId = existing.asset_id;
  } else {
    const now = Date.now();
    const r = run(
      "INSERT INTO assets (name, type, environment, target, tags, status, created_at, updated_at) VALUES (?, 'host', 'lab', 'local', '[\"this-pc\"]', 'unknown', ?, ?)",
      os.hostname(), now, now,
    );
    localAssetId = Number(r.lastInsertRowid);
    run('INSERT INTO host_info (asset_id, collector) VALUES (?, ?)', localAssetId, 'local');
  }
  const cpus = os.cpus();
  run(
    'UPDATE host_info SET hostname = ?, os = ?, cpu_model = ?, cores = ?, mem_total = ?, boot_at = ? WHERE asset_id = ?',
    os.hostname(), `${os.version()} (${os.release()})`, cpus[0]?.model?.trim() ?? null, cpus.length, os.totalmem(),
    Date.now() - os.uptime() * 1000, localAssetId,
  );
  return localAssetId;
}

export const getLocalAssetId = () => localAssetId;

function cpuSample() {
  let idle = 0;
  let total = 0;
  for (const c of os.cpus()) {
    idle += c.times.idle;
    total += c.times.idle + c.times.user + c.times.sys + c.times.irq + c.times.nice;
  }
  return { idle, total };
}

async function scanDrives(): Promise<string[]> {
  if (process.platform !== 'win32') return ['/'];
  const found: string[] = [];
  for (const letter of 'CDEFGHIJKLMNOPQRSTUVWXYZ') {
    try {
      const s = await statfs(`${letter}:\\`);
      if (s.blocks > 0) found.push(`${letter}:`);
    } catch {
      /* no such drive / not ready */
    }
  }
  return found;
}

async function diskSamples(): Promise<DiskSample[]> {
  if (Date.now() - drivesScannedAt > 3_600_000) {
    drives = await scanDrives();
    drivesScannedAt = Date.now();
  }
  const out: DiskSample[] = [];
  for (const d of drives) {
    try {
      const s = await statfs(process.platform === 'win32' ? `${d}\\` : d);
      const total = s.blocks * s.bsize;
      const free = s.bavail * s.bsize;
      out.push({ mount: d, total, free, usedPct: total ? Math.round(((total - free) / total) * 1000) / 10 : 0 });
    } catch {
      /* drive went away */
    }
  }
  return out;
}

export type BatterySample = { pct: number; onAc: boolean };
let batteryCheckedAt = 0;
let hasBattery: boolean | null = null;

/**
 * Battery level and charger state (Win32_Battery). Desktops without a battery are detected once
 * and re-checked hourly. SENTINEL_TEST_BATTERY="pct,onAc" (e.g. "15,0") overrides it for tests.
 */
async function batterySample(): Promise<BatterySample | null> {
  const fake = process.env.SENTINEL_TEST_BATTERY;
  if (fake) {
    const [pct, ac] = fake.split(',').map(Number);
    return { pct, onAc: ac === 1 };
  }
  if (process.platform !== 'win32') return null;
  if (hasBattery === false && Date.now() - batteryCheckedAt < 3_600_000) return null;
  batteryCheckedAt = Date.now();
  try {
    const { stdout } = await exec(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', 'Get-CimInstance Win32_Battery | Select-Object -First 1 EstimatedChargeRemaining, BatteryStatus | ConvertTo-Json -Compress'],
      { windowsHide: true, timeout: 15_000 },
    );
    if (!stdout.trim()) {
      hasBattery = false;
      return null;
    }
    const b = JSON.parse(stdout) as { EstimatedChargeRemaining: number | null; BatteryStatus: number | null };
    if (b.EstimatedChargeRemaining == null) {
      hasBattery = false;
      return null;
    }
    hasBattery = true;
    // BatteryStatus 1 = discharging, 4 = low, 5 = critical (all on battery); others = charger connected.
    return { pct: Math.min(100, b.EstimatedChargeRemaining), onAc: ![1, 4, 5].includes(b.BatteryStatus ?? 2) };
  } catch {
    return null;
  }
}

async function netTotals(): Promise<{ rx: number; tx: number } | null> {
  if (process.platform !== 'win32') return null;
  try {
    const { stdout } = await exec('netstat', ['-e'], { windowsHide: true, timeout: 10_000 });
    const line = stdout.split(/\r?\n/).find((l) => /^Bytes\s/.test(l.trim()));
    const nums = line?.trim().split(/\s+/).slice(1).map(Number);
    if (!nums || nums.length < 2 || nums.some((n) => !Number.isFinite(n))) return null;
    return { rx: nums[0], tx: nums[1] };
  } catch {
    return null;
  }
}

export async function collectHost() {
  if (!localCollectorEnabled()) {
    reportOk('host', 'Disabled in settings');
    return;
  }
  if (localAssetId == null) ensureLocalHost();
  if (localAssetId == null) return;
  const asset = get<{ enabled: number; status: string }>('SELECT enabled, status FROM assets WHERE id = ?', localAssetId);
  if (!asset) {
    localAssetId = null; // asset was deleted; recreate next tick
    return;
  }
  if (!asset.enabled) {
    reportOk('host', 'Host asset is paused');
    return;
  }
  try {
    if (process.env.SENTINEL_TEST_FAIL === 'host') throw new Error('Injected failure (SENTINEL_TEST_FAIL)');
    const now = Date.now();
    const cpu = cpuSample();
    let cpuPct: number | null = null;
    if (prevCpu) {
      const dt = cpu.total - prevCpu.total;
      cpuPct = dt > 0 ? Math.round((1 - (cpu.idle - prevCpu.idle) / dt) * 1000) / 10 : null;
    }
    prevCpu = cpu;

    const memTotal = os.totalmem();
    const memUsed = memTotal - os.freemem();
    const disks = await diskSamples();

    let rxBps: number | null = null;
    let txBps: number | null = null;
    const net = await netTotals();
    if (net && prevNet && net.rx >= prevNet.rx && net.tx >= prevNet.tx) {
      const secs = (now - prevNet.at) / 1000;
      rxBps = Math.round((net.rx - prevNet.rx) / secs);
      txBps = Math.round((net.tx - prevNet.tx) / secs);
    }
    if (net) prevNet = { ...net, at: now };
    const battery = await batterySample();

    if (cpuPct != null) {
      run(
        'INSERT INTO host_metrics (asset_id, ts, cpu_pct, mem_pct, mem_used, mem_total, disks, net_rx_bps, net_tx_bps, battery_pct, on_ac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        localAssetId, now, cpuPct, Math.round((memUsed / memTotal) * 1000) / 10, memUsed, memTotal, JSON.stringify(disks), rxBps, txBps,
        battery?.pct ?? null, battery ? (battery.onAc ? 1 : 0) : null,
      );
    }
    run('UPDATE host_info SET last_seen_at = ?, boot_at = ? WHERE asset_id = ?', now, now - os.uptime() * 1000, localAssetId);
    if (asset.status !== 'up') run("UPDATE assets SET status = 'up', status_since = ? WHERE id = ?", now, localAssetId);
    reportOk('host', cpuPct == null ? 'Warming up (first sample)' : `CPU ${cpuPct}% · RAM ${Math.round((memUsed / memTotal) * 100)}%${battery ? ` · Battery ${battery.pct}%${battery.onAc ? ' (charging)' : ''}` : ''}`);
    publish('metrics', 'assets');
  } catch (e) {
    reportError('host', e instanceof Error ? e.message : String(e));
  }
}

/** Mark hosts offline when no metrics arrive (relevant for future remote agents, and if collection stalls). */
export function markStaleHosts(offlineAfterMs = 3 * 60_000) {
  if (process.uptime() * 1000 < offlineAfterMs) return; // just started; collectors have not reported yet
  const r = run(
    `UPDATE assets SET status = 'down', status_since = ?
     WHERE type = 'host' AND enabled = 1 AND status != 'down'
       AND id IN (SELECT asset_id FROM host_info WHERE last_seen_at IS NOT NULL AND last_seen_at < ?)`,
    Date.now(), Date.now() - offlineAfterMs,
  );
  if (r.changes) publish('assets');
}
