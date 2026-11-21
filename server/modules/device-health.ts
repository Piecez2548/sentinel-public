import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Router } from 'express';
import { all, get, getSetting, run, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { exclusionRisk, SYSTEM_BINARIES, type ExclusionKind } from '../lib/exclusions.js';
import { registerComponent, reportError, reportOk } from '../lib/health.js';
import { clientIp, HttpError } from '../lib/http.js';
import { checkSignature, imagePathToFile } from '../lib/signature.js';
import { DAY, MIN, parseJson } from '../lib/util.js';
import { checkMessage, persistenceMessage, type PersistVerdict } from '../lib/device-messages.js';
import { DEFAULT_TRUSTED_TOOLS, describeOpen, findRemoteTools, isRiskyListener, openPrograms, uacVerdict, type Listener, type Software, type Uac } from '../lib/exposure.js';
import { plainFinding } from '../lib/finding-plain.js';
import { appKey, iconExe, judgeApp, newApps, pickExes, programMessage, removedKeys, trimEvents, uniqueApps, type App, type ProgramEvent } from '../lib/new-programs.js';
import { diffExtensions, extensionMessage, judgeExt, trimExtEvents, type ExtBaseline, type ExtEvent, type ExtProfile, type ExtVerdict } from '../lib/browser-ext.js';
import { readBrowserExtensions } from '../lib/browser-ext-read.js';
import { diffNet, keyParts, netMessage, trimNetEvents, type NetBaseline, type NetEvent, type NetSnap } from '../lib/net-watch.js';
import { judgePhone, mergeCheckin, parsePhone, PHONE_ID, STALE_MS, type PhoneHints, type PhoneRecord } from '../lib/phone-health.js';
import { diffPeriph, judgePeriph, periphMessage, periphSectionOf, trimPeriphEvents, wifiRisk, type PeriphBaseline, type PeriphEvent, type PeriphSnap } from '../lib/periph-watch.js';
import { diffSys, expandApp, judgeSys, sectionOf, settingName, sysMessage, trimSysEvents, type Sig, type SysBaseline, type SysEvent, type SysItem, type SysSnap } from '../lib/sys-watch.js';
import { upsertFinding } from './detection.js';
import { getLocalAssetId } from './host-collector.js';

/**
 * Device health (read-only): is this PC's protection actually working, and did anything new
 * set itself to start automatically? Runs scripts/device-health.ps1 every 30 minutes.
 * Problems become findings (rule device_protection / persistence_added) that resolve themselves
 * once fixed. Nothing on the machine is changed.
 */

const exec = promisify(execFile);
const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), '../../scripts/device-health.ps1');
export const DEVICE_HEALTH_EVERY_MS = 30 * MIN;
registerComponent('device_health', 'Device health checks', DEVICE_HEALTH_EVERY_MS);

/* ---------- snapshot shape (from the PowerShell script) ---------- */

export type Snapshot = {
  isAdmin: boolean;
  defender: { antivirusEnabled: boolean; realTimeProtection: boolean; tamperProtected: boolean; signatureAgeDays: number; signatureVersion: string; quickScanAgeDays: number; fullScanAgeDays: number; lastQuickScan: string | null } | null;
  updates: { lastInstalled: string | null; lastHotfix: string | null; rebootPending: boolean } | null;
  firewall: { name: string; enabled: boolean }[] | null;
  encryption: { available: boolean; needsAdmin?: boolean; drive?: string; protection?: string; status?: string; percent?: number } | null;
  disks: { name: string; media: string; sizeGb: number; health: string; operational: string; wearPct: number | null; temperatureC: number | null }[] | null;
  battery: { designMWh: number; fullMWh: number; cycles: number | null } | null;
  exclusions: { needsAdmin?: boolean; paths?: string[]; processes?: string[]; extensions?: string[] } | null;
  startup: { name: string; command: string; location: string; user: string }[] | null;
  tasks: { path: string; name: string; author: string; exec: string }[] | null;
  /* Added 2026-11-16; older snapshots (and tests) may not have them. */
  uac?: Uac | null;
  software?: Software | null;
  listeners?: Listener[] | null;
  /* Added 2026-11-20: hosts file, hand-typed DNS, proxies. */
  network?: NetSnap | null;
  /* Added 2026-11-21: trusted root certificates, inbound firewall allow rules, security settings. */
  system?: SysSnap | null;
  /* Added 2026-11-21: disks / USB drives, keyboard devices, saved and current Wi-Fi. */
  peripherals?: PeriphSnap | null;
  /** Tests only: browser profiles (the live server reads them itself). */
  extensions?: ExtProfile[] | null;
};

/** What the owner has approved: remote tools they keep, and programs allowed to listen on every network (null = not recorded yet). */
export type Trust = { tools: string[]; ports: string[] | null };

/** status: ok | warn | bad | unknown. severity is set for warn/bad. msg is an English key with {placeholders}. */
export type Check = { id: string; status: 'ok' | 'warn' | 'bad' | 'unknown'; severity?: string; msg: string; vars?: Record<string, string | number>; items?: string[]; keys?: string[] };

export const CHECK_LABELS: Record<string, string> = {
  defender_av: 'Antivirus protection',
  defender_signatures: 'Virus definitions',
  defender_exclusions: 'Defender exclusions',
  defender_scan: 'Recent scans',
  firewall: 'Firewall',
  updates: 'Windows Update',
  encryption: 'Disk encryption (BitLocker)',
  disks: 'Disk health',
  battery: 'Battery health',
  uac: 'User Account Control (UAC)',
  remote_tools: 'Remote-control programs',
  open_ports: 'Open to the network',
};

const daysSince = (iso: string | null | undefined, now: number) => (iso ? Math.floor((now - Date.parse(iso)) / DAY) : null);

/** Pure: turns a snapshot into checks. Exported for tests. */
export function evaluate(s: Snapshot, now = Date.now(), trust: Trust = { tools: DEFAULT_TRUSTED_TOOLS, ports: null }): Check[] {
  const out: Check[] = [];
  const d = s.defender;

  if (!d) out.push({ id: 'defender_av', status: 'unknown', msg: 'Could not read Defender status' });
  else if (d.antivirusEnabled && d.realTimeProtection) out.push({ id: 'defender_av', status: 'ok', msg: 'Antivirus and real-time protection are on', items: d.tamperProtected ? ['Tamper protection on'] : ['Tamper protection off'] });
  else out.push({ id: 'defender_av', status: 'bad', severity: 'high', msg: 'Real-time protection is off' });

  if (d) {
    const n = d.signatureAgeDays;
    if (n <= 2) out.push({ id: 'defender_signatures', status: 'ok', msg: 'Updated {n} day(s) ago', vars: { n }, items: [`v${d.signatureVersion}`] });
    else out.push({ id: 'defender_signatures', status: n <= 7 ? 'warn' : 'bad', severity: n <= 7 ? 'medium' : 'high', msg: 'Definitions are {n} day(s) old', vars: { n } });

    if (d.quickScanAgeDays <= 7) out.push({ id: 'defender_scan', status: 'ok', msg: 'Quick scan {q} day(s) ago · full scan {f} day(s) ago', vars: { q: d.quickScanAgeDays, f: d.fullScanAgeDays } });
    else out.push({ id: 'defender_scan', status: 'warn', severity: 'low', msg: 'No scan for {q} day(s)', vars: { q: d.quickScanAgeDays } });
  }

  const ex = s.exclusions;
  if (!ex) out.push({ id: 'defender_exclusions', status: 'unknown', msg: 'Could not read Defender exclusions' });
  else if (ex.needsAdmin) out.push({ id: 'defender_exclusions', status: 'unknown', msg: 'Needs administrator rights to read' });
  else {
    const all: { kind: ExclusionKind; value: string }[] = [
      ...(ex.paths ?? []).map((value) => ({ kind: 'Paths' as const, value })),
      ...(ex.processes ?? []).map((value) => ({ kind: 'Processes' as const, value })),
      ...(ex.extensions ?? []).map((value) => ({ kind: 'Extensions' as const, value })),
    ];
    const risky = all.map((x) => ({ ...x, risk: exclusionRisk(x.kind, x.value) })).filter((x) => x.risk);
    if (risky.length) {
      out.push({
        id: 'defender_exclusions', status: 'bad', severity: 'critical', msg: '{n} dangerous exclusion(s) — Defender skips these', vars: { n: risky.length },
        items: [...risky.map((x) => `⚠ ${x.value} — ${x.risk}`), ...all.filter((x) => !exclusionRisk(x.kind, x.value)).map((x) => x.value)],
      });
    } else if (all.length) out.push({ id: 'defender_exclusions', status: 'warn', severity: 'low', msg: '{n} exclusion(s), none look dangerous', vars: { n: all.length }, items: all.map((x) => x.value) });
    else out.push({ id: 'defender_exclusions', status: 'ok', msg: 'No scan exclusions' });
  }

  if (!s.firewall) out.push({ id: 'firewall', status: 'unknown', msg: 'Could not read firewall status' });
  else {
    const off = s.firewall.filter((p) => !p.enabled).map((p) => p.name);
    out.push(off.length ? { id: 'firewall', status: 'bad', severity: 'medium', msg: 'Off for: {list}', vars: { list: off.join(', ') } } : { id: 'firewall', status: 'ok', msg: 'On for all networks' });
  }

  const u = s.updates;
  if (!u) out.push({ id: 'updates', status: 'unknown', msg: 'Could not read update history' });
  else {
    const n = daysSince(u.lastInstalled, now);
    if (n == null) out.push({ id: 'updates', status: 'unknown', msg: 'No update history found' });
    else if (n > 35) out.push({ id: 'updates', status: 'warn', severity: 'medium', msg: 'Last update installed {n} days ago', vars: { n } });
    else if (u.rebootPending) out.push({ id: 'updates', status: 'warn', severity: 'low', msg: 'Restart needed to finish installing updates' });
    else out.push({ id: 'updates', status: 'ok', msg: 'Last update {n} day(s) ago', vars: { n }, items: u.lastHotfix ? [u.lastHotfix] : undefined });
  }

  const e = s.encryption;
  if (!e || e.needsAdmin) out.push({ id: 'encryption', status: 'unknown', msg: e?.needsAdmin ? 'Needs administrator rights to read' : 'Could not read encryption status' });
  else if (!e.available) out.push({ id: 'encryption', status: 'unknown', msg: 'BitLocker is not available on this Windows edition' });
  else if (e.protection === 'On') out.push({ id: 'encryption', status: 'ok', msg: 'Drive {d} is encrypted', vars: { d: e.drive ?? 'C:' } });
  else out.push({ id: 'encryption', status: 'warn', severity: 'low', msg: 'Drive {d} is not encrypted — data is readable if the laptop is lost', vars: { d: e.drive ?? 'C:' } });

  if (!s.disks?.length) out.push({ id: 'disks', status: 'unknown', msg: 'Could not read disk health' });
  else {
    const items = s.disks.map((k) => `${k.name} (${k.sizeGb} GB ${k.media}) · ${k.health}${k.wearPct != null ? ` · wear ${k.wearPct}%` : ''}${k.temperatureC ? ` · ${k.temperatureC}°C` : ''}`);
    const bad = s.disks.filter((k) => k.health !== 'Healthy');
    const worn = s.disks.filter((k) => (k.wearPct ?? 0) >= 80);
    if (bad.length) out.push({ id: 'disks', status: 'bad', severity: 'high', msg: '{n} disk(s) report a problem — back up now', vars: { n: bad.length }, items });
    else if (worn.length) out.push({ id: 'disks', status: 'warn', severity: 'medium', msg: '{n} SSD(s) near end of life', vars: { n: worn.length }, items });
    else out.push({ id: 'disks', status: 'ok', msg: 'All {n} disk(s) healthy', vars: { n: s.disks.length }, items });
  }

  const b = s.battery;
  if (b && b.designMWh > 0) {
    const pct = Math.round((b.fullMWh / b.designMWh) * 100);
    const vars = { p: Math.min(pct, 100), c: b.cycles ?? '?' };
    out.push(pct < 50 ? { id: 'battery', status: 'warn', severity: 'low', msg: 'Holds {p}% of its original charge ({c} cycles) — consider replacing', vars } : { id: 'battery', status: 'ok', msg: 'Holds {p}% of its original charge ({c} cycles)', vars });
  }
  out.push(...exposureChecks(s, trust));
  return out;
}

/** UAC, remote-control programs and programs open to every network. Sections missing from the snapshot are skipped. */
export function exposureChecks(s: Snapshot, trust: Trust, windir = process.env.SystemRoot ?? 'C:\\Windows'): Check[] {
  const out: Check[] = [];
  if (s.uac !== undefined) {
    if (!s.uac) out.push({ id: 'uac', status: 'unknown', msg: 'Could not read UAC settings' });
    else out.push({ id: 'uac', ...uacVerdict(s.uac) });
  }

  if (s.software !== undefined) {
    if (!s.software) out.push({ id: 'remote_tools', status: 'unknown', msg: 'Could not read installed programs' });
    else {
      const found = findRemoteTools(s.software);
      const ok = new Set(trust.tools.map((t) => t.toLowerCase()));
      const unknown = found.filter((t) => !ok.has(t.name.toLowerCase()));
      const approved = found.filter((t) => ok.has(t.name.toLowerCase()));
      if (unknown.length)
        out.push({
          id: 'remote_tools', status: 'bad', severity: 'high', msg: '{n} remote-control program(s) you have not approved: {list}',
          vars: { n: unknown.length, list: unknown.map((t) => t.name).join(', ') },
          items: [...unknown.map((t) => `⚠ ${t.name} — ${t.where}`), ...approved.map((t) => `${t.name} — ${t.where} (approved)`)],
          keys: unknown.map((t) => t.name),
        });
      else if (approved.length)
        out.push({ id: 'remote_tools', status: 'ok', msg: 'Only approved remote-control programs: {list}', vars: { list: approved.map((t) => t.name).join(', ') }, items: approved.map((t) => `${t.name} — ${t.where}`) });
      else out.push({ id: 'remote_tools', status: 'ok', msg: 'No remote-control programs installed' });
    }
  }

  if (s.listeners !== undefined) {
    if (!s.listeners) out.push({ id: 'open_ports', status: 'unknown', msg: 'Could not read open ports' });
    else {
      const open = openPrograms(s.listeners, windir);
      const known = trust.ports ? new Set(trust.ports) : null;
      const fresh = known ? open.filter((p) => !known.has(p.key)) : [];
      if (fresh.length) {
        out.push({
          id: 'open_ports', status: 'warn', severity: fresh.some(isRiskyListener) ? 'high' : 'medium',
          msg: '{n} new program(s) accept connections from any network: {list}', vars: { n: fresh.length, list: fresh.map((p) => p.process).join(', ') },
          items: [...fresh.map((p) => `${isRiskyListener(p) ? '⚠ ' : ''}${describeOpen(p)}`), ...open.filter((p) => !fresh.includes(p)).map((p) => `${describeOpen(p)} (known)`)],
          keys: fresh.map((p) => p.key),
        });
      } else
        out.push({
          id: 'open_ports', status: 'ok', msg: open.length ? '{n} known program(s) accept connections from any network' : 'Nothing accepts connections from other devices',
          vars: { n: open.length }, items: open.map(describeOpen),
        });
    }
  }
  return out;
}

/* ---------- auto-start programs and scheduled tasks ---------- */

export type PersistItem = { kind: 'startup' | 'task'; key: string; name: string; command: string; where: string };

export function persistenceItems(s: Snapshot): PersistItem[] {
  const startup = (s.startup ?? []).map((x) => ({ kind: 'startup' as const, key: `startup|${x.location}|${x.name}|${x.command}`.toLowerCase(), name: x.name, command: x.command, where: x.location }));
  const tasks = (s.tasks ?? []).filter((x) => x.exec).map((x) => ({ kind: 'task' as const, key: `task|${x.path}${x.name}|${x.exec}`.toLowerCase(), name: `${x.path}${x.name}`, command: x.exec, where: x.author || 'Task Scheduler' }));
  return [...startup, ...tasks];
}

const expandEnv = (s: string) => s.replace(/%([^%]+)%/g, (m, v: string) => process.env[v] ?? process.env[v.toUpperCase()] ?? m);
export const commandFile = (command: string) => imagePathToFile(expandEnv(command.split(' ; ')[0]));

/** A program named like a Windows system binary but living outside the Windows folder. */
export function masquerades(command: string, windir = process.env.SystemRoot ?? 'C:\\Windows'): string | null {
  const file = commandFile(command);
  if (!file) return null;
  const base = file.split('\\').pop()!.toLowerCase();
  if (!SYSTEM_BINARIES.has(base)) return null;
  return file.toLowerCase().startsWith(`${windir.toLowerCase()}\\`) ? null : `named like the Windows file ${base} but runs from ${file}`;
}

const assetLabel = (id: number) => get<{ name: string }>('SELECT name FROM assets WHERE id = ?', id)?.name ?? `asset #${id}`;

const fp = (assetId: number, it: PersistItem) => `persistence_added:${assetId}:${createHash('sha1').update(it.key).digest('hex').slice(0, 16)}`;

async function judgePersistence(assetId: number, it: PersistItem, isNew: boolean) {
  const fake = masquerades(it.command);
  if (!fake && !isNew) return null;
  let severity = 'medium';
  let why = '';
  let reason: PersistVerdict['reason'] = 'unknown';
  let signer: string | undefined;
  if (fake) {
    severity = 'critical';
    why = fake;
    reason = 'masquerade';
  } else {
    const file = commandFile(it.command);
    if (file && !existsSync(file)) {
      severity = 'high';
      why = 'the program file does not exist (left behind or deleted after running)';
      reason = 'missing';
    } else {
      const sig = await checkSignature(it.command.split(' ; ')[0]);
      if (sig.state === 'signed') {
        severity = 'low';
        why = `signed by ${sig.signer}`;
        reason = 'signed';
        signer = sig.signer;
      } else if (sig.state === 'unknown') why = sig.detail;
      else {
        severity = 'high';
        why = sig.detail;
        reason = 'unsigned';
      }
    }
  }
  const msg = persistenceMessage({ kind: it.kind, name: it.name, command: it.command, severity, reason, signer }, assetLabel(assetId));
  upsertFinding({
    notify: { en: msg.en, th: msg.th },
    ruleId: 'persistence_added',
    assetId,
    severity,
    title: `${it.kind === 'startup' ? 'Auto-start program' : 'Scheduled task'}: ${it.name}`,
    summary: `${it.command} (${it.where}) — ${why}`,
    fingerprint: fp(assetId, it),
    condition: `${isNew ? 'New since the last check' : 'Present'} · ${it.kind === 'startup' ? 'Run key / Startup folder' : 'Task Scheduler'}`,
    extra: { details: { kind: it.kind, name: it.name, command: it.command, where: it.where, assessment: why, headlineTh: msg.headlineTh, headlineEn: msg.headlineEn } },
    mergeWindowMs: 365 * DAY,
  });
  return severity;
}

/* ---------- newly installed programs ---------- */

const PROG_BASELINE = 'device_programs_baseline';
const PROG_EVENTS = 'device_programs_events';
/** More new programs than this in one run is not a person installing things: record them, but don't raise a finding each. */
const MAX_FINDINGS_PER_RUN = 20;
const progFp = (assetId: number, key: string) => `program_installed:${assetId}:${createHash('sha1').update(key).digest('hex').slice(0, 16)}`;

/** The program's own .exe: its icon file, else the biggest .exe in its install folder (never the uninstaller). */
function programFiles(a: App): string[] {
  const icon = iconExe(a.icon);
  if (icon && existsSync(icon)) return [icon];
  const dir = (a.location ?? '').replace(/"/g, '').trim();
  if (!/^[a-z]:\\/i.test(dir)) return [];
  try {
    const files = readdirSync(dir, { withFileTypes: true }).filter((d) => d.isFile()).map((d) => ({ name: d.name, size: statSync(join(dir, d.name)).size }));
    return pickExes(files).map((n) => join(dir, n));
  } catch {
    return [];
  }
}

export function programEvents(): ProgramEvent[] {
  return parseJson<ProgramEvent[]>(getSetting(PROG_EVENTS) ?? '[]', []);
}

async function watchPrograms(assetId: number, s: Snapshot, now: number): Promise<{ count: number; baselineAt: number | null; added: number } | null> {
  const apps = s.software?.apps;
  if (!apps) return null;
  const list = uniqueApps(apps);
  const raw = getSetting(PROG_BASELINE);
  const baseline = raw ? parseJson<Record<string, string>>(raw, {}) : null;
  const keys = new Set(Object.keys(baseline ?? {}));
  // A half-read registry would look like everything was uninstalled (and reinstalled next time): skip that run.
  if (baseline && list.length < keys.size * 0.5) return { count: list.length, baselineAt: Number(getSetting('device_programs_baseline_at')) || null, added: 0 };
  let events = programEvents();
  let added = 0;
  if (baseline) {
    for (const a of newApps(list, keys)) {
      const sigs = await Promise.all(programFiles(a).map((f) => checkSignature(`"${f}"`)));
      const v = judgeApp(a, sigs);
      events.push({ kind: 'added', name: a.name, version: a.version || undefined, publisher: a.publisher || undefined, at: now, severity: v.severity, reason: v.reason, signer: v.signer });
      if (++added > MAX_FINDINGS_PER_RUN) continue;
      const msg = programMessage(a, v, assetLabel(assetId));
      upsertFinding({
        notify: { en: msg.en, th: msg.th },
        ruleId: 'program_installed',
        assetId,
        severity: v.severity,
        title: `New program: ${a.name}${a.version && !a.name.includes(a.version) ? ` ${a.version}` : ''}`,
        summary: `${a.publisher || 'unknown publisher'} — ${v.detail}`,
        fingerprint: progFp(assetId, appKey(a)),
        condition: 'New since the last device check · installed programs (registry Uninstall keys)',
        extra: { details: { name: a.name, version: a.version, publisher: a.publisher, location: a.location, reason: v.reason, signer: v.signer, file: v.file, assessment: v.detail, headlineTh: msg.headlineTh, headlineEn: msg.headlineEn } },
        mergeWindowMs: 365 * DAY,
      });
    }
    for (const k of removedKeys(list, keys)) {
      events.push({ kind: 'removed', name: baseline[k] ?? k.split('|')[0], at: now });
      run(
        "UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Uninstalled — auto-resolved' WHERE fingerprint = ? AND status IN ('open','acknowledged')",
        now, progFp(assetId, k),
      );
    }
  } else setSetting('device_programs_baseline_at', String(now));
  setSetting(PROG_BASELINE, JSON.stringify(Object.fromEntries(list.map((a) => [appKey(a), a.name]))));
  setSetting(PROG_EVENTS, JSON.stringify(trimEvents(events, now)));
  return { count: list.length, baselineAt: Number(getSetting('device_programs_baseline_at')) || null, added };
}

/* ---------- browser extensions ---------- */

const EXT_BASELINE = 'device_extensions_baseline';
const EXT_EVENTS = 'device_extensions_events';
const extFp = (assetId: number, key: string) => `browser_extension:${assetId}:${createHash('sha1').update(key).digest('hex').slice(0, 16)}`;

export type ExtSummary = {
  count: number;
  baselineAt: number | null;
  added: number;
  list: { browser: string; profile: string; id: string; name: string; version?: string; severity: ExtVerdict['severity']; reason: ExtVerdict['reason']; powers: string[] }[];
};

export function extensionEvents(): ExtEvent[] {
  return parseJson<ExtEvent[]>(getSetting(EXT_EVENTS) ?? '[]', []);
}

/** New extensions, ones that gained powers in an update, and removed ones (first run only records what is there). */
function watchExtensions(assetId: number, profiles: ExtProfile[] | null, now: number): ExtSummary | null {
  if (!profiles) return null;
  const raw = getSetting(EXT_BASELINE);
  const base = raw ? parseJson<ExtBaseline | null>(raw, null) : null;
  const { changes, next } = diffExtensions(profiles, base);
  const events = extensionEvents();
  let added = 0;
  for (const c of changes) {
    if (c.kind === 'removed') {
      events.push({ kind: 'removed', name: c.name, browser: c.browser, at: now });
      run(
        "UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Extension removed — auto-resolved' WHERE fingerprint LIKE ? AND status IN ('open','acknowledged')",
        now, `${extFp(assetId, c.key)}%`,
      );
      continue;
    }
    const { ext: e, verdict: v } = c;
    added++;
    events.push({ kind: c.kind, name: e.name, browser: e.browser, at: now, severity: v.severity, reason: v.reason, powers: c.kind === 'gained' ? v.gained : v.powers });
    if (added > MAX_FINDINGS_PER_RUN) continue;
    const msg = extensionMessage(e, v, assetLabel(assetId));
    const key = `${e.browser}|${e.profile}|${e.id}`;
    upsertFinding({
      notify: { en: msg.en, th: msg.th },
      ruleId: 'browser_extension',
      assetId,
      severity: v.severity,
      title: `${c.kind === 'gained' ? 'Extension gained permissions' : 'New browser extension'}: ${e.name} (${e.browser})`,
      summary: v.detail,
      // An update that adds powers is its own finding (the install may already be approved).
      fingerprint: c.kind === 'gained' ? `${extFp(assetId, key)}:${(v.gained ?? []).join(',')}` : extFp(assetId, key),
      condition: 'New since the last device check · browser extensions (Chromium profile preferences)',
      extra: { details: { name: e.name, browser: e.browser, profile: e.profile, id: e.id, version: e.version, kind: c.kind, reason: v.reason, powers: v.powers, gained: v.gained, fromStore: e.fromStore, location: e.location, assessment: v.detail, headlineTh: msg.headlineTh, headlineEn: msg.headlineEn } },
      mergeWindowMs: 365 * DAY,
    });
  }
  if (!base) setSetting('device_extensions_baseline_at', String(now));
  setSetting(EXT_BASELINE, JSON.stringify(next));
  setSetting(EXT_EVENTS, JSON.stringify(trimExtEvents(events, now)));
  const list = profiles
    .flatMap((p) => p.exts)
    .map((e) => {
      const v = judgeExt(e);
      return { browser: e.browser, profile: e.profile, id: e.id, name: e.name, version: e.version, severity: v.severity, reason: v.reason, powers: v.powers };
    });
  return { count: list.length, baselineAt: Number(getSetting('device_extensions_baseline_at')) || null, added, list };
}

/* ---------- hosts file, DNS and proxies ---------- */

const NET_BASELINE = 'device_network_baseline';
const NET_EVENTS = 'device_network_events';
const netFp = (assetId: number, key: string) => `network_changed:${assetId}:${createHash('sha1').update(key).digest('hex').slice(0, 16)}`;

export type NetSummary = {
  baselineAt: number | null;
  added: number;
  hosts: { name: string; ip: string }[];
  dns: { name: string; servers: string[] }[];
  proxies: { name: string; value: string }[];
  rules: { name: string; value: string }[];
};

export function networkEvents(): NetEvent[] {
  return parseJson<NetEvent[]>(getSetting(NET_EVENTS) ?? '[]', []);
}

function watchNetwork(assetId: number, n: NetSnap | null | undefined, now: number): NetSummary | null {
  if (!n) return null;
  const raw = getSetting(NET_BASELINE);
  const base = raw ? parseJson<NetBaseline | null>(raw, null) : null;
  const { changes, next, items } = diffNet(n, base);
  const events = networkEvents();
  let added = 0;
  for (const c of changes) {
    if (c.kind === 'removed') {
      const k = keyParts(c.key);
      events.push({ kind: 'removed', what: k.what, name: k.what === 'dns' ? 'DNS' : k.name, value: k.value, at: now });
      run("UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Setting removed — auto-resolved' WHERE fingerprint = ? AND status IN ('open','acknowledged')", now, netFp(assetId, c.key));
      continue;
    }
    const { item: it, verdict: v } = c;
    events.push({ kind: 'added', what: it.kind, name: it.name, value: it.value, at: now, severity: v.severity, reason: v.reason });
    if (++added > MAX_FINDINGS_PER_RUN) continue;
    const msg = netMessage(it, v, assetLabel(assetId));
    upsertFinding({
      notify: { en: msg.en, th: msg.th },
      ruleId: 'network_changed',
      assetId,
      severity: v.severity,
      title: msg.headlineEn,
      summary: v.detail,
      fingerprint: netFp(assetId, it.key),
      condition: 'New since the last device check · hosts file / DNS servers / proxy settings',
      extra: { details: { kind: it.kind, name: it.name, value: it.value, where: it.where, reason: v.reason, assessment: v.detail, headlineTh: msg.headlineTh, headlineEn: msg.headlineEn } },
      mergeWindowMs: 365 * DAY,
    });
  }
  if (!base) setSetting('device_network_baseline_at', String(now));
  setSetting(NET_BASELINE, JSON.stringify(next));
  setSetting(NET_EVENTS, JSON.stringify(trimNetEvents(events, now)));
  const dns = new Map<string, string[]>();
  for (const i of items.filter((x) => x.kind === 'dns')) dns.set(i.name, [...(dns.get(i.name) ?? []), i.value]);
  return {
    baselineAt: Number(getSetting('device_network_baseline_at')) || null,
    added,
    hosts: items.filter((i) => i.kind === 'hosts').slice(0, 50).map((i) => ({ name: i.name, ip: i.value })),
    dns: [...dns].map(([name, servers]) => ({ name, servers })),
    proxies: items.filter((i) => i.kind === 'proxy' || i.kind === 'pac' || i.kind === 'winhttp').map((i) => ({ name: i.name, value: i.value })),
    rules: items.filter((i) => i.kind === 'nrpt').map((i) => ({ name: i.name, value: i.value })),
  };
}

/* ---------- root certificates, firewall rules, security settings ---------- */

const SYS_BASELINE = 'device_system_baseline';
const SYS_EVENTS = 'device_system_events';
const sysFp = (assetId: number, key: string) => `system_changed:${assetId}:${createHash('sha1').update(key).digest('hex').slice(0, 16)}`;

export type SysSummary = {
  baselineAt: number | null;
  added: number;
  certs: { total: number; added: number; byHand: { name: string; store: string; until?: string }[] };
  firewall: { total: number; open: number };
  settings: { id: string; name: string }[];
  readable: { cert: boolean; firewall: boolean; setting: boolean };
};

export function systemEvents(): SysEvent[] {
  return parseJson<SysEvent[]>(getSetting(SYS_EVENTS) ?? '[]', []);
}

/** Signature of the program a new firewall rule lets in (missing file = leftover rule). Read-only. */
async function ruleSig(it: SysItem): Promise<Sig | undefined> {
  const r = it.rule;
  if (!r?.app || r.builtin || /^system$/i.test(r.app)) return undefined;
  const p = expandApp(r.app);
  if (!/^[a-z]:\\/i.test(p)) return undefined;
  if (!existsSync(p)) return { state: 'missing' };
  const s = await checkSignature(`"${p}"`);
  return s.state === 'signed' ? { state: 'signed', signer: s.signer } : { state: s.state };
}

async function watchSystem(assetId: number, n: SysSnap | null | undefined, now: number): Promise<SysSummary | null> {
  if (!n) return null;
  const raw = getSetting(SYS_BASELINE);
  const base = raw ? parseJson<SysBaseline | null>(raw, null) : null;
  const { changes, next, items } = diffSys(n, base);
  const events = systemEvents();
  let added = 0;
  for (const c of changes) {
    if (c.kind === 'removed') {
      events.push({ kind: 'removed', section: sectionOf(c.key), name: c.name, value: '', at: now });
      run("UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Removed or switched back — auto-resolved' WHERE fingerprint = ? AND status IN ('open','acknowledged')", now, sysFp(assetId, c.key));
      continue;
    }
    const it = c.item;
    const v = judgeSys(it, await ruleSig(it));
    events.push({ kind: 'added', section: it.section, name: it.name, value: it.section === 'cert' ? it.cert!.store : it.value, at: now, severity: v.severity, reason: v.reason });
    if (++added > MAX_FINDINGS_PER_RUN) continue;
    const msg = sysMessage(it, v, assetLabel(assetId));
    upsertFinding({
      notify: { en: msg.en, th: msg.th },
      ruleId: 'system_changed',
      assetId,
      severity: v.severity,
      title: msg.headlineEn,
      summary: v.detail,
      fingerprint: sysFp(assetId, it.key),
      condition: 'New since the last device check · root certificates / firewall rules / security settings',
      extra: {
        details: {
          section: it.section,
          name: it.name,
          value: it.value,
          store: it.cert?.store,
          subject: it.cert?.subject,
          thumbprint: it.cert?.thumb,
          until: it.cert?.until,
          app: it.rule ? expandApp(it.rule.app) : undefined,
          rule: it.rule ? { ports: it.rule.ports, protocol: it.rule.protocol, profile: it.rule.profile, remote: it.rule.remote, source: it.rule.src } : undefined,
          reason: v.reason,
          assessment: v.detail,
          headlineTh: msg.headlineTh,
          headlineEn: msg.headlineEn,
        },
      },
      mergeWindowMs: 365 * DAY,
    });
  }
  if (!base) setSetting('device_system_baseline_at', String(now));
  setSetting(SYS_BASELINE, JSON.stringify(next));
  setSetting(SYS_EVENTS, JSON.stringify(trimSysEvents(events, now)));
  const certs = items.filter((i) => i.section === 'cert');
  const rules = items.filter((i) => i.section === 'firewall');
  return {
    baselineAt: Number(getSetting('device_system_baseline_at')) || null,
    added,
    certs: {
      total: certs.length,
      added: certs.filter((c) => c.cert!.store !== 'authroot').length,
      byHand: certs.filter((c) => c.cert!.store !== 'authroot').slice(0, 40).map((c) => ({ name: c.name, store: c.cert!.store, until: c.cert!.until })),
    },
    firewall: { total: rules.length, open: rules.filter((r) => !r.rule!.builtin).length },
    settings: items.filter((i) => i.section === 'setting').map((i) => ({ id: i.setting!, name: settingName(i.setting!) })),
    readable: { cert: n.certsOk !== false && n.certs != null, firewall: n.firewallOk !== false && n.firewall != null, setting: n.settingsOk !== false && n.settings != null },
  };
}

/* ---------- USB drives, keyboards, Wi-Fi ---------- */

const PER_BASELINE = 'device_peripherals_baseline';
const PER_EVENTS = 'device_peripherals_events';
const perFp = (assetId: number, key: string) => `device_connected:${assetId}:${createHash('sha1').update(key).digest('hex').slice(0, 16)}`;

export type PeriphSummary = {
  baselineAt: number | null;
  added: number;
  usbDrives: number;
  disks: number;
  keyboards: number;
  wifi: { saved: number; openAuto: string[]; now: string | null; nowOpen: boolean };
};

export function peripheralEvents(): PeriphEvent[] {
  return parseJson<PeriphEvent[]>(getSetting(PER_EVENTS) ?? '[]', []);
}

function watchPeripherals(assetId: number, n: PeriphSnap | null | undefined, now: number): PeriphSummary | null {
  if (!n) return null;
  const raw = getSetting(PER_BASELINE);
  const base = raw ? parseJson<PeriphBaseline | null>(raw, null) : null;
  const { changes, next, items } = diffPeriph(n, base);
  const newDrive = changes.some((c) => c.kind === 'added' && c.item.section === 'disk' && c.item.usb);
  const events = peripheralEvents();
  let added = 0;
  for (const c of changes) {
    if (c.kind === 'removed') {
      const section = periphSectionOf(c.key);
      // Leaving an open Wi-Fi is not worth a history line; resolving its finding is enough.
      if (section !== 'wifinow') events.push({ kind: 'removed', section, name: c.name, value: '', at: now });
      run("UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Gone — auto-resolved' WHERE fingerprint = ? AND status IN ('open','acknowledged')", now, perFp(assetId, c.key));
      continue;
    }
    const it = c.item;
    const v = judgePeriph(it, { newDrive });
    events.push({ kind: 'added', section: it.section, name: it.name, value: it.value, at: now, severity: v.severity, reason: v.reason });
    if (++added > MAX_FINDINGS_PER_RUN) continue;
    const msg = periphMessage(it, v, assetLabel(assetId));
    upsertFinding({
      notify: { en: msg.en, th: msg.th },
      ruleId: 'device_connected',
      assetId,
      severity: v.severity,
      title: msg.headlineEn,
      summary: v.detail,
      fingerprint: perFp(assetId, it.key),
      condition: 'New since the last device check · USB drives / keyboard devices / Wi-Fi',
      extra: { details: { section: it.section, name: it.name, value: it.value, vid: it.vid, usb: it.usb, auth: it.auth, autoConnect: it.auto, reason: v.reason, assessment: v.detail, headlineTh: msg.headlineTh, headlineEn: msg.headlineEn } },
      mergeWindowMs: 365 * DAY,
    });
  }
  if (!base) setSetting('device_peripherals_baseline_at', String(now));
  setSetting(PER_BASELINE, JSON.stringify(next));
  setSetting(PER_EVENTS, JSON.stringify(trimPeriphEvents(events, now)));
  const wifi = items.filter((i) => i.section === 'wifi');
  return {
    baselineAt: Number(getSetting('device_peripherals_baseline_at')) || null,
    added,
    usbDrives: items.filter((i) => i.section === 'disk' && i.usb).length,
    disks: items.filter((i) => i.section === 'disk').length,
    keyboards: items.filter((i) => i.section === 'keyboard').length,
    wifi: {
      saved: new Set(wifi.map((w) => w.name)).size,
      openAuto: [...new Set(wifi.filter((w) => w.auto && wifiRisk(w.auth, w.value.split('/')[1]) === 'open').map((w) => w.name))],
      now: n.wifiNow ?? null,
      nowOpen: items.some((i) => i.section === 'wifinow'),
    },
  };
}

/* ---------- Tailscale devices (e.g. the phone) ---------- */

export type TailDevice = { name: string; os: string; online: boolean; lastSeen: string | null; self: boolean };

async function tailscaleDevices(): Promise<TailDevice[] | null> {
  const exe = ['C:\\Program Files\\Tailscale\\tailscale.exe', 'tailscale'].find((p) => p === 'tailscale' || existsSync(p))!;
  try {
    const { stdout } = await exec(exe, ['status', '--json'], { timeout: 15_000, windowsHide: true });
    const j = JSON.parse(stdout) as { Self?: Record<string, unknown>; Peer?: Record<string, Record<string, unknown>> };
    const dev = (p: Record<string, unknown>, self: boolean): TailDevice => ({
      name: String(p.HostName ?? '?'),
      os: String(p.OS ?? ''),
      online: self || !!p.Online,
      lastSeen: typeof p.LastSeen === 'string' && !p.LastSeen.startsWith('0001') ? p.LastSeen : null,
      self,
    });
    return [...(j.Self ? [dev(j.Self, true)] : []), ...Object.values(j.Peer ?? {}).map((p) => dev(p, false))];
  } catch {
    return null;
  }
}

/* ---------- run ---------- */

type Latest = {
  at: number;
  isAdmin: boolean;
  checks: Check[];
  persistence: { startup: number; tasks: number; baselineAt: number | null; flagged: { name: string; command: string; severity: string; kind: string }[] };
  devices: TailDevice[] | null;
  programs?: { count: number; baselineAt: number | null; added: number } | null;
  extensions?: ExtSummary | null;
  network?: NetSummary | null;
  system?: SysSummary | null;
  peripherals?: PeriphSummary | null;
};

const AUTO_NOTE = 'Fixed — auto-resolved by the device health check';
const resolveFinding = (fingerprint: string) =>
  run(
    "UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = ? WHERE fingerprint = ? AND status IN ('open','acknowledged')",
    Date.now(), AUTO_NOTE, fingerprint,
  ).changes;

/** Auto-resolves open per-program findings of a check (fingerprint `base:hash`), except `keep`. */
const resolveOthers = (base: string, keep: string | null) =>
  run(
    "UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = ? WHERE fingerprint LIKE ? AND fingerprint != ? AND status IN ('open','acknowledged')",
    Date.now(), AUTO_NOTE, `${base}:%`, keep ?? '',
  ).changes;

const SEV_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/**
 * The owner closed this check's finding by hand (e.g. "BitLocker is off — I know, not needed") and the
 * check still sees exactly the same thing: keep it closed instead of reopening it on every run.
 * It comes back only when the situation changes (new items, other text, or a worse level).
 */
export function closedByOwner(
  last: { status: string; note: string | null; severity: string; evidence: string | null } | undefined,
  now: { severity: string; observed: string; items: string[] },
): boolean {
  if (!last || !['resolved', 'closed'].includes(last.status) || last.note === AUTO_NOTE) return false;
  const d = parseJson<{ details?: { observed?: string; items?: string[] } }>(last.evidence ?? '{}', {}).details;
  if (!d) return false;
  const same = d.observed === now.observed && JSON.stringify([...(d.items ?? [])].sort()) === JSON.stringify([...now.items].sort());
  return same && (SEV_RANK[now.severity] ?? 0) <= (SEV_RANK[last.severity] ?? 0);
}

/**
 * Approved remote tools and known open programs. Closing a remote_tools / open_ports finding by hand means
 * "I know, that's mine": its items join the approved list so they never alert again.
 */
function loadTrust(assetId: number): Trust {
  const tools = new Set([...DEFAULT_TRUSTED_TOOLS, ...parseJson<string[]>(getSetting('device_trusted_remote_tools') ?? '[]', [])]);
  const portsRaw = getSetting('device_open_ports_baseline');
  const ports = portsRaw ? new Set(parseJson<string[]>(portsRaw, [])) : null;
  const sources = [
    { check: 'remote_tools', into: tools, setting: 'device_trusted_remote_tools' },
    { check: 'open_ports', into: ports, setting: 'device_open_ports_baseline' },
  ];
  for (const { check, into, setting } of sources) {
    if (!into) continue;
    const closed = all<{ evidence: string | null }>(
      "SELECT evidence FROM security_findings WHERE fingerprint LIKE ? AND status IN ('resolved','false_positive','closed') AND (note IS NULL OR note != ?)",
      `device_protection:${assetId}:${check}:%`, AUTO_NOTE,
    );
    const keys = closed.flatMap((f) => parseJson<{ details?: { keys?: string[] } }>(f.evidence ?? '{}', {}).details?.keys ?? []);
    if (!keys.some((k) => !into.has(k))) continue;
    keys.forEach((k) => into.add(k));
    setSetting(setting, JSON.stringify([...into]));
  }
  return { tools: [...tools], ports: ports ? [...ports] : null };
}

let running: Promise<Latest | null> | null = null;
export function runDeviceHealth(): Promise<Latest | null> {
  running ??= collect().finally(() => (running = null));
  return running;
}

async function snapshot(): Promise<Snapshot> {
  if (process.env.SENTINEL_TEST_DEVICE_SNAPSHOT) return JSON.parse(process.env.SENTINEL_TEST_DEVICE_SNAPSHOT) as Snapshot;
  const { stdout } = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', SCRIPT], {
    timeout: 180_000, windowsHide: true, maxBuffer: 32 * 1024 * 1024,
  });
  return JSON.parse(stdout.trim()) as Snapshot;
}

async function collect(): Promise<Latest | null> {
  if (process.platform !== 'win32' && !process.env.SENTINEL_TEST_DEVICE_SNAPSHOT) {
    reportOk('device_health', 'Not available on this OS');
    return null;
  }
  const assetId = getLocalAssetId();
  if (assetId == null) return null;
  let s: Snapshot;
  try {
    s = await snapshot();
  } catch (e) {
    reportError('device_health', `Device check failed: ${e instanceof Error ? e.message.split('\n')[0] : e}`);
    return null;
  }
  const now = Date.now();
  const trust = loadTrust(assetId);
  const checks = evaluate(s, now, trust);
  // First run with port data: what is open now becomes the known list (no alert for what was already there).
  if (s.listeners && trust.ports == null) setSetting('device_open_ports_baseline', JSON.stringify(openPrograms(s.listeners).map((p) => p.key)));

  // Findings: one per check, resolved automatically when the check passes again.
  let changed = false;
  for (const c of checks) {
    const base = `device_protection:${assetId}:${c.id}`;
    // Checks that list programs get one fingerprint per set of programs, so approving (or marking false
    // positive) one program never hides a different one that shows up later.
    const fingerprint = c.keys?.length ? `${base}:${createHash('sha1').update([...c.keys].sort().join('|')).digest('hex').slice(0, 12)}` : base;
    if (c.status === 'ok') {
      if (Number(resolveFinding(base)) + Number(resolveOthers(base, null))) changed = true;
      continue;
    }
    if (c.keys?.length && resolveOthers(base, fingerprint)) changed = true;
    if (c.status === 'unknown' || !c.severity) continue;
    const text = c.msg.replace(/\{(\w+)\}/g, (_, k: string) => String(c.vars?.[k] ?? ''));
    const last = get<{ status: string; note: string | null; severity: string; evidence: string | null }>(
      'SELECT status, note, severity, evidence FROM security_findings WHERE fingerprint = ? ORDER BY id DESC LIMIT 1', fingerprint,
    );
    if (closedByOwner(last, { severity: c.severity, observed: text, items: c.items ?? [] })) continue;
    const msg = checkMessage(c, assetLabel(assetId));
    const id = upsertFinding({
      notify: { en: msg.en, th: msg.th },
      ruleId: 'device_protection',
      assetId,
      severity: c.severity,
      title: `${CHECK_LABELS[c.id] ?? c.id}: ${text}`,
      summary: [text, ...(c.items ?? []).slice(0, 12)].join(' · '),
      fingerprint,
      condition: `Device health check "${c.id}"`,
      extra: { details: { check: c.id, status: c.status, observed: text, items: c.items ?? [], keys: c.keys ?? [], checkedAt: new Date(now).toISOString(), headlineTh: msg.headlineTh, headlineEn: msg.headlineEn } },
      mergeWindowMs: 365 * DAY,
    });
    // upsertFinding keeps an existing finding's level; follow the check when it gets better or worse.
    if (id != null) run('UPDATE security_findings SET severity = ?, title = ? WHERE id = ?', c.severity, `${CHECK_LABELS[c.id] ?? c.id}: ${text}`, id);
  }

  // Auto-start programs / scheduled tasks: compare with the previous run.
  const items = persistenceItems(s);
  const baselineRaw = getSetting('device_persistence_baseline');
  const baseline = baselineRaw ? new Set(parseJson<string[]>(baselineRaw, [])) : null;
  const flagged: Latest['persistence']['flagged'] = [];
  for (const it of items) {
    const isNew = baseline != null && !baseline.has(it.key);
    const sev = await judgePersistence(assetId, it, isNew);
    if (sev) flagged.push({ name: it.name, command: it.command, severity: sev, kind: it.kind });
  }
  if (s.startup && s.tasks) {
    // An auto-start entry that is gone (removed by the admin or an uninstaller) closes its finding.
    const present = new Set(items.map((it) => fp(assetId, it)));
    const stale = all<{ id: number; fingerprint: string }>(
      "SELECT id, fingerprint FROM security_findings WHERE rule_id = 'persistence_added' AND asset_id = ? AND status IN ('open','acknowledged')",
      assetId,
    ).filter((f) => !present.has(f.fingerprint));
    for (const f of stale) {
      run("UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Removed — no longer set to start automatically (auto-resolved)' WHERE id = ?", now, f.id);
      changed = true;
    }
    setSetting('device_persistence_baseline', JSON.stringify(items.map((i) => i.key)));
    if (!baseline) setSetting('device_persistence_baseline_at', String(now));
  }

  // Newly installed programs (first run only records what is already there).
  const programs = await watchPrograms(assetId, s, now);
  if (programs?.added) changed = true;

  // Browser extensions: read straight from the browsers' profile files (tests pass them in the snapshot).
  let extProfiles: ExtProfile[] | null = null;
  try {
    extProfiles = process.env.SENTINEL_TEST_DEVICE_SNAPSHOT ? (s.extensions ?? null) : readBrowserExtensions();
  } catch {
    extProfiles = null;
  }
  const extensions = watchExtensions(assetId, extProfiles, now);
  if (extensions?.added) changed = true;

  // Hosts file, DNS servers typed in by hand, proxies.
  const network = watchNetwork(assetId, s.network, now);
  if (network?.added) changed = true;

  // Trusted root certificates, inbound firewall allow rules, security settings.
  const system = await watchSystem(assetId, s.system, now);
  if (system?.added) changed = true;

  // USB drives, keyboard devices, Wi-Fi.
  const peripherals = watchPeripherals(assetId, s.peripherals, now);
  if (peripherals?.added) changed = true;

  const latest: Latest = {
    at: now,
    isAdmin: s.isAdmin,
    checks,
    persistence: {
      startup: (s.startup ?? []).length,
      tasks: (s.tasks ?? []).length,
      baselineAt: Number(getSetting('device_persistence_baseline_at')) || null,
      flagged,
    },
    devices: await tailscaleDevices(),
    programs,
    extensions,
    network,
    system,
    peripherals,
  };
  setSetting('device_health_latest', JSON.stringify(latest));
  const bad = checks.filter((c) => c.status === 'bad').length;
  const warn = checks.filter((c) => c.status === 'warn').length;
  reportOk('device_health', bad || warn ? `${bad} problem(s), ${warn} warning(s)` : 'All checks passed');
  if (changed || bad || warn || flagged.length) publish('findings');
  publish('device');
  return latest;
}

/* ---------- API ---------- */

export const deviceRouter = Router();

deviceRouter.get('/', (_req, res) => {
  const raw = getSetting('device_health_latest');
  const latest = raw ? parseJson<Latest | null>(raw, null) : null;
  // Open findings about auto-start programs / exclusions (the "flagged" list of one run is only what changed then).
  const findings = all<{ id: number; rule_id: string; severity: string; title: string; summary: string; evidence: string; last_seen: number }>(
    `SELECT id, rule_id, severity, title, summary, evidence, last_seen FROM security_findings
     WHERE rule_id IN ('persistence_added','defender_exclusion_added','program_installed','browser_extension','network_changed','system_changed','device_connected','phone_health') AND status IN ('open','acknowledged') ORDER BY last_seen DESC LIMIT 50`,
  ).map((f) => ({ id: f.id, ruleId: f.rule_id, severity: f.severity, title: f.title, summary: f.summary, lastSeen: f.last_seen, plainTh: plainFinding({ ruleId: f.rule_id, severity: f.severity, title: f.title, summary: f.summary, evidence: parseJson(f.evidence, {}) }) }));
  const recentPrograms = programEvents().filter((e) => Date.now() - e.at < 30 * DAY).reverse().slice(0, 30);
  const recentExtensions = extensionEvents().filter((e) => Date.now() - e.at < 30 * DAY).reverse().slice(0, 30);
  const recentNetwork = networkEvents().filter((e) => Date.now() - e.at < 30 * DAY).reverse().slice(0, 30);
  const recentSystem = systemEvents().filter((e) => Date.now() - e.at < 30 * DAY).reverse().slice(0, 30);
  const recentPeripherals = peripheralEvents().filter((e) => Date.now() - e.at < 30 * DAY).reverse().slice(0, 30);
  const phones = phoneList().map((p) => ({ ...p, stale: Date.now() - p.lastSeen > STALE_MS }));
  res.json({ latest, labels: CHECK_LABELS, findings, phones, recentPrograms, recentExtensions, recentNetwork, recentSystem, recentPeripherals, everyMs: DEVICE_HEALTH_EVERY_MS, running: running != null });
});

/* ---------- phones / tablets (check-in when SENTINEL is opened on them) ---------- */

const PHONES = 'phone_checkins';
const phoneFp = (id: string) => `phone_health:${id}`;
export const phoneList = (): PhoneRecord[] => parseJson<PhoneRecord[]>(getSetting(PHONES) ?? '[]', []);

/** Only plain, short values from the page are kept; everything is display-only except the OS version. */
function readHints(raw: unknown): PhoneHints {
  const h = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const s = (v: unknown, max: number, re: RegExp) => (typeof v === 'string' && v.length <= max && re.test(v) ? v : undefined);
  const b = h.battery && typeof h.battery === 'object' ? (h.battery as Record<string, unknown>) : null;
  return {
    platformVersion: s(h.platformVersion, 20, /^[\d.]+$/),
    model: s(h.model, 40, /^[\w .+()-]*$/),
    touch: h.touch === true,
    battery: b ? { level: typeof b.level === 'number' ? b.level : undefined, charging: typeof b.charging === 'boolean' ? b.charging : undefined } : null,
    standalone: h.standalone === true,
  };
}

deviceRouter.post('/phone-checkin', (req, res) => {
  const b = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
  const id = typeof b.id === 'string' && PHONE_ID.test(b.id) ? b.id : null;
  if (!id) throw new HttpError(400, 'id must be 8–64 letters, digits or dashes');
  const hints = readHints(b.hints);
  const info = parsePhone(String(req.headers['user-agent'] ?? '').slice(0, 400), hints);
  if (!info) return res.json({ ok: true, ignored: 'not a phone or tablet' });
  const now = Date.now();
  const { list, rec, before } = mergeCheckin(phoneList(), id, info, hints, now);
  setSetting(PHONES, JSON.stringify(list));
  if (rec.status === 'old') {
    const v = judgePhone(info);
    const th = `📱 <b>${rec.label}: ระบบเก่าจนไม่ได้รับอัปเดตความปลอดภัยแล้ว</b>\n${rec.os} — ช่องโหว่ใหม่จะไม่ถูกแก้\n\n👉 <b>วิธีแก้:</b> ${info.platform === 'android' ? 'Settings → System → Software update ถ้าไม่มีเวอร์ชันใหม่ให้แล้ว ควรเปลี่ยนเครื่อง' : 'Settings → General → Software Update ถ้าไม่มีเวอร์ชันใหม่ให้แล้ว ควรเปลี่ยนเครื่อง'}`;
    const en = `📱 <b>${rec.label}: the system no longer gets security updates</b>\n${v.detail}\n\n👉 <b>Fix:</b> ${info.platform === 'android' ? 'Settings → System → Software update; if nothing newer is offered, plan to replace the phone' : 'Settings → General → Software Update; if nothing newer is offered, plan to replace the device'}`;
    upsertFinding({
      notify: { en, th },
      ruleId: 'phone_health',
      assetId: getLocalAssetId(),
      severity: 'medium',
      title: `${rec.label}: ${rec.os} no longer gets security updates`,
      summary: v.detail,
      fingerprint: phoneFp(id),
      condition: 'Phone / tablet check-in when SENTINEL is opened on it',
      extra: { details: { device: rec.label, os: rec.os, browser: `${rec.browser} ${rec.browserVersion ?? ''}`.trim(), headlineTh: `${rec.label}: ระบบเก่าจนไม่ได้รับอัปเดตความปลอดภัยแล้ว`, assessment: v.detail } },
      mergeWindowMs: 365 * DAY,
    });
    publish('findings');
  } else if (before?.status === 'old') {
    run("UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Updated — auto-resolved' WHERE fingerprint = ? AND status IN ('open','acknowledged')", now, phoneFp(id));
    publish('findings');
  }
  if (!before) audit('phone.first_checkin', { ip: clientIp(req), detail: { label: rec.label, os: rec.os } });
  publish('device');
  res.json({ ok: true, status: rec.status, os: rec.os });
});

deviceRouter.post('/refresh', async (req, res) => {
  const latest = await runDeviceHealth();
  audit('device_health.refresh', { ip: clientIp(req) });
  res.json({ ok: !!latest, latest });
});
