import { createHash } from 'node:crypto';
import { Router } from 'express';
import { all, get, getSetting, run, setSetting, tx } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { body, clientIp, HttpError, idParam, num, oneOf, str } from '../lib/http.js';
import { stepUp } from './auth.js';
import { securityNotice } from './notify.js';
import { DAY, escHtml, HOUR, MIN, parseJson, SEVERITIES, sevRank } from '../lib/util.js';
import { L, ruleText, sevText } from '../lib/i18n.js';
import { checkSignature, type SignatureResult } from '../lib/signature.js';
import { exclusionPlain, exclusionRisk, type ExclusionKind } from '../lib/exclusions.js';
import { SEV_ICON } from '../lib/device-messages.js';
import { plainFinding } from '../lib/finding-plain.js';
import { EXCLUSION_RE } from './eventlog.js';
import { enqueue } from './notify.js';
import { notifyFinishedScans } from './scan.js';
import { classifySysmon, SYSMON_CHANNEL } from '../lib/sysmon-rules.js';

/**
 * Rule-based, auditable detection (ADR-007). Every finding carries evidence:
 * the ids of the log events that matched, the time range and the condition.
 * Nothing here blocks, kills or changes anything on the machine.
 */

type RuleDef = { id: string; name: string; description: string; severity: string; params: Record<string, number> };

export const RULES: RuleDef[] = [
  { id: 'brute_force', name: 'Password guessing (brute force)', description: 'Many failed logons from the same source within a short window (event 4625).', severity: 'high', params: { threshold: 5, windowMin: 10 } },
  { id: 'slow_brute_force', name: 'Slow password guessing', description: 'Many failed logons from the same source spread over hours (4625), too slow for the brute-force rule. Bursts that rule already reports are skipped.', severity: 'medium', params: { threshold: 10, windowHours: 24 } },
  { id: 'success_after_failures', name: 'Successful logon after repeated failures', description: 'A successful logon (4624) for an account that just had several failed attempts — a guessed password may have worked.', severity: 'critical', params: { failures: 3, windowMin: 15 } },
  { id: 'new_local_user', name: 'New user account created', description: 'A user account was created on the machine (4720).', severity: 'high', params: {} },
  { id: 'admin_group_add', name: 'Account added to a privileged group', description: 'A member was added to Administrators / Remote Desktop Users / Domain Admins (4728/4732/4756).', severity: 'critical', params: {} },
  { id: 'log_cleared', name: 'Audit log cleared', description: 'The Security (1102) or another event log (104) was cleared — a common way to hide activity.', severity: 'critical', params: {} },
  { id: 'service_installed', name: 'New service installed', description: 'A new Windows service was installed (7045). Malware often persists as a service. The binary signature sets the level: valid publisher signature → low, unsigned/invalid → high, not checkable → this severity.', severity: 'medium', params: {} },
  { id: 'account_lockout', name: 'Account locked out', description: 'An account was locked after too many bad passwords (4740).', severity: 'medium', params: {} },
  { id: 'defender_threat', name: 'Malware detected by Defender', description: 'Microsoft Defender detected or acted on a threat (1116/1117).', severity: 'critical', params: {} },
  { id: 'defender_exclusion_added', name: 'Defender exclusion added', description: 'A scan exclusion was added to Microsoft Defender (5007). Malware adds exclusions so it is never scanned. Broad ones (a whole drive, Windows, Temp, system process names) are raised to critical.', severity: 'high', params: {} },
  { id: 'device_protection', name: 'Device protection weakened', description: 'Periodic check of this PC: Defender on and up to date, no dangerous exclusions, firewall on, recent Windows updates, disk and battery health. Each problem has its own level and resolves itself when fixed.', severity: 'medium', params: {} },
  { id: 'persistence_added', name: 'New auto-start program or scheduled task', description: 'A program was added to start automatically (Run keys, Startup folder) or a scheduled task appeared. Signed → low, unsigned or missing file → high, named like a Windows system file outside the Windows folder → critical.', severity: 'medium', params: {} },
  { id: 'network_changed', name: 'Hosts file, DNS or proxy changed', description: 'Something new in the hosts file, a DNS server typed in by hand, a proxy / PAC script / WinHTTP proxy, or a DNS rule (NRPT) since the last device check (every 30 min). Faking or blocking a bank, Google, Microsoft, Defender or Telegram, an unknown DNS server, a proxy on another machine → high; a local proxy, a DNS on your network, an unknown hosts line → medium; public DNS (Google/Cloudflare/Quad9) or ad blocking → low (no message). Tailscale\'s own entries are ignored. Removing it closes the finding.', severity: 'low', params: {} },
  { id: 'browser_extension', name: 'New browser extension', description: 'An extension appeared in Chrome, Brave, Edge, Vivaldi or Opera since the last device check (every 30 min), or an update gave one new powers. Not from the Web Store or forced in by a policy → high; from the store with access to every site or risky permissions (debugger, proxy, cookies, native messaging…) → medium; anything else → low (no message). Removing it closes the finding.', severity: 'low', params: {} },
  { id: 'program_installed', name: 'New program installed', description: 'A program appeared in the installed-programs list since the last device check (every 30 min). Its main file signature sets the level: signed → low (no message), unsigned → medium, modified after signing (e.g. HashMismatch) or a crack/repack name → high.', severity: 'low', params: {} },
  { id: 'defender_disabled', name: 'Defender real-time protection disabled', description: 'Real-time protection was turned off (5001).', severity: 'high', params: {} },
  { id: 'remote_logon', name: 'Remote Desktop logon', description: 'Someone logged on via Remote Desktop (4624, logon type 10).', severity: 'medium', params: {} },
  { id: 'unexpected_shutdown', name: 'Unexpected shutdown', description: 'The machine shut down unexpectedly (6008): power loss, crash or forced off.', severity: 'low', params: {} },
  { id: 'sentinel_login_failed', name: 'Password guessing on SENTINEL sign-in', description: 'Wrong passwords on the SENTINEL sign-in page: several from one address within 15 minutes (medium), or enough to lock the account (high).', severity: 'medium', params: { threshold: 3 } },
  { id: 'sentinel_mfa_failed', name: 'Correct password but wrong 2FA code', description: 'Someone typed the right SENTINEL password but a wrong 6-digit code — the password may be known to someone else. One wrong code → high, three or more within 15 minutes → critical.', severity: 'high', params: { repeat: 3 } },
  { id: 'sentinel_new_device', name: 'SENTINEL sign-in from a new device', description: 'A successful sign-in from an address/browser that has never signed in before.', severity: 'medium', params: {} },
  { id: 'sysmon_doc_spawn', name: 'Document or script opened a command shell (Sysmon)', description: 'Word, Excel, PowerPoint, Outlook, a PDF reader or a script host started cmd, PowerShell or another tool malware borrows — the classic way a booby-trapped file runs its payload.', severity: 'high', params: {} },
  { id: 'sysmon_powershell', name: 'Hidden or encoded PowerShell (Sysmon)', description: 'PowerShell or cmd ran an encoded command, downloaded code and ran it (IEX / DownloadString / WebClient), or a hidden window fetching a URL.', severity: 'high', params: {} },
  { id: 'sysmon_tamper_cmd', name: 'Command that disables protection or deletes backups (Sysmon)', description: 'A command added a Defender exclusion or turned Defender off, deleted shadow copies or backups, disabled boot recovery, cleared a log, turned the firewall off, created an account or abused certutil/bitsadmin to download — what ransomware and intruders run first.', severity: 'critical', params: {} },
  { id: 'sysmon_temp_program', name: 'Unsigned program started from a temp folder (Sysmon)', description: 'A program without a valid publisher signature started from Temp, Windows\\Temp, ProgramData or the Recycle Bin (medium), or from Users\\Public (high). Signed programs (installers) are ignored.', severity: 'medium', params: {} },
  { id: 'sysmon_tool_network', name: 'Script host or system tool connected out (Sysmon)', description: 'mshta, wscript, cscript, regsvr32, certutil, bitsadmin, msbuild (high) or rundll32 (medium) connected to the internet, or an unsigned program in a temp folder did. Local and Tailscale addresses are ignored.', severity: 'high', params: {} },
  { id: 'sysmon_lsass', name: 'Program read Windows sign-in secrets (Sysmon)', description: 'A program opened LSASS memory, where Windows keeps sign-in secrets — how password-stealing tools work. Unsigned → critical, signed → medium. Windows and Defender are excluded in the Sysmon config.', severity: 'critical', params: {} },
  { id: 'sysmon_injection', name: 'Code injected into another program (Sysmon)', description: 'A program outside the Windows folder started a thread inside lsass, explorer, svchost or winlogon. Unsigned → high, signed → medium.', severity: 'high', params: {} },
  { id: 'sysmon_registry_hijack', name: 'UAC, sign-in or Defender settings changed in the registry (Sysmon)', description: 'Real-time: UAC turned off, Winlogon Shell/Userinit replaced, a program hijacked through Image File Execution Options, or Defender turned off by policy.', severity: 'critical', params: {} },
  { id: 'sysmon_startup_file', name: 'File added to the Startup folder (Sysmon)', description: 'A file appeared in a Startup folder, so it runs at every sign-in. Programs and scripts → high, shortcuts → low.', severity: 'medium', params: {} },
  { id: 'sysmon_tampering', name: 'Running program\'s code replaced (Sysmon)', description: 'Sysmon saw a program\'s code swapped while it ran (process hollowing / herpaderping). Unsigned programs only.', severity: 'high', params: {} },
  { id: 'web_security_headers', name: 'Website missing security headers', description: 'A monitored website lacks HSTS, CSP, X-Content-Type-Options or clickjacking protection, or leaks X-Powered-By.', severity: 'low', params: {} },
];

const PRIVILEGED_GROUPS = new Set(['administrators', 'remote desktop users', 'domain admins', 'enterprise admins', 'schema admins']);
const PRIVILEGED_SIDS = new Set(['S-1-5-32-544', 'S-1-5-32-555']);

export function seedDetectionRules() {
  for (const r of RULES) {
    run(
      'INSERT OR IGNORE INTO detection_rules (id, name, description, severity, enabled, params) VALUES (?, ?, ?, ?, 1, ?)',
      r.id, r.name, r.description, r.severity, JSON.stringify(r.params),
    );
    // Keep name/description current; user-tuned severity/params/enabled stay.
    run('UPDATE detection_rules SET name = ?, description = ? WHERE id = ?', r.name, r.description, r.id);
  }
}

type RuleRow = { id: string; name: string; severity: string; enabled: number; params: string };
export function rule(id: string): (RuleRow & { p: Record<string, number> }) | null {
  const r = get<RuleRow>('SELECT * FROM detection_rules WHERE id = ?', id);
  if (!r || !r.enabled) return null;
  const defaults = RULES.find((x) => x.id === id)?.params ?? {};
  return { ...r, p: { ...defaults, ...parseJson<Record<string, number>>(r.params, {}) } };
}

/* ---------- findings ---------- */

type Evidence = {
  eventIds?: number[];
  samples?: { ts: number; summary: string }[];
  from?: number;
  to?: number;
  condition?: string;
  headers?: Record<string, string | null>;
  url?: string;
  /** Snapshot-based findings (device health): what was observed, shown as evidence. */
  details?: Record<string, unknown>;
};

type FindingInput = {
  ruleId: string;
  assetId: number | null;
  title: string;
  summary: string;
  fingerprint: string;
  events?: { id: number; ts: number; summary: string }[];
  condition: string;
  extra?: Partial<Evidence>;
  /** Merge into an open finding with the same fingerprint seen within this window. */
  mergeWindowMs?: number;
  /** Overrides the rule's severity for this finding (e.g. signed vs unsigned service). */
  severity?: string;
  /** Plain-language Telegram message (HTML, already escaped) replacing the generic one. */
  notify?: { en: string; th: string };
};

const assetName = (id: number | null) => (id == null ? 'SENTINEL' : get<{ name: string }>('SELECT name FROM assets WHERE id = ?', id)?.name ?? `asset #${id}`);

export function upsertFinding(f: FindingInput): number | null {
  const r = rule(f.ruleId);
  if (!r) return null;
  const severity = f.severity ?? r.severity;
  const now = Date.now();
  const events = f.events ?? [];
  const lastEventTs = events.length ? Math.max(...events.map((e) => e.ts)) : now;
  const firstEventTs = events.length ? Math.min(...events.map((e) => e.ts)) : now;

  // A finding the admin marked as false positive suppresses the same fingerprint.
  if (get("SELECT id FROM security_findings WHERE fingerprint = ? AND status = 'false_positive'", f.fingerprint)) return null;

  const existing = get<{ id: number; severity: string; evidence: string; count: number; first_seen: number; last_seen: number }>(
    `SELECT id, severity, evidence, count, first_seen, last_seen FROM security_findings
     WHERE fingerprint = ? AND status IN ('open', 'acknowledged') AND last_seen > ? ORDER BY id DESC LIMIT 1`,
    f.fingerprint, now - (f.mergeWindowMs ?? DAY),
  );

  if (existing) {
    const ev = parseJson<Evidence>(existing.evidence, {});
    const known = new Set(ev.eventIds ?? []);
    const fresh = events.filter((e) => !known.has(e.id));
    if (!fresh.length && !f.extra) return existing.id;
    const ids = [...(ev.eventIds ?? []), ...fresh.map((e) => e.id)].slice(-200);
    const samples = [...(ev.samples ?? []), ...fresh.map((e) => ({ ts: e.ts, summary: e.summary }))].slice(-20);
    // An explicit severity never lowers a definite earlier verdict, but replaces one that was inconclusive
    // (signature could not be checked, or the finding predates signature checks).
    const inconclusive = /: unknown$/.test(ev.condition ?? '') || (f.ruleId === 'service_installed' && !/Authenticode:/.test(ev.condition ?? ''));
    const mergedSeverity = !f.severity || !fresh.length ? existing.severity
      : inconclusive || sevRank(f.severity) > sevRank(existing.severity) ? f.severity : existing.severity;
    run(
      'UPDATE security_findings SET last_seen = ?, count = ?, summary = ?, severity = ?, evidence = ? WHERE id = ?',
      // last_seen = time of the newest matching activity, not "now" (correlation relies on this).
      Math.max(existing.last_seen, events.length ? lastEventTs : now), existing.count + fresh.length, f.summary, mergedSeverity,
      JSON.stringify({ ...ev, ...f.extra, eventIds: ids, samples, from: Math.min(ev.from ?? firstEventTs, firstEventTs), to: Math.max(ev.to ?? lastEventTs, lastEventTs), condition: f.condition }),
      existing.id,
    );
    publish('findings');
    return existing.id;
  }

  const evidence: Evidence = {
    ...f.extra,
    eventIds: events.map((e) => e.id).slice(-200),
    samples: events.map((e) => ({ ts: e.ts, summary: e.summary })).slice(-20),
    from: firstEventTs,
    to: lastEventTs,
    condition: f.condition,
  };
  const res = run(
    `INSERT INTO security_findings (rule_id, asset_id, severity, title, summary, fingerprint, status, first_seen, last_seen, count, evidence)
     VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)`,
    f.ruleId, f.assetId, severity, f.title, f.summary, f.fingerprint, firstEventTs, lastEventTs, Math.max(1, events.length), JSON.stringify(evidence),
  );
  const id = Number(res.lastInsertRowid);
  publish('findings');

  // Notify only for recent activity (avoid a flood when 7 days of history are first ingested).
  const minSev = getSetting('notify_finding_min_severity') ?? 'medium';
  if (sevRank(severity) >= sevRank(minSev) && now - lastEventTs < HOUR) {
    enqueue(
      'finding',
      `finding:${id}`,
      f.notify ? L(f.notify.en, f.notify.th) : L(
        `🛡️ <b>[${sevText(severity)}] ${escHtml(f.title)}</b>\nAsset: ${escHtml(assetName(f.assetId))}\n${escHtml(f.summary)}\n<i>Condition: ${escHtml(f.condition)}</i>`,
        `🛡️ <b>[${sevText(severity)}] ${escHtml(ruleText(f.ruleId, r.name))}</b>\n${escHtml(f.title)}\nเครื่อง: ${escHtml(assetName(f.assetId))}\n${escHtml(f.summary)}\n<i>เงื่อนไข: ${escHtml(f.condition)}</i>`,
      ),
    );
  }
  return id;
}

/* ---------- log-based detection ---------- */

type LogRow = { id: number; asset_id: number; event_id: number; ts: number; summary: string; fields: string; channel?: string };
type Ev = LogRow & { f: Record<string, string> };

const lower = (s: string | undefined) => (s ?? '').toLowerCase();
const dayKey = (ts: number) => new Date(ts).toISOString().slice(0, 10);
const sourceOf = (f: Record<string, string>) => {
  const ip = f.IpAddress && f.IpAddress !== '-' ? f.IpAddress : '';
  return ip || (f.WorkstationName && f.WorkstationName !== '-' ? f.WorkstationName : 'local');
};
const asEv = (r: LogRow): Ev => ({ ...r, f: parseJson<Record<string, string>>(r.fields, {}) });
const ref = (e: Ev) => ({ id: e.id, ts: e.ts, summary: e.summary });

function single(e: Ev) {
  const f = e.f;
  const a = e.asset_id;
  switch (e.event_id) {
    case 4720:
      upsertFinding({ ruleId: 'new_local_user', assetId: a, title: `New user account: ${f.TargetUserName || '?'}`, summary: e.summary, fingerprint: `new_local_user:${a}:${f.TargetSid || f.TargetUserName}`, events: [ref(e)], condition: 'Event 4720 (user account created)' });
      break;
    case 4728:
    case 4732:
    case 4756:
      if (PRIVILEGED_SIDS.has(f.TargetSid) || PRIVILEGED_GROUPS.has(lower(f.TargetUserName))) {
        upsertFinding({ ruleId: 'admin_group_add', assetId: a, title: `Added to privileged group ${f.TargetUserName}`, summary: e.summary, fingerprint: `admin_group_add:${a}:${f.TargetSid}:${f.MemberSid || f.MemberName}`, events: [ref(e)], condition: `Event ${e.event_id} with group ${f.TargetUserName}` });
      }
      break;
    case 1102:
    case 104:
      upsertFinding({ ruleId: 'log_cleared', assetId: a, title: 'Event log cleared', summary: e.summary, fingerprint: `log_cleared:${a}:${e.id}`, events: [ref(e)], condition: `Event ${e.event_id} (log cleared)` });
      break;
    case 4740:
      upsertFinding({ ruleId: 'account_lockout', assetId: a, title: `Account locked out: ${f.TargetUserName || '?'}`, summary: e.summary, fingerprint: `account_lockout:${a}:${lower(f.TargetUserName)}:${dayKey(e.ts)}`, events: [ref(e)], condition: 'Event 4740 (account lockout)' });
      break;
    case 1116:
    case 1117:
    case 1118:
    case 1119:
      upsertFinding({ ruleId: 'defender_threat', assetId: a, title: `Malware: ${f['Threat Name'] || 'threat detected'}`, summary: e.summary, fingerprint: `defender_threat:${a}:${f['Threat Name']}:${f.Path ?? ''}`, events: [ref(e)], condition: `Defender event ${e.event_id}` });
      break;
    case 5007: {
      const m = EXCLUSION_RE.exec(f['New Value'] ?? '');
      if (!m) break;
      const kind = m[1] as ExclusionKind;
      const risk = exclusionRisk(kind, m[2]);
      const what = { th: escHtml(exclusionPlain(m[2], true)), en: escHtml(exclusionPlain(m[2], false)) };
      const fixTh = 'Windows Security → การป้องกันไวรัสและภัยคุกคาม → จัดการการตั้งค่า → การยกเว้น → ลบรายการนี้ แล้วสแกนแบบ Microsoft Defender Offline';
      const fixEn = 'Windows Security → Virus & threat protection → Manage settings → Exclusions → remove it, then run a Microsoft Defender Offline scan';
      const icon = SEV_ICON[risk ? 'critical' : 'high'];
      upsertFinding({
        ruleId: 'defender_exclusion_added',
        assetId: a,
        severity: risk ? 'critical' : undefined,
        notify: {
          th: `${icon} <b>มีคนสั่งให้ Defender ไม่ตรวจ: ${what.th}</b>\n${risk ? 'เป็นจุดที่กว้างหรืออันตราย มัลแวร์มักตั้งแบบนี้เพื่อซ่อนตัว' : 'ถ้าคุณเพิ่มเอง (เช่น ให้โปรแกรมทำงานเร็วขึ้น) ไม่ต้องทำอะไร'}\n\n👉 <b>ถ้าไม่ได้ทำเอง:</b> ${fixTh}\n\n💻 ${escHtml(assetName(a))}`,
          en: `${icon} <b>Defender was told to skip: ${what.en}</b>\n${risk ? 'This is broad or dangerous — malware does this to hide.' : 'If you added it yourself, nothing to do.'}\n\n👉 <b>If it wasn't you:</b> ${fixEn}\n\n💻 ${escHtml(assetName(a))}`,
        },
        extra: { details: { headlineTh: `Defender ถูกสั่งไม่ให้ตรวจ ${exclusionPlain(m[2], true)}`, headlineEn: `Defender told to skip ${exclusionPlain(m[2], false)}` } },
        title: `Defender exclusion added: ${m[2]}`,
        summary: `${e.summary}${risk ? ` — ${risk}` : ''}`,
        fingerprint: `defender_exclusion_added:${a}:${kind}:${lower(m[2])}`,
        events: [ref(e)],
        condition: `Defender event 5007 (Exclusions\\${kind})${risk ? ' · risky' : ''}`,
      });
      break;
    }
    case 5001:
      upsertFinding({ ruleId: 'defender_disabled', assetId: a, title: 'Defender real-time protection disabled', summary: e.summary, fingerprint: `defender_disabled:${a}:${dayKey(e.ts)}`, events: [ref(e)], condition: 'Defender event 5001' });
      break;
    case 4624:
      if (e.f.LogonType === '10') {
        upsertFinding({ ruleId: 'remote_logon', assetId: a, title: `Remote Desktop logon: ${f.TargetUserName}`, summary: e.summary, fingerprint: `remote_logon:${a}:${lower(f.TargetUserName)}:${sourceOf(f)}:${dayKey(e.ts)}`, events: [ref(e)], condition: 'Event 4624 with LogonType 10' });
      }
      break;
    case 6008:
      upsertFinding({ ruleId: 'unexpected_shutdown', assetId: a, title: 'Unexpected shutdown', summary: e.summary, fingerprint: `unexpected_shutdown:${a}:${e.id}`, events: [ref(e)], condition: 'Event 6008' });
      break;
  }
}

function bruteForce(batch: Ev[]) {
  const r = rule('brute_force');
  if (!r) return;
  const windowMs = r.p.windowMin * MIN;
  const fails = batch.filter((e) => e.event_id === 4625);
  if (!fails.length) return;
  const byAsset = new Map<number, Ev[]>();
  for (const e of fails) byAsset.set(e.asset_id, [...(byAsset.get(e.asset_id) ?? []), e]);

  for (const [assetId, newOnes] of byAsset) {
    const from = Math.min(...newOnes.map((e) => e.ts)) - windowMs;
    const to = Math.max(...newOnes.map((e) => e.ts));
    const all4625 = all<LogRow>('SELECT id, asset_id, event_id, ts, summary, fields FROM log_events WHERE asset_id = ? AND event_id = 4625 AND ts BETWEEN ? AND ? ORDER BY ts', assetId, from, to).map(asEv);
    const bySource = new Map<string, Ev[]>();
    for (const e of all4625) bySource.set(sourceOf(e.f), [...(bySource.get(sourceOf(e.f)) ?? []), e]);

    for (const [source, evs] of bySource) {
      // Largest sliding-window burst that ends at one of the new events.
      let best: Ev[] = [];
      for (const n of newOnes.filter((x) => sourceOf(x.f) === source)) {
        const win = evs.filter((e) => e.ts > n.ts - windowMs && e.ts <= n.ts);
        if (win.length > best.length) best = win;
      }
      if (best.length < r.p.threshold) continue;
      const users = [...new Set(best.map((e) => e.f.TargetUserName || '?'))];
      upsertFinding({
        ruleId: 'brute_force',
        assetId,
        title: `Password guessing from ${source}`,
        summary: `${best.length} failed logons within ${r.p.windowMin} min from ${source} for ${users.length > 1 ? `${users.length} accounts (${users.slice(0, 5).join(', ')})` : `account ${users[0]}`}`,
        fingerprint: `brute_force:${assetId}:${source}`,
        events: best.map(ref),
        condition: `≥ ${r.p.threshold} × event 4625 from the same source within ${r.p.windowMin} min`,
        mergeWindowMs: 6 * HOUR,
      });
    }
  }
}

/** Largest number of events inside any `windowMs` span (events sorted by ts). */
function maxBurst(evs: Ev[], windowMs: number) {
  let best = 0;
  for (let i = 0, j = 0; j < evs.length; j++) {
    while (evs[j].ts - evs[i].ts >= windowMs) i++;
    best = Math.max(best, j - i + 1);
  }
  return best;
}

/**
 * Slow password guessing: many failures from one source spread over hours, each 10-minute
 * slice too small for the brute-force rule. Bursts the fast rule already reports are skipped.
 */
function slowBruteForce(batch: Ev[]) {
  const r = rule('slow_brute_force');
  if (!r) return;
  const windowMs = r.p.windowHours * HOUR;
  const fast = rule('brute_force');
  const fails = batch.filter((e) => e.event_id === 4625);
  for (const assetId of new Set(fails.map((e) => e.asset_id))) {
    const newOnes = fails.filter((e) => e.asset_id === assetId);
    const to = Math.max(...newOnes.map((e) => e.ts));
    const recent = all<LogRow>('SELECT id, asset_id, event_id, ts, summary, fields FROM log_events WHERE asset_id = ? AND event_id = 4625 AND ts > ? AND ts <= ? ORDER BY ts', assetId, to - windowMs, to).map(asEv);
    for (const source of new Set(newOnes.map((e) => sourceOf(e.f)))) {
      const evs = recent.filter((e) => sourceOf(e.f) === source);
      if (evs.length < r.p.threshold) continue;
      if (fast && maxBurst(evs, fast.p.windowMin * MIN) >= fast.p.threshold) continue; // the fast rule covers it
      const users = [...new Set(evs.map((e) => e.f.TargetUserName || '?'))];
      const spanH = Math.max(1, Math.round((evs[evs.length - 1].ts - evs[0].ts) / HOUR));
      upsertFinding({
        ruleId: 'slow_brute_force',
        assetId,
        title: `Slow password guessing from ${source}`,
        summary: `${evs.length} failed logons over ~${spanH} h from ${source} for ${users.length > 1 ? `${users.length} accounts (${users.slice(0, 5).join(', ')})` : `account ${users[0]}`}`,
        fingerprint: `slow_brute_force:${assetId}:${source}`,
        events: evs.map(ref),
        condition: `≥ ${r.p.threshold} × event 4625 from the same source within ${r.p.windowHours} h, never ${fast ? `${fast.p.threshold} within ${fast.p.windowMin} min` : 'in a burst'}`,
        mergeWindowMs: windowMs,
      });
    }
  }
}

function successAfterFailures(batch: Ev[]) {
  const r = rule('success_after_failures');
  if (!r) return;
  const windowMs = r.p.windowMin * MIN;
  for (const s of batch.filter((e) => e.event_id === 4624)) {
    const user = lower(s.f.TargetUserName);
    if (!user) continue;
    const fails = all<LogRow>(
      `SELECT id, asset_id, event_id, ts, summary, fields FROM log_events
       WHERE asset_id = ? AND event_id = 4625 AND ts BETWEEN ? AND ? AND lower(json_extract(fields, '$.TargetUserName')) = ?`,
      s.asset_id, s.ts - windowMs, s.ts, user,
    ).map(asEv);
    if (fails.length < r.p.failures) continue;
    // All attempts typed at this PC's keyboard (interactive/unlock, no remote source) is most often
    // the owner mistyping: still reported, but as medium so it does not open an incident on its own.
    // Console logons record IpAddress as 127.0.0.1 / ::1 / "-" depending on the Windows version.
    const isLocal = (x: Record<string, string>) => ['2', '7', '11'].includes(x.LogonType) && ['', '-', '127.0.0.1', '::1'].includes(x.IpAddress ?? '');
    const allLocal = isLocal(s.f) && fails.every((x) => isLocal(x.f));
    upsertFinding({
      severity: allLocal && sevRank(r.severity) > sevRank('medium') ? 'medium' : undefined,
      ruleId: 'success_after_failures',
      assetId: s.asset_id,
      title: `Logon succeeded after ${fails.length} failures: ${s.f.TargetUserName}`,
      summary: `${s.summary} — preceded by ${fails.length} failed attempts in ${r.p.windowMin} min. Verify it was you.`,
      fingerprint: `success_after_failures:${s.asset_id}:${user}`,
      events: [...fails, s].map(ref),
      condition: `Event 4624 after ≥ ${r.p.failures} × 4625 for the same account within ${r.p.windowMin} min`,
      mergeWindowMs: HOUR,
    });
  }
}

/**
 * New service (7045): the binary's Authenticode signature sets the severity.
 * Valid signature (Microsoft, Google, …) → low (recorded, no notification);
 * unsigned or broken signature → high; could not check → the rule's severity.
 */
function serviceVerdict(sig: SignatureResult, ruleSeverity: string) {
  const severity = sig.state === 'signed' ? 'low' : sig.state === 'unknown' ? ruleSeverity : sevRank(ruleSeverity) > sevRank('high') ? ruleSeverity : 'high';
  const note = sig.state === 'signed' ? `signed by ${sig.signer} (valid)` : sig.detail;
  return { severity, note };
}

async function servicesInstalled(batch: Ev[]) {
  const r = rule('service_installed');
  if (!r) return;
  for (const e of batch.filter((x) => x.event_id === 7045)) {
    const f = e.f;
    const sig = await checkSignature(f.ImagePath ?? '');
    const { severity, note } = serviceVerdict(sig, r.severity);
    upsertFinding({
      ruleId: 'service_installed',
      assetId: e.asset_id,
      title: `New service: ${f.ServiceName || '?'}`,
      summary: `${e.summary} · ${note}`,
      fingerprint: `service_installed:${e.asset_id}:${lower(f.ServiceName)}`,
      events: [ref(e)],
      condition: `Event 7045 (service installed) · Authenticode: ${sig.state}`,
      mergeWindowMs: 30 * DAY,
      severity,
    });
  }
}

/** Sysmon events → findings. Signature checks decide the level where the program's publisher matters. */
async function sysmonDetect(events: Ev[]) {
  for (const e of events) {
    const v = classifySysmon(e.event_id, e.f);
    if (!v) continue;
    const r = rule(v.rule);
    if (!r) continue;
    let severity = v.severity;
    let note = '';
    if (v.sig) {
      const sig = await checkSignature(`"${v.sig.path}"`);
      if (sig.state === 'signed') {
        if (!v.sig.signed) continue;
        severity = v.sig.signed;
        note = ` · signed by ${sig.signer}`;
      } else note = ` · ${sig.state === 'unknown' ? 'signature not checkable' : 'not signed'}`;
    }
    const icon = SEV_ICON[severity] ?? '🟡';
    upsertFinding({
      ruleId: v.rule,
      assetId: e.asset_id,
      severity,
      title: v.title,
      summary: `${e.summary}${note}`,
      fingerprint: `${v.rule}:${e.asset_id}:${createHash('sha1').update(v.key).digest('hex').slice(0, 16)}`,
      events: [ref(e)],
      condition: `Sysmon event ${e.event_id}${note}`,
      mergeWindowMs: DAY,
      notify: {
        th: `${icon} <b>${escHtml(v.th)}</b>\n${escHtml(e.summary.slice(0, 300))}${note ? `\n<i>${escHtml(note.slice(3))}</i>` : ''}\n\n👉 ถ้าไม่ได้ทำเอง: ดูรายละเอียดในศูนย์ความปลอดภัย แล้วสแกนแบบ Offline จากหน้า สุขภาพเครื่อง\n\n💻 ${escHtml(assetName(e.asset_id))}`,
        en: `${icon} <b>${escHtml(v.title)}</b>\n${escHtml(e.summary.slice(0, 300))}${note ? `\n<i>${escHtml(note.slice(3))}</i>` : ''}\n\n👉 If this wasn't you: open it in Security Center, then run an Offline scan from Device health\n\n💻 ${escHtml(assetName(e.asset_id))}`,
      },
      extra: { details: { headlineTh: v.th, headlineEn: v.title } },
    });
  }
}

/**
 * Open "new service" findings recorded before signature checks existed carry the rule's default
 * severity. Check their binaries now and set the level the same way a new finding would get it.
 * Idempotent: a re-graded finding has "Authenticode:" in its condition and is skipped next time.
 */
export async function regradeServiceFindings(): Promise<number> {
  const r = rule('service_installed');
  if (!r) return 0;
  const rows = all<{ id: number; severity: string; summary: string; evidence: string }>(
    "SELECT id, severity, summary, evidence FROM security_findings WHERE rule_id = 'service_installed' AND status IN ('open','acknowledged')",
  );
  let changed = 0;
  for (const row of rows) {
    const ev = parseJson<Evidence>(row.evidence, {});
    if (/Authenticode:/.test(ev.condition ?? '')) continue;
    const lastId = (ev.eventIds ?? []).at(-1);
    const src = lastId == null ? undefined : get<{ fields: string }>('SELECT fields FROM log_events WHERE id = ?', lastId);
    const imagePath = src ? parseJson<Record<string, string>>(src.fields, {}).ImagePath : undefined;
    if (!imagePath) continue; // raw event aged out: leave as is
    const sig = await checkSignature(imagePath);
    if (sig.state === 'unknown') continue;
    const { severity, note } = serviceVerdict(sig, r.severity);
    run(
      'UPDATE security_findings SET severity = ?, summary = ?, evidence = ? WHERE id = ?',
      severity, `${row.summary} · ${note}`, JSON.stringify({ ...ev, condition: `${ev.condition ?? 'Event 7045 (service installed)'} · Authenticode: ${sig.state}` }), row.id,
    );
    if (severity !== row.severity) {
      audit('finding.regraded', { resourceType: 'finding', resourceId: row.id, detail: { from: row.severity, to: severity, signature: sig.state } });
    }
    changed++;
  }
  if (changed) publish('findings');
  return changed;
}

let detectionRun: Promise<number> | null = null;

/** Process log events ingested since the last run. Concurrent calls share one run. */
export function runDetection(): Promise<number> {
  detectionRun ??= detectBatches().finally(() => (detectionRun = null));
  return detectionRun;
}

async function detectBatches(): Promise<number> {
  let cursor = Number(getSetting('detection_cursor') ?? 0);
  let processed = 0;
  for (;;) {
    const rows = all<LogRow>('SELECT id, asset_id, event_id, ts, summary, fields, channel FROM log_events WHERE id > ? ORDER BY id LIMIT 2000', cursor).map(asEv);
    if (!rows.length) break;
    // Sysmon event ids (1, 3, 10…) mean something else in other channels: keep them apart.
    const batch = rows.filter((e) => e.channel !== SYSMON_CHANNEL);
    await sysmonDetect(rows.filter((e) => e.channel === SYSMON_CHANNEL));
    for (const e of batch) single(e);
    bruteForce(batch);
    slowBruteForce(batch);
    successAfterFailures(batch);
    await servicesInstalled(batch);
    notifyFinishedScans(batch);
    cursor = rows[rows.length - 1].id;
    processed += rows.length;
    setSetting('detection_cursor', String(cursor));
  }
  return processed;
}

/* ---------- website security headers ---------- */

export function evaluateWebHeaders(assetId: number, url: string, headers: Record<string, string | null>) {
  const missing: string[] = [];
  if (url.startsWith('https://') && !headers['strict-transport-security']) missing.push('Strict-Transport-Security');
  if (!headers['content-security-policy']) missing.push('Content-Security-Policy');
  if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options');
  if (!headers['x-frame-options'] && !/frame-ancestors/i.test(headers['content-security-policy'] ?? '')) missing.push('X-Frame-Options / frame-ancestors');
  const leaks = headers['x-powered-by'] ? [`X-Powered-By: ${headers['x-powered-by']}`] : [];

  const fp = `web_security_headers:${assetId}`;
  if (!missing.length && !leaks.length) {
    const r = run(
      "UPDATE security_findings SET status = 'resolved', resolved_at = ?, note = 'Headers are now present (auto-resolved)' WHERE fingerprint = ? AND status IN ('open','acknowledged')",
      Date.now(), fp,
    );
    if (r.changes) publish('findings');
    return;
  }
  upsertFinding({
    ruleId: 'web_security_headers',
    assetId,
    title: 'Missing security headers',
    summary: [missing.length ? `Missing: ${missing.join(', ')}` : '', leaks.length ? `Leaks: ${leaks.join(', ')}` : ''].filter(Boolean).join(' · '),
    fingerprint: fp,
    condition: 'Response headers of the monitored URL',
    extra: { headers, url },
    mergeWindowMs: 365 * DAY,
  });
}

/* ---------- API ---------- */

export const detectionRouter = Router();

const FINDING_STATUSES = ['open', 'acknowledged', 'resolved', 'false_positive'] as const;

type FindingRow = {
  id: number; rule_id: string; asset_id: number | null; severity: string; title: string; summary: string; status: string;
  first_seen: number; last_seen: number; count: number; evidence: string; resolved_at: number | null; note: string | null;
  asset_name: string | null; rule_name: string;
};

const findingDto = (f: FindingRow) => ({
  id: f.id,
  ruleId: f.rule_id,
  ruleName: f.rule_name,
  assetId: f.asset_id,
  assetName: f.asset_name,
  severity: f.severity,
  title: f.title,
  summary: f.summary,
  status: f.status,
  firstSeen: f.first_seen,
  lastSeen: f.last_seen,
  count: f.count,
  resolvedAt: f.resolved_at,
  note: f.note,
  /** Plain Thai wording for the Thai UI (null when there is none for this rule). */
  plainTh: plainFinding({ ruleId: f.rule_id, severity: f.severity, title: f.title, summary: f.summary, evidence: parseJson<Evidence>(f.evidence, {}) }),
});

const FINDING_SELECT = `SELECT f.*, a.name AS asset_name, r.name AS rule_name FROM security_findings f
  LEFT JOIN assets a ON a.id = f.asset_id JOIN detection_rules r ON r.id = f.rule_id`;

detectionRouter.get('/findings', (req, res) => {
  const where: string[] = [];
  const params: (string | number)[] = [];
  const status = req.query.status as string | undefined;
  if (status === 'active') where.push("f.status IN ('open','acknowledged')");
  else if (status && (FINDING_STATUSES as readonly string[]).includes(status)) {
    where.push('f.status = ?');
    params.push(status);
  }
  if (req.query.severity && (SEVERITIES as readonly string[]).includes(String(req.query.severity))) {
    where.push('f.severity = ?');
    params.push(String(req.query.severity));
  }
  if (req.query.ruleId) {
    where.push('f.rule_id = ?');
    params.push(String(req.query.ruleId));
  }
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const rows = all<FindingRow>(`${FINDING_SELECT} ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY f.last_seen DESC LIMIT ?`, ...params, limit);
  res.json({ findings: rows.map(findingDto) });
});

detectionRouter.get('/findings/:id', (req, res) => {
  const f = get<FindingRow>(`${FINDING_SELECT} WHERE f.id = ?`, idParam(req));
  if (!f) throw new HttpError(404, 'Not found');
  const ev = parseJson<Evidence>(f.evidence, {});
  const ids = (ev.eventIds ?? []).slice(-100);
  const events = ids.length
    ? all<{ id: number; ts: number; event_id: number; channel: string; summary: string; fields: string }>(
        `SELECT id, ts, event_id, channel, summary, fields FROM log_events WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY ts`,
        ...ids,
      ).map((e) => ({ id: e.id, ts: e.ts, eventId: e.event_id, channel: e.channel, summary: e.summary, fields: parseJson(e.fields, {}) }))
    : [];
  const incidents = all<{ id: number; title: string; status: string }>(
    "SELECT i.id, i.title, i.status FROM incident_links l JOIN incidents i ON i.id = l.incident_id WHERE l.kind = 'finding' AND l.ref_id = ?",
    f.id,
  );
  res.json({
    finding: findingDto(f),
    evidence: {
      condition: ev.condition ?? null,
      from: ev.from ?? null,
      to: ev.to ?? null,
      eventCount: (ev.eventIds ?? []).length,
      retainedEvents: events,
      // When raw events have aged out (14-day retention), the stored samples remain as evidence.
      samples: ev.samples ?? [],
      headers: ev.headers ?? null,
      url: ev.url ?? null,
      details: ev.details ?? null,
    },
    incidents,
  });
});

function readStatusChange(b: Record<string, unknown>) {
  const status = oneOf(b.status, 'Status', FINDING_STATUSES)!;
  const note = str(b.note, 'Note', { optional: true, max: 1000 });
  if ((status === 'false_positive' || status === 'resolved') && !note) throw new HttpError(400, 'Please add a short note explaining why');
  return { status, note };
}

function setFindingStatus(id: number, status: string, note: string | undefined, ip: string) {
  const r = run(
    'UPDATE security_findings SET status = ?, note = COALESCE(?, note), resolved_at = ? WHERE id = ?',
    status, note ?? null, status === 'resolved' || status === 'false_positive' ? Date.now() : null, id,
  );
  if (r.changes) audit('finding.status', { ip, resourceType: 'finding', resourceId: id, detail: { status, note } });
  return r.changes > 0;
}

detectionRouter.put('/findings/:id/status', (req, res) => {
  const id = idParam(req);
  const { status, note } = readStatusChange(body(req));
  if (!setFindingStatus(id, status, note, clientIp(req))) throw new HttpError(404, 'Not found');
  publish('findings');
  res.json({ ok: true });
});

/** Same as the single-finding change, applied to many at once; every finding still gets its own audit entry. */
detectionRouter.post('/findings/bulk-status', (req, res) => {
  const b = body(req);
  const { status, note } = readStatusChange(b);
  const raw = b.ids;
  if (!Array.isArray(raw) || !raw.length || raw.length > 500 || !raw.every((x) => Number.isInteger(x) && x > 0)) {
    throw new HttpError(400, 'ids must be a list of 1–500 finding ids');
  }
  const ids = [...new Set(raw as number[])];
  const ip = clientIp(req);
  const updated = tx(() => ids.filter((id) => setFindingStatus(id, status, note, ip)).length);
  if (updated) publish('findings');
  res.json({ ok: true, updated });
});

detectionRouter.get('/rules', (_req, res) => {
  const rows = all<RuleRow & { description: string }>('SELECT * FROM detection_rules');
  const counts = new Map(
    all<{ rule_id: string; n: number }>('SELECT rule_id, COUNT(*) AS n FROM security_findings WHERE first_seen > ? GROUP BY rule_id', Date.now() - 30 * DAY).map((r) => [r.rule_id, r.n]),
  );
  res.json({
    rules: RULES.map((def) => {
      const r = rows.find((x) => x.id === def.id)!;
      return {
        id: def.id,
        name: def.name,
        description: def.description,
        severity: r.severity,
        enabled: !!r.enabled,
        params: { ...def.params, ...parseJson<Record<string, number>>(r.params, {}) },
        paramKeys: Object.keys(def.params),
        findings30d: counts.get(def.id) ?? 0,
      };
    }),
  });
});

detectionRouter.put('/rules/:id', stepUp, (req, res) => {
  const def = RULES.find((r) => r.id === req.params.id);
  if (!def) throw new HttpError(404, 'Unknown rule');
  const b = body(req);
  const cur = get<RuleRow>('SELECT * FROM detection_rules WHERE id = ?', def.id)!;
  const params = { ...def.params, ...parseJson<Record<string, number>>(cur.params, {}) };
  if (b.params && typeof b.params === 'object') {
    for (const k of Object.keys(def.params)) {
      const v = (b.params as Record<string, unknown>)[k];
      if (v !== undefined) params[k] = num(v, k, { min: 1, max: 1440, int: true })!;
    }
  }
  const severity = b.severity !== undefined ? oneOf(b.severity, 'Severity', SEVERITIES)! : cur.severity;
  const enabled = b.enabled !== undefined ? (b.enabled ? 1 : 0) : cur.enabled;
  run('UPDATE detection_rules SET severity = ?, enabled = ?, params = ? WHERE id = ?', severity, enabled, JSON.stringify(params), def.id);
  audit('detection_rule.updated', { ip: clientIp(req), resourceType: 'detection_rule', resourceId: def.id, detail: { severity, enabled: !!enabled, params } });
  if (cur.enabled && !enabled) securityNotice(`detection rule "${def.id}" turned off`, `ปิดกฎตรวจจับ "${def.id}"`, req);
  publish('findings');
  res.json({ ok: true });
});
