import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { getSetting, run, setSetting, tx } from '../db.js';
import { publish } from '../lib/bus.js';
import { registerComponent, reportError, reportOk } from '../lib/health.js';
import { getLocalAssetId } from './host-collector.js';
import { describeSysmon, SYSMON_CHANNEL, SYSMON_IDS } from '../lib/sysmon-rules.js';

/**
 * Windows Event Log collector (ADR-005). Reads only the event IDs that the
 * detection rules use, with an EventRecordID cursor per channel so every
 * event is ingested exactly once (INSERT OR IGNORE guards overlaps).
 */

const exec = promisify(execFile);
registerComponent('eventlog', 'Windows Event Log collector', 30_000);

const SECURITY = 'Security';
const SYSTEM = 'System';
const DEFENDER = 'Microsoft-Windows-Windows Defender/Operational';
const CAP = 1000;
const FIRST_RUN_WINDOW_MS = 7 * 86_400_000;

/** keep: post-filter for noisy ids that XPath cannot narrow (event log XPath has no contains()). */
type Query = { channel: string; ids: number[]; extra?: string; optional?: boolean; keep?: (e: ParsedEvent) => boolean };

/** Defender 5007 "configuration changed" that adds or removes a scan exclusion (path / process / extension / IP). */
export const EXCLUSION_RE = /\\Windows Defender\\Exclusions\\(Paths|Processes|Extensions|IpAddresses)\\(.*?)(?:\s*=\s*0x[0-9a-f]+)?$/i;

const INTERACTIVE_LOGON_TYPES = ['2', '7', '10', '11'];
const QUERIES: Query[] = [
  { channel: SECURITY, ids: [4625, 4648, 4720, 4722, 4724, 4728, 4732, 4756, 4740, 1102] },
  {
    channel: SECURITY,
    ids: [4624],
    extra: `EventData[${INTERACTIVE_LOGON_TYPES.map((t) => `(Data[@Name='LogonType']='${t}')`).join(' or ')}]`,
  },
  { channel: SYSTEM, ids: [104, 6005, 6006, 6008, 7045] },
  { channel: DEFENDER, ids: [1116, 1117, 1118, 1119, 5001], optional: true },
  // Scan started / finished / stopped / failed: scan status on Device health and the result on Telegram.
  { channel: DEFENDER, ids: [1000, 1001, 1002, 1005], optional: true },
  // Sysmon (only when installed; scripts/sysmon-config.xml keeps it to suspicious activity).
  { channel: SYSMON_CHANNEL, ids: SYSMON_IDS, optional: true },
  { channel: DEFENDER, ids: [5007], optional: true, keep: (e) => EXCLUSION_RE.test(e.fields['New Value'] || e.fields['Old Value'] || '') },
];

/* ---------- parsing ---------- */

export type ParsedEvent = {
  channel: string;
  eventId: number;
  recordId: number;
  ts: number;
  provider: string;
  computer: string;
  fields: Record<string, string>;
};

const unescapeXml = (s: string) =>
  s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&amp;/g, '&')
    // Windows embeds invisible bidi marks in some dates (e.g. event 6008).
    .replace(/[‎‏‪-‮]/g, '');

/** Fields that are noise for detection and investigation. */
const DROP_FIELDS = new Set(['LogonGuid', 'TransmittedServices', 'LmPackageName', 'KeyLength', 'ImpersonationLevel', 'RestrictedAdminMode', 'RemoteCredentialGuard', 'VirtualAccount', 'ElevatedToken', 'TargetLinkedLogonId', 'TargetOutboundUserName', 'TargetOutboundDomainName']);

export function parseEvents(xml: string, channel: string): ParsedEvent[] {
  const out: ParsedEvent[] = [];
  for (const chunk of xml.split('<Event xmlns').slice(1)) {
    const eventId = Number(/<EventID[^>]*>(\d+)<\/EventID>/.exec(chunk)?.[1]);
    const recordId = Number(/<EventRecordID>(\d+)<\/EventRecordID>/.exec(chunk)?.[1]);
    const time = /<TimeCreated SystemTime=['"]([^'"]+)['"]/.exec(chunk)?.[1];
    if (!eventId || !recordId || !time) continue;
    const fields: Record<string, string> = {};
    let unnamed = 0;
    for (const m of chunk.matchAll(/<Data(?: Name=['"]([^'"]*)['"])?\s*(?:\/>|>([\s\S]*?)<\/Data>)/g)) {
      const name = m[1] ?? `Data${unnamed++}`;
      if (DROP_FIELDS.has(name)) continue;
      fields[name] = unescapeXml((m[2] ?? '').trim()).slice(0, 500);
    }
    const userData = /<UserData>([\s\S]*?)<\/UserData>/.exec(chunk)?.[1];
    if (userData) {
      for (const m of userData.matchAll(/<(\w+)>([^<]*)<\/\1>/g)) fields[m[1]] = unescapeXml(m[2].trim()).slice(0, 500);
    }
    out.push({
      channel,
      eventId,
      recordId,
      ts: Date.parse(time),
      provider: /<Provider Name=['"]([^'"]+)['"]/.exec(chunk)?.[1] ?? '',
      computer: /<Computer>([^<]*)<\/Computer>/.exec(chunk)?.[1] ?? '',
      fields,
    });
  }
  return out;
}

/* ---------- catalog: category / level / human summary ---------- */

const LOGON_TYPES: Record<string, string> = {
  '2': 'interactive', '3': 'network', '4': 'batch', '5': 'service', '7': 'unlock', '8': 'network-cleartext',
  '9': 'new-credentials', '10': 'remote (RDP)', '11': 'cached',
};
const FAILURE_REASONS: Record<string, string> = {
  '0xc000006a': 'wrong password',
  '0xc0000064': 'user does not exist',
  '0xc0000234': 'account locked out',
  '0xc0000072': 'account disabled',
  '0xc000006f': 'outside allowed hours',
  '0xc0000070': 'workstation not allowed',
  '0xc0000071': 'password expired',
  '0xc0000193': 'account expired',
  '0xc0000133': 'clock out of sync',
  '0xc0000224': 'must change password',
  '0xc000015b': 'logon type not granted',
  '0xc000006d': 'bad username or password',
};

const dash = (v: string | undefined) => (!v || v === '-' ? '' : v);
const who = (f: Record<string, string>, p = 'Target') =>
  [dash(f[`${p}DomainName`]), dash(f[`${p}UserName`])].filter(Boolean).join('\\') || 'unknown';

export function describe(e: ParsedEvent): { category: string; level: string; summary: string } {
  if (e.channel === SYSMON_CHANNEL) return describeSysmon(e.eventId, e.fields);
  const f = e.fields;
  const from = dash(f.IpAddress) || dash(f.WorkstationName);
  switch (e.eventId) {
    case 4624:
      return { category: 'logon', level: 'info', summary: `Logon: ${who(f)} (${LOGON_TYPES[f.LogonType] ?? `type ${f.LogonType}`})${from ? ` from ${from}` : ''}` };
    case 4625: {
      const reason = FAILURE_REASONS[(f.SubStatus || '').toLowerCase()] ?? FAILURE_REASONS[(f.Status || '').toLowerCase()] ?? 'logon failure';
      return { category: 'logon_failure', level: 'warning', summary: `Failed logon: ${who(f)} — ${reason} (${LOGON_TYPES[f.LogonType] ?? `type ${f.LogonType}`})${from ? ` from ${from}` : ''}` };
    }
    case 4648:
      return { category: 'credentials', level: 'info', summary: `${who(f, 'Subject')} used explicit credentials of ${who(f)}${dash(f.TargetServerName) ? ` for ${f.TargetServerName}` : ''}${dash(f.ProcessName) ? ` (${f.ProcessName})` : ''}` };
    case 4720:
      return { category: 'account', level: 'warning', summary: `User account created: ${who(f)} by ${who(f, 'Subject')}` };
    case 4722:
      return { category: 'account', level: 'info', summary: `User account enabled: ${who(f)} by ${who(f, 'Subject')}` };
    case 4724:
      return { category: 'account', level: 'warning', summary: `Password reset attempted for ${who(f)} by ${who(f, 'Subject')}` };
    case 4728:
    case 4732:
    case 4756:
      return { category: 'group', level: 'warning', summary: `${dash(f.MemberName) || dash(f.MemberSid) || 'member'} added to group ${f.TargetUserName || '?'} by ${who(f, 'Subject')}` };
    case 4740:
      return { category: 'account', level: 'warning', summary: `Account locked out: ${dash(f.TargetUserName) || 'unknown'}${dash(f.TargetDomainName) ? ` (caller: ${f.TargetDomainName})` : ''}` };
    case 1102:
      return { category: 'log_tamper', level: 'critical', summary: `Security audit log was cleared by ${dash(f.SubjectUserName) || 'unknown'}` };
    case 104:
      return { category: 'log_tamper', level: 'critical', summary: `${f.Channel || 'An event'} log was cleared by ${dash(f.SubjectUserName) || 'unknown'}` };
    case 6005:
      return { category: 'system', level: 'info', summary: 'System started (Event Log service started)' };
    case 6006:
      return { category: 'system', level: 'info', summary: 'Clean shutdown' };
    case 6008: {
      // wevtutil writes in the console code page, so the bidi marks around the date arrive as '?'.
      const date = (f.Data0 ?? '').replace(/\?/g, '');
      return { category: 'system', level: 'warning', summary: `Unexpected shutdown${date ? ` (previous shutdown at ${f.Data1 ?? ''} ${date})` : ''}` };
    }
    case 7045:
      return { category: 'service', level: 'warning', summary: `New service installed: ${f.ServiceName || '?'} — ${f.ImagePath || '?'} (start: ${f.StartType || '?'}, account: ${f.AccountName || '?'})` };
    case 1116:
      return { category: 'malware', level: 'critical', summary: `Defender detected ${f['Threat Name'] || 'a threat'}${f.Path ? ` in ${f.Path}` : ''}` };
    case 1117:
      return { category: 'malware', level: 'warning', summary: `Defender action "${f['Action Name'] || '?'}" on ${f['Threat Name'] || 'threat'}` };
    case 1118:
    case 1119:
      return { category: 'malware', level: 'critical', summary: `Defender could not ${(f['Action Name'] || 'act on').toLowerCase()} ${f['Threat Name'] || 'a threat'}${f.Path ? ` in ${f.Path}` : ''}` };
    case 5001:
      return { category: 'defense', level: 'critical', summary: 'Defender real-time protection was disabled' };
    case 1000:
      return { category: 'scan', level: 'info', summary: `Defender ${f['Scan Parameters'] || 'scan'} started${f['Scan Trigger'] ? ` (${f['Scan Trigger']})` : ''}` };
    case 1001:
      return { category: 'scan', level: 'info', summary: `Defender ${f['Scan Parameters'] || 'scan'} finished in ${Number(f['Scan Time Hours'] || 0)}h ${Number(f['Scan Time Minutes'] || 0)}m ${Number(f['Scan Time Seconds'] || 0)}s` };
    case 1002:
      return { category: 'scan', level: 'info', summary: `Defender ${f['Scan Parameters'] || 'scan'} stopped${f['Stop Reason'] ? `: ${f['Stop Reason']}` : ''}` };
    case 1005:
      return { category: 'scan', level: 'warning', summary: `Defender ${f['Scan Parameters'] || 'scan'} failed${f['Error Description'] ? `: ${f['Error Description']}` : ''}` };
    case 5007: {
      const added = EXCLUSION_RE.exec(f['New Value'] ?? '');
      const removed = EXCLUSION_RE.exec(f['Old Value'] ?? '');
      if (added) return { category: 'defense', level: 'critical', summary: `Defender exclusion added (${added[1]}): ${added[2]}` };
      if (removed) return { category: 'defense', level: 'info', summary: `Defender exclusion removed (${removed[1]}): ${removed[2]}` };
      return { category: 'defense', level: 'info', summary: 'Defender configuration changed' };
    }
    default:
      return { category: 'other', level: 'info', summary: `Event ${e.eventId} from ${e.provider}` };
  }
}

/* ---------- collection ---------- */

function buildXPath(q: Query, cursor: number | null): string {
  const ids = q.ids.map((id) => `EventID=${id}`).join(' or ');
  const range = cursor != null ? `EventRecordID > ${cursor}` : `TimeCreated[timediff(@SystemTime) <= ${FIRST_RUN_WINDOW_MS}]`;
  return `*[System[(${range}) and (${ids})]${q.extra ? ` and ${q.extra}` : ''}]`;
}

async function wevtutil(channel: string, xpath: string): Promise<string> {
  const { stdout } = await exec('wevtutil', ['qe', channel, `/q:${xpath}`, '/f:xml', `/c:${CAP}`], {
    windowsHide: true,
    timeout: 60_000,
    maxBuffer: 128 * 1024 * 1024,
  });
  return stdout;
}

export function eventlogEnabled() {
  return process.platform === 'win32' && getSetting('eventlog_enabled') !== 'false';
}

let lastIngest = { at: 0, count: 0 };
export const lastEventlogIngest = () => lastIngest;

/** Returns ids of newly inserted log_events rows. */
export async function collectEventLog(): Promise<number> {
  if (process.env.SENTINEL_TEST_FAIL === 'eventlog') throw new Error('Injected failure (SENTINEL_TEST_FAIL)');
  if (process.platform !== 'win32') {
    reportOk('eventlog', 'Not available on this OS');
    return 0;
  }
  if (!eventlogEnabled()) {
    reportOk('eventlog', 'Disabled in settings');
    return 0;
  }
  const assetId = getLocalAssetId();
  if (assetId == null) return 0;

  const byChannel = new Map<string, Query[]>();
  for (const q of QUERIES) byChannel.set(q.channel, [...(byChannel.get(q.channel) ?? []), q]);

  const errors: string[] = [];
  let inserted = 0;

  for (const [channel, queries] of byChannel) {
    const key = `evtlog_cursor:${channel}`;
    const cursorRaw = getSetting(key);
    const cursor = cursorRaw ? Number(cursorRaw) : null;
    const results: { events: ParsedEvent[]; capped: boolean; maxRecord: number }[] = [];
    let failed = false;

    for (const q of queries) {
      try {
        const xml = await wevtutil(channel, buildXPath(q, cursor));
        const parsed = parseEvents(xml, channel);
        // `capped` and the cursor are based on everything read, the filter only decides what is stored.
        results.push({ events: q.keep ? parsed.filter(q.keep) : parsed, capped: parsed.length >= CAP, maxRecord: parsed.length ? Math.max(...parsed.map((e) => e.recordId)) : 0 });
      } catch (e) {
        const msg = (e as { stderr?: string }).stderr?.trim() || (e instanceof Error ? e.message : String(e));
        // A channel that does not exist (no Defender, Sysmon not installed). A half-registered channel answers
        // with a WMI "instance name … not recognized" error instead of "not found".
        if (q.optional && /could not be found|not found|instance name passed was not recognized/i.test(msg)) continue;
        failed = true;
        errors.push(
          /access is denied/i.test(msg)
            ? `${channel}: access denied — run SENTINEL as an administrator or add your account to the "Event Log Readers" group`
            : `${channel}: ${msg.split(/\r?\n/)[0]}`,
        );
      }
    }
    if (failed) continue; // keep cursor; retry next tick

    const all = results.flatMap((r) => r.events);
    const seenMax = Math.max(0, ...results.map((r) => r.maxRecord));
    if (!seenMax) continue;

    // Advance the cursor carefully when a query was capped (more events remain).
    const cappedMax = results.filter((r) => r.capped).map((r) => r.maxRecord);
    const newCursor = cappedMax.length ? Math.min(...cappedMax) : seenMax;

    tx(() => {
      for (const e of all) {
        const d = describe(e);
        const r = run(
          `INSERT OR IGNORE INTO log_events (asset_id, channel, event_id, record_id, ts, level, category, summary, fields)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          assetId, e.channel, e.eventId, e.recordId, e.ts, d.level, d.category, d.summary, JSON.stringify(e.fields),
        );
        inserted += Number(r.changes);
      }
      setSetting(key, String(Math.max(newCursor, cursor ?? 0)));
    });
  }

  if (errors.length) reportError('eventlog', errors.join(' · '));
  else reportOk('eventlog', inserted ? `Ingested ${inserted} new event(s)` : 'Up to date');
  if (inserted) {
    lastIngest = { at: Date.now(), count: inserted };
    publish('logs');
  }
  return inserted;
}
