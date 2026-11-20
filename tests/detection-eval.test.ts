/**
 * Detection & correlation accuracy on a labelled set of scenarios (AT-23, AT-33).
 *
 *   npx tsx --test tests/detection-eval.test.ts
 *
 * Each scenario is a short burst of Windows events with a ground-truth label written
 * by hand: which rules SHOULD alert (severity ≥ medium) and whether it SHOULD become an
 * incident. Scenarios are replayed two hours apart on a simulated clock so they cannot
 * influence each other, then precision / recall are computed per rule and overall.
 * Two scenarios are deliberately hard (a very slow password spray below every threshold
 * and a user who mistypes three times) to show the known limits honestly rather than a perfect score.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dir = mkdtempSync(join(tmpdir(), 'sentinel-eval-'));
process.env.DATA_DIR = dir;
const unsignedFile = join(dir, 'evil-service.ps1');
writeFileSync(unsignedFile, "'not signed'\n");

const { all, db, get, migrate, run } = await import('../server/db.js');
const { runDetection, seedDetectionRules } = await import('../server/modules/detection.js');
const { correlate } = await import('../server/modules/incidents.js');

const realNow = Date.now;
after(() => {
  Date.now = realNow;
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

type Ev = { at: number; id: number; channel?: string; f: Record<string, string> };
/** alerts: threshold alerts (e.g. CPU) firing on the same machine during the scenario; expectLinks: signals the incident must hold. */
type Scenario = { name: string; truth: string; events: Ev[]; expectRules: string[]; expectIncident: boolean; alerts?: { at: number; title: string; severity: string }[]; expectLinks?: number };

const MIN = 60_000;
const fail = (at: number, user: string, ip: string): Ev => ({ at, id: 4625, f: { TargetUserName: user, IpAddress: ip, LogonType: '3', SubStatus: '0xc000006a' } });
const logon = (at: number, user: string, type: string, ip = '-'): Ev => ({ at, id: 4624, f: { TargetUserName: user, LogonType: type, IpAddress: ip } });
const NOTEPAD = `"${process.env.SystemRoot ?? 'C:\\Windows'}\\System32\\notepad.exe"`;

const SCENARIOS: Scenario[] = [
  { name: 'AT-31: CPU + memory alerts and password guessing on one PC', truth: 'attack', expectRules: ['brute_force'], expectIncident: true, expectLinks: 3,
    alerts: [
      { at: 0, title: 'CPU high on EvalPC', severity: 'high' },
      { at: 2 * MIN, title: 'Memory high on EvalPC', severity: 'high' },
    ],
    events: Array.from({ length: 7 }, (_, i) => fail(MIN + i * 20_000, 'admin', '203.0.113.31')) },
  { name: 'Brute force from one IP', truth: 'attack', expectRules: ['brute_force'], expectIncident: false,
    events: Array.from({ length: 8 }, (_, i) => fail(i * 30_000, 'admin', '203.0.113.7')) },
  { name: 'Attack chain: guess → success → new user → admin', truth: 'attack', expectRules: ['brute_force', 'success_after_failures', 'new_local_user', 'admin_group_add'], expectIncident: true,
    events: [
      ...Array.from({ length: 6 }, (_, i) => fail(i * 20_000, 'svc', '198.51.100.9')),
      logon(3 * MIN, 'svc', '3', '198.51.100.9'),
      { at: 5 * MIN, id: 4720, f: { TargetUserName: 'backdoor', TargetSid: 'S-1-5-21-1-1001', SubjectUserName: 'svc' } },
      { at: 6 * MIN, id: 4732, f: { TargetUserName: 'Administrators', TargetSid: 'S-1-5-32-544', MemberSid: 'S-1-5-21-1-1001', SubjectUserName: 'svc' } },
    ] },
  { name: 'Slow password spray (1 try / 10 min, 10 tries)', truth: 'attack', expectRules: ['slow_brute_force'], expectIncident: false,
    events: Array.from({ length: 10 }, (_, i) => fail(i * 10 * MIN, 'administrator', '192.0.2.99')) },
  { name: 'Very slow spray (5 tries in 1 h)', truth: 'attack (hard case)', expectRules: ['slow_brute_force'], expectIncident: false,
    events: Array.from({ length: 5 }, (_, i) => fail(i * 15 * MIN, 'administrator', '192.0.2.98')) },
  { name: 'Device with a stale saved password (6 failures over 100 min)', truth: 'benign', expectRules: [], expectIncident: false,
    events: Array.from({ length: 6 }, (_, i) => fail(i * 20 * MIN, 'nas-backup', '192.168.1.40')) },
  { name: 'Owner mistypes password 3× then logs in', truth: 'benign (hard case)', expectRules: [], expectIncident: false,
    events: [...[0, 20_000, 40_000].map((t) => ({ ...fail(t, 'piece', '-'), f: { TargetUserName: 'piece', LogonType: '2', IpAddress: '127.0.0.1', SubStatus: '0xc000006a' } })), logon(60_000, 'piece', '2', '127.0.0.1')] },
  { name: 'One typo then success', truth: 'benign', expectRules: [], expectIncident: false,
    events: [{ ...fail(0, 'owner2', '-'), f: { TargetUserName: 'owner2', LogonType: '2', IpAddress: '-' } }, logon(10_000, 'owner2', '2')] },
  { name: 'Normal interactive logon and unlock', truth: 'benign', expectRules: [], expectIncident: false,
    events: [logon(0, 'owner3', '2'), logon(5 * MIN, 'owner3', '7')] },
  { name: 'Remote Desktop logon', truth: 'review', expectRules: ['remote_logon'], expectIncident: false,
    events: [logon(0, 'owner4', '10', '192.0.2.50')] },
  { name: 'New local user only', truth: 'review', expectRules: ['new_local_user'], expectIncident: false,
    events: [{ at: 0, id: 4720, f: { TargetUserName: 'guest2', TargetSid: 'S-1-5-21-1-1002', SubjectUserName: 'owner' } }] },
  { name: 'User added to non-privileged group (Users)', truth: 'benign', expectRules: [], expectIncident: false,
    events: [{ at: 0, id: 4732, f: { TargetUserName: 'Users', TargetSid: 'S-1-5-32-545', MemberSid: 'S-1-5-21-1-1003' } }] },
  { name: 'Security log cleared', truth: 'attack', expectRules: ['log_cleared'], expectIncident: true,
    events: [{ at: 0, id: 1102, f: { SubjectUserName: 'intruder' } }] },
  { name: 'Signed service installed (Windows binary)', truth: 'benign', expectRules: [], expectIncident: false,
    events: [{ at: 0, id: 7045, channel: 'System', f: { ServiceName: 'EvalSigned', ImagePath: NOTEPAD, StartType: 'auto start', AccountName: 'LocalSystem' } }] },
  { name: 'Unsigned service installed', truth: 'attack', expectRules: ['service_installed'], expectIncident: false,
    events: [{ at: 0, id: 7045, channel: 'System', f: { ServiceName: 'EvalUnsigned', ImagePath: `"${unsignedFile}"`, StartType: 'auto start', AccountName: 'LocalSystem' } }] },
  { name: 'Account lockout', truth: 'review', expectRules: ['account_lockout'], expectIncident: false,
    events: [{ at: 0, id: 4740, f: { TargetUserName: 'owner5', TargetDomainName: 'PC' } }] },
  { name: 'Defender detects malware', truth: 'attack', expectRules: ['defender_threat'], expectIncident: true,
    events: [{ at: 0, id: 1116, channel: 'Microsoft-Windows-Windows Defender/Operational', f: { 'Threat Name': 'Trojan:Win32/Eval', Path: 'C:\\Users\\x\\Downloads\\bad.exe' } }] },
  { name: 'Defender disabled, then unsigned service', truth: 'attack', expectRules: ['defender_disabled', 'service_installed'], expectIncident: true,
    events: [
      { at: 0, id: 5001, channel: 'Microsoft-Windows-Windows Defender/Operational', f: {} },
      { at: 4 * MIN, id: 7045, channel: 'System', f: { ServiceName: 'EvalPersist', ImagePath: `"${unsignedFile}"`, StartType: 'auto start', AccountName: 'LocalSystem' } },
    ] },
  { name: 'Dropper adds Defender exclusions (drive + fake svchost)', truth: 'attack', expectRules: ['defender_exclusion_added'], expectIncident: true,
    events: ['Paths\\C:\\', 'Paths\\C:\\Users\\me\\AppData\\Local\\svchost.exe', 'Processes\\svchost.exe'].map((v, k) => ({
      at: k * 1000, id: 5007, channel: 'Microsoft-Windows-Windows Defender/Operational',
      f: { 'Old Value': '', 'New Value': `HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\${v} = 0x0` },
    })) },
  { name: 'Owner excludes one program folder', truth: 'review', expectRules: ['defender_exclusion_added'], expectIncident: false,
    events: [{ at: 0, id: 5007, channel: 'Microsoft-Windows-Windows Defender/Operational', f: { 'Old Value': '', 'New Value': 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\C:\\Users\\me\\AppData\\Local\\DBeaver\\dbeaver.exe = 0x0' } }] },
  { name: 'Defender internal config change (not an exclusion)', truth: 'benign', expectRules: [], expectIncident: false,
    events: [{ at: 0, id: 5007, channel: 'Microsoft-Windows-Windows Defender/Operational', f: { 'Old Value': '', 'New Value': 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\EcsConfigs\\MpFC_Nis_WdFilterProcessExclusions = 0x1' } }] },
  { name: 'Unexpected shutdown (battery ran out)', truth: 'benign', expectRules: [], expectIncident: false,
    events: [{ at: 0, id: 6008, channel: 'System', f: { Data0: '11/11/2569', Data1: '17:38:35' } }] },
  { name: 'Few failures each from several IPs', truth: 'benign', expectRules: [], expectIncident: false,
    events: ['10.0.0.11', '10.0.0.12', '10.0.0.13'].flatMap((ip, k) => [fail(k * MIN, 'share', ip), fail(k * MIN + 5000, 'share', ip)]) },
  { name: 'Two signed services from one installer', truth: 'benign', expectRules: [], expectIncident: false,
    events: ['EvalInstA', 'EvalInstB'].map((n, k) => ({ at: k * 10_000, id: 7045, channel: 'System', f: { ServiceName: n, ImagePath: NOTEPAD, StartType: 'auto start', AccountName: 'LocalSystem' } })) },
];

const ALERTING = new Set(['medium', 'high', 'critical']);

test('detection and correlation accuracy on labelled scenarios', { timeout: 300_000 }, async () => {
  migrate();
  seedDetectionRules();
  const t0 = realNow() - 3 * 24 * 3600_000;
  run("INSERT INTO assets (id, name, type, environment, target, tags, status, created_at, updated_at) VALUES (1, 'EvalPC', 'host', 'lab', 'local', '[]', 'up', ?, ?)", t0, t0);

  let record = 1;
  const rows: { name: string; truth: string; expected: string[]; fired: string[]; incident: boolean; expectIncident: boolean }[] = [];
  for (const [i, s] of SCENARIOS.entries()) {
    const base = t0 + i * 2 * 3600_000;
    const ids: number[] = [];
    for (const e of s.events) {
      const r = run(
        'INSERT INTO log_events (asset_id, channel, event_id, record_id, ts, level, category, summary, fields) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)',
        e.channel ?? 'Security', e.id, record++, base + e.at, 'info', 'eval', `Eval event ${e.id}`, JSON.stringify(e.f),
      );
      ids.push(Number(r.lastInsertRowid));
    }
    for (const [k, a] of (s.alerts ?? []).entries()) {
      run(
        "INSERT INTO alert_events (rule_id, asset_id, fingerprint, status, severity, title, detail, value, triggered_at, last_notified_at) VALUES (NULL, 1, ?, 'firing', ?, ?, 'eval', NULL, ?, ?)",
        `eval:${i}:${k}`, a.severity, a.title, base + a.at, base + a.at,
      );
    }
    const end = base + Math.max(...s.events.map((e) => e.at), ...(s.alerts ?? []).map((a) => a.at));
    Date.now = () => end + MIN; // the "present" is one minute after the last event
    await runDetection();
    const before = get<{ n: number }>('SELECT MAX(id) AS n FROM incidents')?.n ?? 0;
    correlate();
    const created = all<{ id: number }>('SELECT id FROM incidents WHERE id > ?', before);
    const incident = created.length > 0;
    if (s.expectLinks != null) {
      assert.equal(created.length, 1, `${s.name}: exactly one incident`);
      const links = get<{ n: number }>('SELECT COUNT(*) AS n FROM incident_links WHERE incident_id = ?', created[0].id)!.n;
      assert.equal(links, s.expectLinks, `${s.name}: every signal is linked as evidence`);
    }
    const fired = all<{ rule_id: string; severity: string; evidence: string }>('SELECT rule_id, severity, evidence FROM security_findings')
      .filter((f) => ALERTING.has(f.severity) && (JSON.parse(f.evidence).eventIds as number[]).some((id) => ids.includes(id)))
      .map((f) => f.rule_id);
    rows.push({ name: s.name, truth: s.truth, expected: [...s.expectRules].sort(), fired: [...new Set(fired)].sort(), incident, expectIncident: s.expectIncident });
  }

  // ---- metrics ----
  let tp = 0, fp = 0, fn = 0;
  const perRule = new Map<string, { tp: number; fp: number; fn: number }>();
  const bump = (r: string, k: 'tp' | 'fp' | 'fn') => {
    const m = perRule.get(r) ?? { tp: 0, fp: 0, fn: 0 };
    m[k]++;
    perRule.set(r, m);
  };
  for (const r of rows) {
    for (const x of r.fired) if (r.expected.includes(x)) { tp++; bump(x, 'tp'); } else { fp++; bump(x, 'fp'); }
    for (const x of r.expected) if (!r.fired.includes(x)) { fn++; bump(x, 'fn'); }
  }
  const precision = tp / (tp + fp);
  const recall = tp / (tp + fn);
  let itp = 0, ifp = 0, ifn = 0;
  for (const r of rows) {
    if (r.incident && r.expectIncident) itp++;
    else if (r.incident) ifp++;
    else if (r.expectIncident) ifn++;
  }
  const iprec = itp / (itp + ifp);
  const irec = itp / (itp + ifn);

  const pct = (v: number) => `${(v * 100).toFixed(0)}%`;
  console.log('\nScenario | truth | expected | fired | incident (exp/got)');
  for (const r of rows) {
    const ok = r.expected.join() === r.fired.join() && r.incident === r.expectIncident ? '✓' : '✗';
    console.log(`${ok} ${r.name} | ${r.truth} | ${r.expected.join(', ') || '—'} | ${r.fired.join(', ') || '—'} | ${r.expectIncident ? 'yes' : 'no'}/${r.incident ? 'yes' : 'no'}`);
  }
  console.log('\nPer rule (tp/fp/fn):', JSON.stringify(Object.fromEntries(perRule)));
  console.log(`DETECTION precision ${pct(precision)} recall ${pct(recall)} (tp ${tp}, fp ${fp}, fn ${fn})`);
  console.log(`CORRELATION precision ${pct(iprec)} recall ${pct(irec)} (tp ${itp}, fp ${ifp}, fn ${ifn})`);

  // Quality gate: ≥ 85 % on this set. The two hard cases are expected misses.
  assert.ok(precision >= 0.85, `detection precision ${pct(precision)}`);
  assert.ok(recall >= 0.85, `detection recall ${pct(recall)}`);
  assert.ok(iprec >= 0.75, `correlation precision ${pct(iprec)}`);
  assert.ok(irec >= 0.75, `correlation recall ${pct(irec)}`);
});
