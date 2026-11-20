import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

// The module opens the database on import: point it at a throwaway folder first.
const dir = mkdtempSync(join(tmpdir(), 'sentinel-devh-'));
process.env.DATA_DIR = dir;
const { closedByOwner, evaluate, masquerades, persistenceItems } = await import('../modules/device-health.js');
const { db } = await import('../db.js');
after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const NOW = Date.parse('2026-11-12T12:00:00Z');
// Example values (trimmed).
const LAB = {
  isAdmin: true,
  defender: { antivirusEnabled: true, realTimeProtection: true, tamperProtected: true, signatureAgeDays: 0, signatureVersion: '1.463.261.0', quickScanAgeDays: 0, fullScanAgeDays: 253, lastQuickScan: '2026-11-12T02:19:37Z' },
  updates: { lastInstalled: '2026-11-11T17:00:00Z', lastHotfix: 'KB5132688', rebootPending: true },
  firewall: [{ name: 'Domain', enabled: true }, { name: 'Private', enabled: false }, { name: 'Public', enabled: true }],
  encryption: { available: true, drive: 'C:', protection: 'Off', status: 'FullyDecrypted', percent: 0 },
  disks: [{ name: 'KIOXIA', media: 'SSD', sizeGb: 477, health: 'Healthy', operational: 'OK', wearPct: 0, temperatureC: 46 }],
  battery: { designMWh: 56163, fullMWh: 56163, cycles: 103 },
  exclusions: {
    paths: ['C:\\', 'C:\\Program Files', 'C:\\Users\\me\\AppData\\Local\\svchost.exe', 'C:\\WINDOWS'],
    processes: ['becsv.exe', 'C:\\Users\\me\\AppData\\Local\\DBeaver\\dbeaver.exe', 'svchost.exe'],
    extensions: [],
  },
  startup: [
    { name: 'svchost', command: 'C:\\Users\\me\\AppData\\Local\\svchost.exe', location: 'HKU\\S-1-5-21-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', user: 'PC\\me' },
    { name: 'SecurityHealth', command: '%windir%\\system32\\SecurityHealthSystray.exe', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', user: 'Public' },
  ],
  tasks: [{ path: '\\', name: 'NoExec', author: '', exec: '' }, { path: '\\', name: 'Updater', author: 'X', exec: '"C:\\Program Files\\X\\up.exe" /c' }],
};

type C = { id: string; status: string; severity?: string; items?: string[]; vars?: Record<string, unknown> };
const byId = (checks: C[], id: string) => checks.find((c) => c.id === id)!;

test('example PC: dangerous Defender exclusions are critical, everything else graded sensibly', () => {
  const c = evaluate(LAB, NOW);
  const ex = byId(c, 'defender_exclusions');
  assert.equal(ex.status, 'bad');
  assert.equal(ex.severity, 'critical');
  assert.equal(ex.vars!.n, 5, 'C:\\, Program Files, svchost.exe path, WINDOWS, svchost.exe process');
  assert.ok(ex.items!.includes('C:\\Users\\me\\AppData\\Local\\DBeaver\\dbeaver.exe'), 'harmless exclusions still listed');
  assert.equal(byId(c, 'defender_av').status, 'ok');
  assert.equal(byId(c, 'defender_signatures').status, 'ok');
  assert.equal(byId(c, 'firewall').status, 'bad');
  assert.equal(byId(c, 'updates').status, 'warn', 'restart pending');
  assert.equal(byId(c, 'encryption').severity, 'low');
  assert.equal(byId(c, 'disks').status, 'ok');
  assert.equal(byId(c, 'battery').status, 'ok');
});

test('clean PC passes; old definitions and old updates are flagged', () => {
  const clean = { ...LAB, exclusions: { paths: [], processes: [], extensions: [] }, firewall: LAB.firewall.map((p) => ({ ...p, enabled: true })), updates: { ...LAB.updates, rebootPending: false }, encryption: { ...LAB.encryption, protection: 'On' } };
  assert.ok(evaluate(clean, NOW).every((c) => c.status === 'ok'), JSON.stringify(evaluate(clean, NOW).filter((c) => c.status !== 'ok')));
  const stale = { ...clean, defender: { ...LAB.defender, signatureAgeDays: 9 }, updates: { ...clean.updates, lastInstalled: '2026-09-01T00:00:00Z' } };
  const c = evaluate(stale, NOW);
  assert.equal(byId(c, 'defender_signatures').severity, 'high');
  assert.equal(byId(c, 'updates').severity, 'medium');
  const rtpOff = evaluate({ ...clean, defender: { ...LAB.defender, realTimeProtection: false } }, NOW);
  assert.equal(byId(rtpOff, 'defender_av').status, 'bad');
  const noAdmin = evaluate({ ...clean, exclusions: { needsAdmin: true } }, NOW);
  assert.equal(byId(noAdmin, 'defender_exclusions').status, 'unknown');
});

test('a program named like a Windows binary outside the Windows folder is caught', () => {
  assert.match(masquerades('C:\\Users\\me\\AppData\\Local\\svchost.exe', 'C:\\Windows')!, /svchost\.exe/);
  assert.equal(masquerades('C:\\Windows\\System32\\svchost.exe -k netsvcs', 'C:\\Windows'), null);
  assert.equal(masquerades('"C:\\Program Files\\Steam\\steam.exe" -silent', 'C:\\Windows'), null);
});

test('persistence items: startup entries and tasks with a program; tasks without one are ignored', () => {
  const items = persistenceItems(LAB);
  assert.equal(items.filter((i) => i.kind === 'startup').length, 2);
  assert.deepEqual(items.filter((i) => i.kind === 'task').map((i) => i.name), ['\\Updater']);
});

test('a finding the owner closed stays closed until the check sees something new', () => {
  const ev = (observed: string, items: string[]) => JSON.stringify({ details: { observed, items } });
  const closed = { status: 'resolved', note: 'รับทราบ', severity: 'low', evidence: ev('Drive C: is not encrypted', []) };
  assert.equal(closedByOwner(closed, { severity: 'low', observed: 'Drive C: is not encrypted', items: [] }), true);
  assert.equal(closedByOwner(closed, { severity: 'high', observed: 'Drive C: is not encrypted', items: [] }), false, 'worse level reopens');
  const excl = { ...closed, evidence: ev('1 exclusion(s), none look dangerous', ['a.exe']) };
  assert.equal(closedByOwner(excl, { severity: 'low', observed: '2 exclusion(s), none look dangerous', items: ['a.exe', 'b.exe'] }), false, 'a new item reopens');
  assert.equal(closedByOwner({ ...closed, note: 'Fixed — auto-resolved by the device health check' }, { severity: 'low', observed: 'Drive C: is not encrypted', items: [] }), false, 'fixed then broken again reopens');
  assert.equal(closedByOwner({ ...closed, status: 'open' }, { severity: 'low', observed: 'Drive C: is not encrypted', items: [] }), false);
});
