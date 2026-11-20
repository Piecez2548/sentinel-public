import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

// The modules open the database on import: point it at a throwaway folder first.
const dir = mkdtempSync(join(tmpdir(), 'sentinel-proc-'));
process.env.DATA_DIR = dir;
const { db, migrate } = await import('../db.js');
migrate();
const { culpritText, groupProcesses, isProtected, runningGame } = await import('../modules/processes.js');
after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const rows = [
  { pid: 1, name: 'fczf', cpu: 40.2, mem: 3000, title: 'FC Online', company: 'Nexon' },
  { pid: 2, name: 'brave', cpu: 8, mem: 400, title: 'Brave Browser' },
  { pid: 3, name: 'brave#1', cpu: 7, mem: 500 },
  { pid: 4, name: 'MsMpEng', cpu: 20, mem: 300 },
  { pid: 5, name: 'notepad', cpu: 0, mem: 20 },
];

test('processes are summed per program', () => {
  const g = groupProcesses(rows);
  const brave = g.find((x) => x.name === 'brave')!;
  assert.equal(brave.count, 2);
  assert.equal(brave.cpu, 15);
  assert.equal(brave.memMB, 900);
  assert.equal(brave.title, 'Brave Browser');
});

test('alert text names the heaviest programs by their friendly name', () => {
  const g = groupProcesses(rows);
  assert.equal(culpritText(g, 'cpu'), 'FC Online 40% · MsMpEng 20% · Brave Browser 15%');
  assert.equal(culpritText(g, 'mem', 2), 'FC Online 2.9 GB · Brave Browser 900 MB');
});

test('Windows, security software, Tailscale and SENTINEL itself can never be closed', () => {
  for (const n of ['svchost.exe', 'MsMpEng', 'lsass', 'explorer', 'tailscaled', 'node', 'csrss']) assert.equal(isProtected(n), true, n);
  for (const n of ['fczf.exe', 'brave', 'notepad']) assert.equal(isProtected(n), false, n);
});

test('game mode spots a listed game in the snapshot', () => {
  const snap = { at: Date.now(), groups: groupProcesses(rows), running: ['fczf', 'brave', 'notepad'] };
  assert.equal(runningGame(snap, { enabled: true, processes: ['fczf'] })?.title, 'FC Online');
  assert.equal(runningGame(snap, { enabled: false, processes: ['fczf'] }), null, 'off');
  assert.equal(runningGame({ ...snap, running: ['brave'] }, { enabled: true, processes: ['fczf'] }), null, 'game not open');
  assert.equal(runningGame(null, { enabled: true, processes: ['fczf'] }), null, 'no snapshot yet');
});
