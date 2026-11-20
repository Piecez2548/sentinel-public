import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { findRemoteTools, isRiskyListener, openPrograms, uacVerdict } from './exposure.js';
import { checkMessage } from './device-messages.js';

const dir = mkdtempSync(join(tmpdir(), 'sentinel-exposure-'));
process.env.DATA_DIR = dir;
const { exposureChecks } = await import('../modules/device-health.js');
const { db } = await import('../db.js');
after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const svc = (name: string, display = name, path = '') => ({ name, display, path, state: 'Running' });
// Example snapshot (trimmed).
const PC = {
  programs: ['Chrome Remote Desktop', 'Docker Desktop', 'RustDesk', 'Steam', 'MySQL Server 8.0'],
  services: [svc('RustDesk', 'RustDesk Service', '"C:\\Program Files\\RustDesk\\RustDesk.exe" --service'), svc('Spooler', 'Print Spooler', 'C:\\WINDOWS\\System32\\spoolsv.exe')],
};
const LISTEN = [
  { port: 135, process: 'svchost', path: 'C:\\WINDOWS\\system32\\svchost.exe' },
  { port: 445, process: 'System', path: '' },
  { port: 49664, process: 'lsass', path: '' },
  { port: 21118, process: 'rustdesk', path: 'C:\\Program Files\\RustDesk\\RustDesk.exe' },
  { port: 27036, process: 'steam', path: 'C:\\Program Files (x86)\\Steam\\steam.exe' },
  { port: 5719, process: 'SpotifyLauncher', path: 'C:\\Program Files\\WindowsApps\\Spotify\\SpotifyLauncher.exe' },
];

test('UAC: off and silent elevation are high, secure desktop off is a low warning', () => {
  assert.equal(uacVerdict({ enableLua: 0, consentAdmin: 5, secureDesktop: 1 }).severity, 'high');
  assert.equal(uacVerdict({ enableLua: 1, consentAdmin: 0, secureDesktop: 1 }).severity, 'high');
  assert.equal(uacVerdict({ enableLua: 1, consentAdmin: 5, secureDesktop: 0 }).status, 'warn');
  assert.equal(uacVerdict({ enableLua: 1, consentAdmin: 5, secureDesktop: 1 }).status, 'ok');
});

test('remote tools: services and installed programs, no false matches on Docker Desktop or the CRD web app', () => {
  assert.deepEqual(findRemoteTools(PC).map((t) => t.name), ['RustDesk']);
  const bad = { programs: [...PC.programs, 'AnyDesk'], services: [...PC.services, svc('TeamViewer', 'TeamViewer', 'C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe'), svc('chromoting', 'Chrome Remote Desktop Service')] };
  assert.deepEqual(findRemoteTools(bad).map((t) => t.name).sort(), ['AnyDesk', 'Chrome Remote Desktop Host', 'RustDesk', 'TeamViewer']);
});

test('open ports: Windows services are left out, the rest grouped by program', () => {
  const open = openPrograms([...LISTEN, { port: 1, process: 'svchost', path: 'C:\\Users\\me\\AppData\\svchost.exe' }], 'C:\\Windows');
  assert.deepEqual(open.map((p) => p.key), ['rustdesk', 'spotifylauncher', 'steam', 'svchost'], 'a fake svchost outside Windows is not hidden');
  assert.equal(isRiskyListener(open.find((p) => p.key === 'steam')!), false);
  assert.equal(isRiskyListener({ key: 'mysqld', process: 'mysqld', path: '', ports: [3306] }), true);
});

test('checks: approved tools pass, a new tool is high and names itself', () => {
  const ok = exposureChecks({ software: PC } as never, { tools: ['RustDesk'], ports: null });
  assert.equal(ok[0].status, 'ok');
  const c = exposureChecks({ software: { ...PC, programs: [...PC.programs, 'AnyDesk'] } } as never, { tools: ['RustDesk'], ports: null })[0];
  assert.equal(c.status, 'bad');
  assert.equal(c.severity, 'high');
  assert.deepEqual(c.keys, ['AnyDesk']);
  assert.match(checkMessage(c, 'PC').th, /AnyDesk/);
  const approved = exposureChecks({ software: { ...PC, programs: [...PC.programs, 'AnyDesk'] } } as never, { tools: ['RustDesk', 'AnyDesk'], ports: null })[0];
  assert.equal(approved.status, 'ok', 'once approved it no longer alerts');
});

test('checks: first run records ports quietly, later only new programs alert; databases are high', () => {
  assert.equal(exposureChecks({ listeners: LISTEN } as never, { tools: [], ports: null }, 'C:\\Windows')[0].status, 'ok', 'no baseline yet');
  const known = ['rustdesk', 'steam', 'spotifylauncher'];
  assert.equal(exposureChecks({ listeners: LISTEN } as never, { tools: [], ports: known }, 'C:\\Windows')[0].status, 'ok');
  const withDb = [...LISTEN, { port: 3306, process: 'mysqld', path: 'C:\\Program Files\\MySQL\\bin\\mysqld.exe' }];
  const c = exposureChecks({ listeners: withDb } as never, { tools: [], ports: known }, 'C:\\Windows')[0];
  assert.equal(c.status, 'warn');
  assert.equal(c.severity, 'high');
  assert.deepEqual(c.keys, ['mysqld']);
  assert.match(checkMessage(c, 'PC').th, /mysqld/);
  const game = exposureChecks({ listeners: [...LISTEN, { port: 2283, process: 'MuMuPlayerRemoteBackend', path: 'C:\\Program Files\\Netease\\x.exe' }] } as never, { tools: [], ports: known }, 'C:\\Windows')[0];
  assert.equal(game.severity, 'medium');
});

test('checks: sections missing from an older snapshot add nothing', () => {
  assert.deepEqual(exposureChecks({} as never, { tools: [], ports: null }), []);
});
