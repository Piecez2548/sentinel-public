import assert from 'node:assert/strict';
import { test } from 'node:test';
import { appKey, crackHint, iconExe, judgeApp, newApps, normName, pickExes, programMessage, removedKeys, trimEvents, type App } from './new-programs.js';

const ps: App = { name: 'Adobe Photoshop 2020', version: '21.1.3', publisher: 'Adobe Systems Incorporated', location: 'C:\\Program Files\\Adobe\\Adobe Photoshop 2020', icon: 'C:\\Program Files\\Adobe\\Adobe Photoshop 2020\\Photoshop.exe' };

test('updates do not look like new programs: versions, architectures and languages are ignored', () => {
  assert.equal(normName('Python 3.12.1 (64-bit)'), 'python');
  assert.equal(normName('Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135'), 'microsoft visual c++ 2015-2022 redistributable');
  assert.equal(normName('Mozilla Firefox (x64 en-US)'), 'mozilla firefox (x64 en-us)'); // unusual tag kept: still stable across updates
  assert.equal(appKey({ name: 'Git 2.44.0', publisher: 'The Git Development Community' }), appKey({ name: 'Git 2.47.1', publisher: 'The Git Development Community' }));
  // A new year's edition is a different program.
  assert.notEqual(appKey({ name: 'Adobe Photoshop 2020' }), appKey({ name: 'Adobe Photoshop 2021' }));
});

test('new and removed programs against the baseline (duplicates under HKLM/HKCU count once)', () => {
  const base = new Set([appKey({ name: 'Git 2.44.0', publisher: 'Git' }), appKey({ name: 'Old Tool', publisher: 'X' })]);
  const now: App[] = [{ name: 'Git 2.47.1', publisher: 'Git' }, ps, { ...ps }];
  assert.deepEqual(newApps(now, base).map((a) => a.name), ['Adobe Photoshop 2020']);
  assert.deepEqual(removedKeys(now, base), ['old tool|x']);
});

test('crack and repack words are spotted; ordinary names are not', () => {
  assert.equal(crackHint({ name: 'Adobe Photoshop 2020 (repack by KpoJIuK)' }), 'repack');
  assert.equal(crackHint({ name: 'Office 2019', publisher: 'm0nkrus' }), 'm0nkrus');
  assert.equal(crackHint({ name: 'KMSAuto Net' }), 'KMSAuto');
  for (const n of ['Microsoft 365 Apps', 'Patch My PC', 'Crackle Media Player', 'Git', 'Discord']) assert.equal(crackHint({ name: n }), null, n);
});

test('the program file comes from DisplayIcon, else the biggest real .exe in the folder', () => {
  assert.equal(iconExe('"C:\\Program Files\\App\\app.exe",0'), 'C:\\Program Files\\App\\app.exe');
  assert.equal(iconExe('C:\\App\\app.exe,-101'), 'C:\\App\\app.exe');
  assert.equal(iconExe('C:\\App\\app.ico'), null);
  assert.equal(iconExe('%SystemRoot%\\x.exe'), null);
  assert.deepEqual(pickExes([{ name: 'unins000.exe', size: 9e6 }, { name: 'Updater.exe', size: 8e6 }, { name: 'app.exe', size: 5e6 }, { name: 'tool.exe', size: 1e6 }, { name: 'readme.txt', size: 1 }]), ['app.exe', 'tool.exe']);
});

test('verdicts: the cracked Photoshop of 2026-11-17 is high; signed is low and quiet', () => {
  const tampered = judgeApp(ps, [{ state: 'invalid', detail: 'signature HashMismatch', path: ps.icon! }]);
  assert.equal(tampered.severity, 'high');
  assert.equal(tampered.reason, 'tampered');
  assert.equal(judgeApp({ name: 'X (repack)' }, [{ state: 'signed', signer: 'X', path: 'C:\\x.exe' }]).reason, 'crack');
  assert.deepEqual(judgeApp({ name: 'Tool' }, [{ state: 'unsigned', detail: 'not digitally signed', path: 'C:\\t.exe' }]).severity, 'medium');
  const ok = judgeApp({ name: 'Discord' }, [{ state: 'signed', signer: 'Discord Inc.', path: 'C:\\d.exe' }]);
  assert.equal(ok.severity, 'low');
  assert.equal(ok.signer, 'Discord Inc.');
  assert.equal(judgeApp({ name: 'Y' }, []).reason, 'unknown');
  assert.equal(judgeApp({ name: 'Y' }, []).severity, 'low');
});

test('the Telegram message is in Thai, escaped, and says how to remove it', () => {
  const v = judgeApp(ps, [{ state: 'invalid', detail: 'signature HashMismatch', path: ps.icon! }]);
  const m = programMessage({ ...ps, name: 'A <b>' }, v, 'my-pc');
  assert.match(m.th, /ไฟล์ถูกดัดแปลง/);
  assert.match(m.th, /Uninstall/);
  assert.ok(!m.th.includes('<b>A <b>'), 'name is escaped');
  assert.match(m.en, /modified/);
});

test('history keeps 90 days', () => {
  const now = Date.now();
  const ev = trimEvents([{ kind: 'added', name: 'old', at: now - 91 * 86_400_000 }, { kind: 'removed', name: 'new', at: now - 1000 }], now);
  assert.deepEqual(ev.map((e) => e.name), ['new']);
});
