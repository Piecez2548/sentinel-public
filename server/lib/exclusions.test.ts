import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exclusionRisk } from './exclusions.js';

test('flags the exclusions a malware dropper adds', () => {
  // The exact set found on a test PC on 2026-04-11.
  for (const p of ['C:\\', 'C:\\WINDOWS', 'C:\\Program Files', 'C:\\Users\\WINDOW~1\\AppData\\Local\\Temp', 'C:\\Users\\me\\AppData\\Roaming',
    'C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup', 'C:\\Users\\me\\AppData\\Local\\Temp\\becsv.exe',
    'C:\\Users\\me\\AppData\\Local\\svchost.exe']) {
    assert.ok(exclusionRisk('Paths', p), p);
  }
  assert.ok(exclusionRisk('Processes', 'svchost.exe'));
  assert.ok(exclusionRisk('Extensions', '.exe'));
});

test('a narrow exclusion for one program is not flagged', () => {
  assert.equal(exclusionRisk('Processes', 'C:\\Users\\me\\AppData\\Local\\DBeaver\\dbeaver.exe'), null);
  assert.equal(exclusionRisk('Processes', 'becsv.exe'), null, 'unknown bare name: not provably risky by itself');
  assert.equal(exclusionRisk('Paths', 'D:\\Project_001\\node_modules'), null);
  assert.equal(exclusionRisk('Paths', 'C:\\Program Files\\SomeGame'), null);
  assert.equal(exclusionRisk('Extensions', '.log'), null);
});
