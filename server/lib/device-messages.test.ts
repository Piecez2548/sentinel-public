import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkMessage, persistenceMessage } from './device-messages.js';

const EXCL = {
  id: 'defender_exclusions', status: 'bad' as const, severity: 'critical', msg: '{n} dangerous exclusion(s) — Defender skips these', vars: { n: 9 },
  items: ['⚠ C:\\ — excludes an entire drive', '⚠ C:\\WINDOWS — excludes the Windows folder', '⚠ C:\\Program Files — excludes all installed programs',
    '⚠ C:\\Users\\me\\AppData\\Local\\Temp — x', '⚠ C:\\Users\\me\\AppData\\Roaming — x', '⚠ svchost.exe — x', 'C:\\Users\\me\\AppData\\Local\\DBeaver\\dbeaver.exe'],
};

test('exclusions message: Thai, plain words, short list, fix steps', () => {
  const m = checkMessage(EXCL, 'my-pc');
  assert.match(m.th, /^🔴 <b>Defender ถูกตั้งให้ "ข้าม" 9 จุด<\/b>/);
  assert.match(m.th, /• ทั้งไดรฟ์ C:/);
  assert.match(m.th, /• โฟลเดอร์ Windows/);
  assert.match(m.th, /และอีก 2 จุด/);
  assert.match(m.th, /👉 <b>วิธีแก้:<\/b> Windows Security/);
  assert.match(m.th, /💻 my-pc$/);
  assert.ok(!/excludes|dangerous/.test(m.th), 'no English left in the Thai message');
  assert.ok(m.th.length < 500, `short enough for a phone (${m.th.length})`);
  assert.equal(m.headlineTh, 'Defender ถูกตั้งให้ "ข้าม" 9 จุด');
});

test('fake svchost auto-start message', () => {
  const m = persistenceMessage({ kind: 'startup', name: 'svchost', command: 'C:\\Users\\me\\AppData\\Local\\svchost.exe', severity: 'critical', reason: 'masquerade' }, 'my-pc');
  assert.match(m.th, /^🔴 <b>พบโปรแกรมเปิดอัตโนมัติปลอม: svchost<\/b>/);
  assert.match(m.th, /อยู่ที่ AppData\\Local\\svchost\.exe/);
  assert.match(m.th, /Task Manager → Startup apps → คลิกขวา "svchost" → Disable/);
});

test('HTML in names is escaped', () => {
  const m = persistenceMessage({ kind: 'task', name: '<b>x</b>', command: 'C:\\a.exe', severity: 'high', reason: 'unsigned' }, 'PC');
  assert.ok(!m.th.includes('<b>x</b>') && m.th.includes('&lt;b&gt;x&lt;/b&gt;'));
});
