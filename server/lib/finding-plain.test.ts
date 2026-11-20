import assert from 'node:assert/strict';
import { test } from 'node:test';
import { plainFinding } from './finding-plain.js';

test('signed new service reads as nothing to do', () => {
  const p = plainFinding({
    ruleId: 'service_installed', severity: 'low',
    title: 'New service: Google Updater Service (GoogleUpdaterService159.0.8140.0)',
    summary: 'New service installed: … · signed by Google LLC (valid)',
    evidence: { condition: 'Event 7045 (service installed) · Authenticode: signed' },
  });
  assert.equal(p?.title, 'มีโปรแกรมติดตั้งบริการเบื้องหลังใหม่: Google Updater Service');
  assert.match(p!.summary, /Google LLC.*ไม่ต้องทำอะไร/);
});

test('scheduled task name is shortened and the GUID dropped', () => {
  const p = plainFinding({
    ruleId: 'persistence_added', severity: 'low', title: 'Scheduled task: x', summary: '',
    evidence: { details: { kind: 'task', name: '\\GoogleSystem\\GoogleUpdater\\GoogleUpdaterTaskSystem159.0.8140.0{624C73CB-DE05-437F-AE38-AD244A3D4269}', assessment: 'signed by Google LLC' } },
  });
  assert.equal(p?.title, 'งานตั้งเวลาอัตโนมัติใหม่: GoogleUpdaterTaskSystem159.0.8140.0');
});

test('a fake system file in auto-start is called out with a fix', () => {
  const p = plainFinding({ ruleId: 'persistence_added', severity: 'critical', title: 'Auto-start program: svchost', summary: '', evidence: { details: { kind: 'startup', name: 'svchost', assessment: '' } } });
  assert.match(p!.title, /ปลอมตัว/);
  assert.match(p!.fix!, /Offline/);
});

test('harmless exclusions do not sound like malware; dangerous ones do', () => {
  const calm = plainFinding({ ruleId: 'device_protection', severity: 'low', title: '', summary: '', evidence: { details: { check: 'defender_exclusions', status: 'warn', items: ['C:\\Users\\me\\AppData\\Local\\DBeaver\\dbeaver.exe'] } } });
  assert.match(calm!.title, /ไม่อันตราย/);
  assert.doesNotMatch(calm!.summary, /มัลแวร์/);
  const bad = plainFinding({ ruleId: 'device_protection', severity: 'critical', title: '', summary: '', evidence: { details: { check: 'defender_exclusions', status: 'bad', items: ['⚠ C:\\ — whole drive'], headlineTh: 'Defender ถูกตั้งให้ "ข้าม" 1 จุด' } } });
  assert.match(bad!.summary, /มัลแวร์/);
});

test('password guessing from this PC is worded as local', () => {
  const p = plainFinding({ ruleId: 'brute_force', severity: 'high', title: 'Password guessing from 127.0.0.1', summary: '6 failed logons within 10 min from 127.0.0.1 for account me', evidence: {} });
  assert.equal(p?.title, 'มีคนพยายามเดารหัสผ่าน ที่เครื่องนี้เอง');
  assert.match(p!.summary, /6 ครั้งภายใน 10 นาที/);
});

test('unknown rule falls back to the technical text', () => {
  assert.equal(plainFinding({ ruleId: 'something_else', severity: 'low', title: 't', summary: 's', evidence: {} }), null);
});
