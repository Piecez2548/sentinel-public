import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cleanPaths, needsAttention, PENDING_AFTER_MS, threatHistory, type ThreatRow } from './threats.js';

const T0 = Date.parse('2026-11-17T01:32:39+07:00');
const ev = (event_id: number, ts: number, fields: Record<string, string>): ThreatRow => ({ event_id, ts, fields });
const keygen = { 'Threat Name': 'HackTool:Win32/Keygen', 'Severity Name': 'High', 'Category Name': 'Tool', Path: 'file:_C:\\Program Files (x86)\\Adobe\\Acrobat 11.0\\Acrobat\\amtlib.dll' };
const trojan = { 'Threat Name': 'Trojan:Win32/Kepavll!rfn', 'Severity Name': 'Severe', 'Category Name': 'Trojan', Path: 'file:_D:\\Q\\Dropbox.exe.quarantine; file:_D:\\Q\\updater.exe.quarantine' };

test('cleanPaths strips the resource prefix and splits on ;', () => {
  assert.deepEqual(cleanPaths(trojan.Path), ['D:\\Q\\Dropbox.exe.quarantine', 'D:\\Q\\updater.exe.quarantine']);
  assert.deepEqual(cleanPaths('containerfile:_C:\\a.zip; process:_pid:12'), ['C:\\a.zip', 'pid:12']);
  assert.deepEqual(cleanPaths(undefined), []);
});

test('the night of 2026-11-17: both found and quarantined', () => {
  const h = threatHistory([
    ev(1116, T0, keygen),
    ev(1116, T0, trojan),
    ev(1117, T0 + 19_000, { ...keygen, 'Action Name': 'Quarantine' }),
    ev(1117, T0 + 19_000, { ...trojan, 'Action Name': 'Quarantine' }),
  ]);
  assert.equal(h.length, 2);
  for (const t of h) {
    assert.equal(t.status, 'handled');
    assert.equal(t.action, 'Quarantine');
    assert.equal(t.detections, 1);
    assert.equal(needsAttention(t, T0 + 60 * 60_000), false);
  }
  const tr = h.find((t) => t.category === 'Trojan')!;
  assert.equal(tr.severity, 'Severe');
  assert.equal(tr.paths.length, 2);
});

test('failed, allowed and unanswered detections need attention', () => {
  const failed = threatHistory([ev(1116, T0, keygen), ev(1118, T0 + 5_000, { ...keygen, 'Action Name': 'Quarantine' })])[0];
  assert.equal(failed.status, 'failed');
  assert.ok(needsAttention(failed, T0 + 10_000));

  const allowed = threatHistory([ev(1116, T0, keygen), ev(1117, T0 + 5_000, { ...keygen, 'Action Name': 'Allow' })])[0];
  assert.equal(allowed.status, 'allowed');
  assert.ok(needsAttention(allowed, T0 + 10_000));

  const quiet = threatHistory([ev(1116, T0, keygen)])[0];
  assert.equal(quiet.status, 'pending');
  assert.equal(needsAttention(quiet, T0 + 60_000), false, 'too early: the action event usually follows within seconds');
  assert.ok(needsAttention(quiet, T0 + PENDING_AFTER_MS + 1));
});

test('found again after being quarantined counts as pending again; newest first', () => {
  const h = threatHistory([
    ev(1116, T0, keygen),
    ev(1117, T0 + 1_000, { ...keygen, 'Action Name': 'Quarantine' }),
    ev(1116, T0 + 86_400_000, keygen),
    ev(1116, T0 + 500, trojan),
  ]);
  assert.equal(h[0].name, 'HackTool:Win32/Keygen');
  assert.equal(h[0].status, 'pending');
  assert.equal(h[0].detections, 2);
  assert.equal(h[0].firstAt, T0);
});

test('same threat in two places is listed twice', () => {
  const h = threatHistory([ev(1116, T0, keygen), ev(1116, T0, { ...keygen, Path: 'file:_C:\\other\\amtlib.dll' })]);
  assert.equal(h.length, 2);
});
