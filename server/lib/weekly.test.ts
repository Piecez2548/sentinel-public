import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AUTO_SCAN_DEFAULT, autoScanDecision, lastSlot, weekKey, weeklySummary, type WeeklyData } from './weekly.js';

// Local times (the PC is in Thailand; tests use the machine's zone through new Date(y, m, d, h)).
const at = (y: number, m: number, d: number, h = 0, min = 0) => new Date(y, m - 1, d, h, min).getTime();
// 2026-11-15 is a Sunday.
const SUN_20 = at(2026, 11, 15, 20);

test('lastSlot finds the most recent Sunday 20:00', () => {
  assert.equal(lastSlot(at(2026, 11, 15, 20, 5), 0, 20), SUN_20);
  assert.equal(lastSlot(at(2026, 11, 17, 9), 0, 20), SUN_20); // Tuesday
  assert.equal(lastSlot(at(2026, 11, 15, 19, 59), 0, 20), SUN_20 - 7 * 86_400_000); // just before → last week
  assert.equal(new Date(lastSlot(at(2026, 11, 18, 12), 3, 9)).getDay(), 3);
});

const base = { cfg: AUTO_SCAN_DEFAULT, lastAuto: 0, lastScanEnd: null, scanBusy: false, gameRunning: false };

test('auto scan: runs once per slot, catches up within 3 days, never during a game or another scan', () => {
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 60_000 }), 'run');
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 60_000, lastAuto: SUN_20 + 1000 }), 'done');
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 2 * 86_400_000 }), 'run', 'PC was off Sunday night: catch up on Tuesday');
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 4 * 86_400_000 }), 'done', 'too late: wait for next week');
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 60_000, gameRunning: true }), 'wait');
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 60_000, scanBusy: true }), 'wait');
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 60_000, lastScanEnd: SUN_20 - 3 * 3_600_000 }), 'covered', 'Defender scanned this afternoon');
  assert.equal(autoScanDecision({ ...base, now: SUN_20 + 60_000, lastScanEnd: SUN_20 - 2 * 86_400_000 }), 'run');
  assert.equal(autoScanDecision({ ...base, cfg: { ...AUTO_SCAN_DEFAULT, enabled: false }, now: SUN_20 + 60_000 }), 'off');
});

test('weekKey: weeks start on Monday', () => {
  assert.equal(weekKey(at(2026, 11, 15, 23)), weekKey(at(2026, 11, 9, 1))); // Sun and the Monday before
  assert.notEqual(weekKey(at(2026, 11, 16, 0, 1)), weekKey(at(2026, 11, 15, 23, 59)));
  assert.equal(weekKey(at(2026, 11, 16, 8)), '2026-W47');
  assert.equal(weekKey(at(2027, 1, 1, 8)), '2026-W53');
});

const week: WeeklyData = {
  from: at(2026, 11, 9, 8),
  to: at(2026, 11, 16, 8),
  threats: { total: 2, attention: 0, names: ['HackTool:Win32/Keygen', 'Trojan:Win32/Kepavll!rfn'] },
  scans: { done: 3, failed: 0, lastQuick: at(2026, 11, 15, 20, 5), lastFull: at(2026, 11, 13, 1), autoRan: true },
  programs: { added: [{ name: 'Discord', severity: 'low' }, { name: 'Tool <x>', severity: 'medium' }], removed: 2 },
  findings: { high: 1, low: 3 },
  backup: { lastAt: at(2026, 11, 16, 3), sealed: 7 },
  updates: null,
};

test('weekly summary in Thai: threats handled, programs, open findings, backups', () => {
  const s = weeklySummary(week, true);
  assert.match(s, /สรุปประจำสัปดาห์ \(9\/11 – 16\/11\)/);
  assert.match(s, /พบ 2 — Defender จัดการครบแล้ว/);
  assert.match(s, /ติดตั้งใหม่ 2 \(Discord, 🟡 Tool &lt;x&gt;\) · ถอนออก 2/);
  assert.match(s, /🟠 สูง 1 · ⚪ ต่ำ 3/);
  assert.match(s, /แบ็กอัป: ปกติ · สำเนาเข้ารหัสบนคลาวด์ 7 ชุด/);
  assert.ok(!s.includes('Windows Update'));
});

test('weekly summary flags what needs a look', () => {
  const s = weeklySummary({ ...week, threats: { total: 1, attention: 1, names: ['X'] }, findings: {}, backup: { lastAt: at(2026, 11, 10), sealed: null }, updates: 'Last update installed 40 days ago', programs: { added: [], removed: 0 } }, false);
  assert.match(s, /⚠️ 1 need a look/);
  assert.match(s, /Open findings: none/);
  assert.match(s, /Backups: ⚠️ last 6 day\(s\) ago/);
  assert.match(s, /Windows Update: ⚠️ Last update/);
  assert.match(s, /nothing installed or removed/);
});
