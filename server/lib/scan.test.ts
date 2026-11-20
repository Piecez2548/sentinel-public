import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dir = mkdtempSync(join(tmpdir(), 'sentinel-scan-'));
process.env.DATA_DIR = dir;
const { pairScans, scanResultMessage, isSkip } = await import('../modules/scan.js');
const { db } = await import('../db.js');
after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const T0 = Date.parse('2026-11-16T15:00:00Z');
const ev = (eventId: number, min: number, scanId: string, param: string, extra: Partial<{ durationSec: number; stopReason: string; trigger: string }> = {}) => ({
  id: min, eventId, ts: T0 + min * 60_000, scanId, param, trigger: extra.trigger ?? '', stopReason: extra.stopReason ?? '', stopIndex: '', durationSec: extra.durationSec ?? null,
});

test('scans are paired by Scan ID; skipped scheduled scans are dropped', () => {
  const runs = pairScans([
    ev(1000, 0, 'A', 'Full Scan', { trigger: 'User' }),
    ev(1000, 5, 'B', 'Quick Scan', { trigger: 'Scheduled maintenance' }),
    ev(1002, 5, 'B', 'Quick Scan', { stopReason: 'Scheduled scan was skipped because the last successful scan was within the last 7 days' }),
    ev(1001, 130, 'A', 'Full Scan', { durationSec: 7800 }),
    ev(1000, 140, 'C', 'Quick Scan'),
  ], T0 + 141 * 60_000);
  assert.deepEqual(runs.map((r) => [r.scanId, r.outcome]), [['A', 'done'], ['C', 'running']]);
  assert.equal(runs[0].durationSec, 7800);
  assert.equal(runs[0].trigger, 'User');
  assert.ok(isSkip(ev(1002, 0, 'x', 'Quick Scan', { stopReason: 'Scheduled scan was skipped because…' })));
});

test('a start never reported back on for a day is not shown as running', () => {
  assert.equal(pairScans([ev(1000, 0, 'A', 'Full Scan')], T0 + 25 * 3_600_000).length, 0);
});

test('messages: full scan always, daily quick scans only when asked or something was found', () => {
  const full = pairScans([ev(1000, 0, 'A', 'Full Scan'), ev(1001, 130, 'A', 'Full Scan', { durationSec: 7800 })], T0)[0];
  const m = scanResultMessage(full, [], false)!;
  assert.match(m.th, /สแกนเต็มเสร็จแล้ว — ไม่พบภัยคุกคาม/);
  assert.match(m.th, /2 ชม\. 10 นาที/);
  const quick = pairScans([ev(1000, 0, 'Q', 'Quick Scan'), ev(1001, 3, 'Q', 'Quick Scan', { durationSec: 157 })], T0)[0];
  assert.equal(scanResultMessage(quick, [], false), null, 'Defender’s own daily quick scan stays quiet');
  assert.match(scanResultMessage(quick, [], true)!.th, /สแกนด่วนเสร็จแล้ว/);
  const found = scanResultMessage(quick, ['Trojan:Win32/Test', 'Trojan:Win32/Test'], false)!;
  assert.match(found.th, /พบภัยคุกคาม 2 รายการ/);
  assert.match(found.th, /Trojan:Win32\/Test/);
  const stopped = pairScans([ev(1000, 0, 'S', 'Full Scan'), ev(1002, 20, 'S', 'Full Scan', { stopReason: 'User' })], T0)[0];
  assert.match(scanResultMessage(stopped, [], false)!.th, /หยุดกลางคัน/);
});
