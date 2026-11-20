import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DRILL_EVERY_MS, DRILL_RETRY_MS, drillDue, drillProblems, type DrillFacts, type DrillResult } from './restore-drill.js';

const NOW = Date.parse('2026-11-17T15:00:00+07:00');
const run = (over: Partial<DrillResult>): DrillResult => ({ at: NOW, reason: 'scheduled', ok: true, problems: [], ...over });

test('due: first time at once, then monthly; a failure is retried the next day', () => {
  assert.equal(drillDue(null, NOW), true);
  assert.equal(drillDue(run({ at: NOW - DRILL_EVERY_MS + 60_000 }), NOW), false);
  assert.equal(drillDue(run({ at: NOW - DRILL_EVERY_MS }), NOW), true);
  assert.equal(drillDue(run({ ok: false, at: NOW - DRILL_RETRY_MS }), NOW), true);
  assert.equal(drillDue(run({ ok: false, at: NOW - 3_600_000 }), NOW), false);
  assert.equal(drillDue(run({ ok: false, skipped: true, at: NOW - DRILL_RETRY_MS }), NOW), false, 'nothing to test is not retried daily');
});

const good: DrillFacts = {
  name: 'sentinel-20261117-030000',
  createdAt: NOW - 12 * 3_600_000,
  bytes: 5_000_000,
  files: ['sentinel.db', 'master.key', 'manifest.json'],
  integrity: 'ok',
  counts: { assets: 12, log_events: 50_000, audit_logs: 900 },
  manifestCounts: { assets: 12, log_events: 50_020, audit_logs: 901 }, // logging went on while the manifest was counted
  masterMatches: true,
};

test('a healthy copy has no problems', () => {
  assert.deepEqual(drillProblems(good, NOW), []);
});

test('each kind of damage is reported', () => {
  assert.match(drillProblems({ ...good, files: ['sentinel.db', 'manifest.json'] }, NOW).join(), /master\.key is missing/);
  assert.match(drillProblems({ ...good, integrity: '*** in database main *** Page 7: btree' }, NOW).join(), /Database check failed/);
  assert.match(drillProblems({ ...good, counts: { ...good.counts!, log_events: 20_000 } }, NOW).join(), /Rows missing.*log_events/);
  assert.match(drillProblems({ ...good, masterMatches: false }, NOW).join(), /not this PC's key/);
  assert.match(drillProblems({ ...good, createdAt: NOW - 4 * 86_400_000 }, NOW).join(), /4 days old/);
});
