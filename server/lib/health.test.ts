import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getHealth, registerComponent, reportJobError, reportOk } from './health.js';

const find = (name: string, now?: number) => getHealth(now).find((c) => c.name === name)!;

test('a component that stops reporting is flagged as stalled', () => {
  registerComponent('t-stall', 'Stall test', 30_000);
  reportOk('t-stall', 'fine');
  assert.equal(find('t-stall').ok, true);
  // 3 × 30 s = 90 s < 2 min floor, so still OK at +100 s, stalled at +3 min.
  assert.equal(find('t-stall', Date.now() + 100_000).ok, true);
  const stalled = find('t-stall', Date.now() + 3 * 60_000);
  assert.equal(stalled.ok, false);
  assert.match(stalled.message, /stalled/);
  assert.ok(stalled.errorSince, 'errorSince is set so the pipeline alert can time it');
});

test('a component that never reports after start is flagged', () => {
  registerComponent('t-never', 'Never test', 60_000);
  assert.equal(find('t-never').ok, true, 'fresh start is fine');
  assert.match(find('t-never', Date.now() + 10 * 60_000).message, /Never reported/);
});

test('components without an expected interval are never marked stalled', () => {
  registerComponent('t-free', 'No interval');
  reportOk('t-free');
  assert.equal(find('t-free', Date.now() + 24 * 3600_000).ok, true);
});

test('a crashing job is reported as an error', () => {
  registerComponent('t-crash', 'Crash test', 60_000);
  reportJobError('t-crash', new Error('boom'));
  const c = find('t-crash');
  assert.equal(c.ok, false);
  assert.match(c.message, /boom/);
  reportJobError('not-registered', new Error('ignored')); // must not throw
});
