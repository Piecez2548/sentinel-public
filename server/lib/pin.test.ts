import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PIN_GRACE_MS, PIN_IDLE_MS, pinNeeded, pinProblem } from './pin.js';

const NOW = Date.parse('2026-11-16T12:00:00Z');

test('PIN is needed after leaving the app for longer than the grace period, or after going quiet', () => {
  const ok = { pin_ok: 1, away_at: null, last_seen_at: NOW - 10_000 };
  assert.equal(pinNeeded(ok, NOW), false);
  assert.equal(pinNeeded({ ...ok, away_at: NOW - PIN_GRACE_MS + 1000 }, NOW), false, 'a quick look at Telegram is fine');
  assert.equal(pinNeeded({ ...ok, away_at: NOW - PIN_GRACE_MS - 1000 }, NOW), true);
  assert.equal(pinNeeded({ ...ok, last_seen_at: NOW - PIN_IDLE_MS - 1000 }, NOW), true, 'closed app / phone asleep');
  assert.equal(pinNeeded({ ...ok, pin_ok: 0 }, NOW), true, 'stays locked until the PIN is entered');
});

test('PIN rules: exactly 6 digits, not trivially guessable', () => {
  assert.equal(pinProblem('482913'), null);
  assert.equal(pinProblem('905172'), null);
  assert.match(pinProblem('12345')!, /6 digits/);
  assert.match(pinProblem('12a456')!, /6 digits/);
  assert.match(pinProblem(123456)!, /6 digits/, 'must be a string');
  assert.match(pinProblem('000000')!, /same digit/);
  assert.match(pinProblem('123456')!, /run of digits/);
  assert.match(pinProblem('987654')!, /run of digits/);
  assert.match(pinProblem('112233')!, /common/);
});
