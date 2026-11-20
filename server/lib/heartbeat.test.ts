import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pingUrl } from '../modules/heartbeat.js';

test('heartbeat pings the plain URL when healthy and <url>/fail when a component fails', () => {
  const base = new URL('https://hc-ping.com/0b8f9a7e-1111-2222-3333-444455556666');
  assert.equal(pingUrl(base, []), 'https://hc-ping.com/0b8f9a7e-1111-2222-3333-444455556666');
  assert.equal(pingUrl(base, ['Backups']), 'https://hc-ping.com/0b8f9a7e-1111-2222-3333-444455556666/fail');
  assert.equal(pingUrl(new URL('https://hc-ping.com/abc/'), ['x']), 'https://hc-ping.com/abc/fail', 'trailing slash');
  assert.equal(pingUrl(new URL('https://hc-ping.com/abc?rid=1'), ['x']), 'https://hc-ping.com/abc/fail?rid=1', 'query kept');
});
