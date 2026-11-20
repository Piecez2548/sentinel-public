import assert from 'node:assert/strict';
import { test } from 'node:test';
import { relyingParty } from './passkey-rp.js';

test('fingerprint relying party: the tailnet address and localhost work, IP addresses do not', () => {
  assert.deepEqual(relyingParty('my-pc.tailnet-example.ts.net:8443'), { rpID: 'my-pc.tailnet-example.ts.net', origin: 'https://my-pc.tailnet-example.ts.net:8443' });
  assert.deepEqual(relyingParty('localhost:3001'), { rpID: 'localhost', origin: 'http://localhost:3001' });
  assert.equal(relyingParty('127.0.0.1:3001'), null, 'WebAuthn needs a domain name');
  assert.equal(relyingParty('100.64.0.10:8443'), null);
  assert.equal(relyingParty(undefined), null);
  assert.equal(relyingParty('evil.com/x'), null, 'odd host headers refused');
  assert.equal(relyingParty('intranet'), null, 'single-label names other than localhost refused');
});
