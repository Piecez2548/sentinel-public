import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hostAllowed, hostName } from './host-allow.js';

test('host allowlist: this PC and the tailnet are answered', () => {
  for (const h of ['127.0.0.1:3001', 'localhost:3001', 'localhost:5173', '[::1]:3001', '100.64.0.20:8443', 'my-pc.tailnet-example.ts.net:8443', 'MY-PC.tailnet-example.ts.net']) {
    assert.ok(hostAllowed(h), h);
  }
});

test('host allowlist: rebinding names and junk are refused', () => {
  for (const h of [undefined, '', 'evil.example.com', 'evil.example.com:3001', '127.0.0.1.nip.io:3001', 'ts.net', 'a.b.c.ts.net.evil.com', 'localhost:3001 evil', 'x'.repeat(300)]) {
    assert.ok(!hostAllowed(h), String(h));
  }
});

test('host allowlist: ALLOWED_HOSTS adds names', () => {
  process.env.ALLOWED_HOSTS = 'sentinel.lan, Other.Home';
  try {
    assert.ok(hostAllowed('sentinel.lan:3001'));
    assert.ok(hostAllowed('other.home'));
    assert.ok(!hostAllowed('third.home'));
  } finally {
    delete process.env.ALLOWED_HOSTS;
  }
  assert.equal(hostName('Example.COM.:80'), 'example.com');
});
