import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertUrlAllowed, isBlockedAddress } from './ssrf.js';
import { checkUrl } from './checker.js';

test('blocks private, loopback, link-local and metadata addresses', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.1.1', '172.20.0.5', '169.254.169.254', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1']) {
    assert.equal(isBlockedAddress(ip), true, ip);
  }
});

test('allows public addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
    assert.equal(isBlockedAddress(ip), false, ip);
  }
});

test('rejects bad URLs', () => {
  for (const u of ['ftp://example.com', 'file:///etc/passwd', 'http://localhost:3000', 'http://127.0.0.1', 'http://[::1]/', 'http://169.254.169.254/latest/meta-data', 'http://user:pw@example.com']) {
    assert.throws(() => assertUrlAllowed(u), u);
  }
  assert.doesNotThrow(() => assertUrlAllowed('https://example.com'));
});

test('checkUrl refuses to connect to private targets', async () => {
  const r = await checkUrl('http://127.0.0.1:9/');
  assert.equal(r.ok, false);
  assert.match(r.error ?? '', /blocked/i);
});
