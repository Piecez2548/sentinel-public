import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Request } from 'express';
import { clientIp, isLoopback } from './http.js';

const req = (remote: string, headers: Record<string, string> = {}) => ({ socket: { remoteAddress: remote }, headers }) as unknown as Request;

test('the phone behind tailscale serve shows as its Tailscale address', () => {
  assert.equal(clientIp(req('127.0.0.1', { 'x-forwarded-for': '100.64.0.20' })), '100.64.0.20');
  assert.equal(clientIp(req('::ffff:127.0.0.1')), '127.0.0.1');
});

test('X-Forwarded-For is only trusted from the local proxy', () => {
  assert.equal(clientIp(req('192.168.1.50', { 'x-forwarded-for': '127.0.0.1' })), '192.168.1.50');
  assert.equal(clientIp(req('127.0.0.1', { 'x-forwarded-for': 'not an ip; drop table' })), '127.0.0.1');
});

test('"this PC" means loopback without a proxy in between', () => {
  assert.equal(isLoopback(req('127.0.0.1')), true);
  assert.equal(isLoopback(req('::1')), true);
  assert.equal(isLoopback(req('127.0.0.1', { 'x-forwarded-for': '100.64.0.20' })), false, 'relayed by tailscale serve');
  assert.equal(isLoopback(req('127.0.0.1', { 'tailscale-user-login': 'someone@example.com' })), false);
  assert.equal(isLoopback(req('100.64.0.20')), false);
});
