import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diffNet, importantDomain, judgeNet, netItems, netMessage, type NetItem, type NetSnap } from './net-watch.js';

/** Example snapshot (trimmed). */
const LIVE: NetSnap = {
  hosts: ['100.64.0.10 my-pc.tailnet-example.ts.net. my-pc', '100.64.0.20 phone.tailnet-example.ts.net. phone', '127.0.0.1 localhost'],
  hostsOk: true,
  dns: [{ iface: '{8087}', name: '', servers: ['8.8.8.8', '8.8.4.4'] }],
  dnsOk: true,
  proxies: [],
  proxyOk: true,
  winhttp: '',
  nrpt: [{ ns: '.100.100.in-addr.arpa', servers: ['100.100.100.100', 'fd7a:115c:a1e0::53'] }],
  nrptOk: true,
};
const item = (kind: NetItem['kind'], name: string, value: string): NetItem => ({ key: `${kind}|${name}|${value}`, kind, section: kind === 'hosts' ? 'hosts' : kind === 'dns' ? 'dns' : kind === 'nrpt' ? 'nrpt' : 'proxy', name, value });

test("items: Tailscale's own hosts lines, localhost and Tailscale NRPT rules are left out", () => {
  const { items, ok } = netItems(LIVE);
  assert.deepEqual(items.map((i) => i.key), ['dns|{8087}|8.8.8.8', 'dns|{8087}|8.8.4.4']);
  assert.deepEqual(ok, { hosts: true, dns: true, proxy: true, nrpt: true });
  // PowerShell's one-element "list" arrives as an object.
  assert.equal(netItems({ ...LIVE, dns: { iface: 'x', servers: '1.2.3.4' } as never }).items.length, 1);
  // A Tailscale address claiming a bank's name still counts.
  assert.equal(netItems({ hosts: ['100.100.1.1 www.kasikornbank.com'] }).items.length, 1);
});

test('judge: fake or blocked important sites are high; ad blocking low; public DNS low, unknown DNS and remote proxies high', () => {
  assert.equal(importantDomain('login.microsoftonline.com'), 'microsoftonline.com');
  assert.equal(importantDomain('notgoogle.com'), null);
  assert.equal(judgeNet(item('hosts', 'www.kasikornbank.com', '45.1.2.3')).reason, 'redirect');
  assert.equal(judgeNet(item('hosts', 'api.telegram.org', '0.0.0.0')).reason, 'block');
  assert.equal(judgeNet(item('hosts', 'definitionupdates.microsoft.com', '127.0.0.1')).severity, 'high');
  assert.equal(judgeNet(item('hosts', 'ads.example.net', '0.0.0.0')).severity, 'low');
  assert.equal(judgeNet(item('hosts', 'myapp.test', '192.168.1.5')).severity, 'medium');
  assert.equal(judgeNet(item('dns', 'Wi-Fi', '1.1.1.1')).severity, 'low');
  assert.equal(judgeNet(item('dns', 'Wi-Fi', '192.168.1.1')).severity, 'medium');
  assert.equal(judgeNet(item('dns', 'Wi-Fi', '45.8.8.1')).severity, 'high');
  assert.equal(judgeNet(item('proxy', 'user', '127.0.0.1:8888')).severity, 'medium');
  assert.equal(judgeNet(item('proxy', 'user', 'http=5.6.7.8:3128;https=5.6.7.8:3128')).detail, 'web traffic goes through 5.6.7.8:3128');
  assert.equal(judgeNet(item('pac', 'user', 'http://evil.example/proxy.pac')).severity, 'high');
  assert.equal(judgeNet(item('nrpt', '.bank.com', '6.6.6.6')).severity, 'high');
});

test('diff: first run silent; new items reported, removed ones closed; unreadable sections change nothing', () => {
  const first = diffNet(LIVE, null);
  assert.deepEqual(first.changes, []);
  const bad: NetSnap = { ...LIVE, hosts: [...LIVE.hosts!, '203.0.113.9 accounts.google.com'], dns: [{ iface: '{8087}', servers: ['8.8.8.8'] }], proxies: [{ who: 'S-1-5-21-1-1001', server: '5.6.7.8:3128' }] };
  const second = diffNet(bad, first.next);
  assert.deepEqual(second.changes.map((c) => (c.kind === 'added' ? `+${c.item.kind}:${c.verdict.severity}` : `-${c.key}`)), ['+hosts:high', '+proxy:high', '-dns|{8087}|8.8.4.4']);
  // hosts file unreadable next time: its items are kept, nothing "removed".
  const third = diffNet({ ...bad, hosts: null, hostsOk: false }, second.next);
  assert.deepEqual(third.changes, []);
  assert.ok(third.next.items.includes('hosts|accounts.google.com|203.0.113.9'));
  const fourth = diffNet(LIVE, third.next);
  assert.deepEqual(fourth.changes.map((c) => c.kind).sort(), ['added', 'removed', 'removed']);
});

test('messages tell exactly where to undo it', () => {
  const it = item('hosts', 'www.scb.co.th', '45.1.2.3');
  const m = netMessage(it, judgeNet(it), 'my-pc');
  assert.match(m.headlineTh, /ไฟล์ hosts ส่ง www\.scb\.co\.th ไปที่อื่น/);
  assert.match(m.th, /drivers\\etc\\hosts/);
  const w = item('winhttp', 'Windows services (WinHTTP)', '5.6.7.8:80');
  assert.match(netMessage(w, judgeNet(w), 'pc').en, /netsh winhttp reset proxy/);
});
