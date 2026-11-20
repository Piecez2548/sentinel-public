import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diffExtensions, extensionMessage, judgeExt, parseProfile, riskyPowers, type Ext, type ExtProfile } from './browser-ext.js';

const ext = (o: Partial<Ext>): Ext => ({ browser: 'Brave', profile: 'Default', id: 'a'.repeat(32), name: 'Tool', location: 1, fromStore: true, apis: ['storage'], hosts: [], ...o });

test('preferences: built-in and leftover entries are skipped; names come from the manifest file when needed', () => {
  const secure = {
    extensions: {
      settings: {
        pdf: { location: 5, path: 'C:\\Program Files\\x', manifest: { name: 'PDF Viewer' } },
        gone: { disable_reasons: [8192] },
        claude: { location: 1, from_webstore: true, path: 'claude\\1.0_0', manifest: { name: 'Claude', version: '1.0' }, granted_permissions: { api: ['debugger', 'tabs'], explicit_host: ['<all_urls>'] }, first_install_time: '13437877381772767' },
        evil: { location: 4, path: 'D:\\x\\ext' },
      },
    },
  };
  const exts = parseProfile('Brave', 'Default', [secure, null, { extensions: 'junk' }], (p) => (p === 'D:\\x\\ext' ? { name: 'Helper', permissions: ['cookies', 'https://*/*'] } : null));
  assert.deepEqual(exts.map((e) => e.name), ['Claude', 'Helper']);
  const claude = exts[0];
  assert.equal(claude.fromStore, true);
  assert.deepEqual(riskyPowers(claude), ['all sites', 'debugger']);
  assert.ok(claude.installedAt! > Date.UTC(2026, 0, 1) && claude.installedAt! < Date.UTC(2027, 0, 1));
  assert.deepEqual(riskyPowers(exts[1]), ['all sites', 'cookies']);
});

test('judge: sideloaded and policy-forced are high, broad store extensions medium, plain ones low', () => {
  assert.equal(judgeExt(ext({ location: 4, fromStore: false })).reason, 'sideloaded');
  assert.equal(judgeExt(ext({ location: 3, fromStore: false })).severity, 'high');
  assert.equal(judgeExt(ext({ location: 1, fromStore: false })).severity, 'high'); // dragged-in .crx
  assert.equal(judgeExt(ext({ location: 9, fromStore: true })).reason, 'policy');
  assert.deepEqual(judgeExt(ext({ hosts: ['*://*/*'], apis: ['cookies'] })), { severity: 'medium', reason: 'powerful', detail: 'from the Web Store; can use: all sites, cookies', powers: ['all sites', 'cookies'] });
  assert.equal(judgeExt(ext({ hosts: ['https://docs.google.com/*'] })).severity, 'low');
  assert.equal(judgeExt(ext({ location: 6, fromStore: true })).severity, 'low'); // default apps (Google Docs Offline)
});

test('diff: first run and new profiles are silent; added, gained and removed are reported; unreadable profiles change nothing', () => {
  const p = (exts: Ext[], o: Partial<ExtProfile> = {}): ExtProfile => ({ browser: 'Brave', profile: 'Default', ok: true, exts, ...o });
  const a = ext({ id: 'a', name: 'A' });
  const first = diffExtensions([p([a])], null);
  assert.deepEqual(first.changes, []);

  const b = ext({ id: 'b', name: 'B', location: 4, fromStore: false });
  const a2 = ext({ id: 'a', name: 'A', hosts: ['<all_urls>'] });
  const edge = p([ext({ id: 'c', name: 'C', browser: 'Edge' })], { browser: 'Edge' });
  const second = diffExtensions([p([a2, b]), edge], first.next);
  assert.deepEqual(second.changes.map((c) => [c.kind, c.kind === 'removed' ? c.name : c.ext.name, c.kind === 'removed' ? '' : c.verdict.severity]), [
    ['gained', 'A', 'medium'],
    ['added', 'B', 'high'],
  ]); // Edge profile is new: recorded silently
  const gained = second.changes[0];
  assert.ok(gained.kind === 'gained' && gained.verdict.gained?.join() === 'all sites');

  // Brave unreadable this time: nothing removed, its entries kept.
  const third = diffExtensions([p([], { ok: false }), edge], second.next);
  assert.deepEqual(third.changes, []);
  assert.ok(third.next.exts['Brave|Default|b']);

  // B removed; then the whole Edge browser is gone.
  const fourth = diffExtensions([p([a2])], third.next);
  assert.deepEqual(fourth.changes.map((c) => c.kind === 'removed' && c.name).sort(), ['B', 'C']);
});

test('messages name the browser page to remove it from, in Thai and English', () => {
  const e = ext({ name: 'Free VPN', location: 4, fromStore: false });
  const m = extensionMessage(e, judgeExt(e), 'my-pc');
  assert.match(m.headlineTh, /ไม่ได้มาจาก Web Store ใน Brave: Free VPN/);
  assert.match(m.th, /brave:\/\/extensions/);
  assert.match(m.en, /Remove/);
  const g = ext({ name: 'Color Picker', browser: 'Edge', hosts: ['<all_urls>'] });
  const v = { ...judgeExt(g), reason: 'gained' as const, gained: ['all sites'], detail: 'an update added: all sites' };
  assert.match(extensionMessage(g, v, 'pc').th, /อ่านและแก้ทุกเว็บที่เปิด/);
});
