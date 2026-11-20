/**
 * Alerting acceptance tests that need time to pass (~3 min):
 *   AT-02  sustained CPU above threshold → alert
 *   AT-11  a collector that fails → "pipeline" alert (failure is never silent)
 *   AT-15  battery low while unplugged → alert
 *
 * The server runs on a throwaway data dir. Two test-only env switches are used:
 *   SENTINEL_TEST_BATTERY="15,0"   pretend the battery is at 15 % and not charging
 *   SENTINEL_TEST_FAIL=eventlog    make the Event Log collector job throw
 */
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';

const PORT = 3990 + Math.floor(Math.random() * 9);
const BASE = `http://127.0.0.1:${PORT}`;
const dataDir = mkdtempSync(join(tmpdir(), 'sentinel-alerting-'));
let server: ChildProcess;
let session = '';

async function call(method: string, path: string, body?: unknown) {
  const r = await fetch(`${BASE}/api${path}`, {
    method,
    headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(session ? { cookie: session } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const c = r.headers.get('set-cookie');
  if (c) session = c.split(';')[0];
  return { status: r.status, body: (await r.json().catch(() => null)) as any };
}

async function waitFor<T>(fn: () => Promise<T | undefined>, timeoutMs: number): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 2000));
  }
}

const activeAlerts = async () => (await call('GET', '/alerts/events?status=active')).body.events as { title: string; ruleType: string; detail: string }[];

before(async () => {
  server = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
    env: { ...process.env, DATA_DIR: dataDir, PORT: String(PORT), SENTINEL_TEST_BATTERY: '15,0', SENTINEL_TEST_FAIL: 'eventlog' },
    stdio: 'ignore',
  });
  await waitFor(async () => (await fetch(`${BASE}/api/auth/state`).then((r) => r.ok).catch(() => false)) || undefined, 30_000);
  assert.equal((await call('POST', '/auth/setup', { password: 'alerting-test-pass-1' })).status, 200);
  // Faster rules for the test: CPU ≥ 1 % sustained 60 s; pipeline failing ≥ 1 min.
  assert.equal((await call('POST', '/alerts/rules', { name: 'Test CPU', type: 'host_cpu', severity: 'low', forSec: 60, cooldownSec: 300, params: { threshold: 1 } })).status, 201);
  assert.equal((await call('POST', '/alerts/rules', { name: 'Test pipeline', type: 'pipeline', severity: 'high', cooldownSec: 300, params: { minutes: 1 } })).status, 201);
});

after(async () => {
  if (server && server.exitCode === null) {
    const exited = new Promise((r) => server.once('exit', r));
    server.kill();
    await exited;
  }
  rmSync(dataDir, { recursive: true, force: true });
});

test('AT-15: battery low while unplugged raises an alert', async () => {
  const a = await waitFor(async () => (await activeAlerts()).find((e) => e.ruleType === 'host_battery'), 150_000);
  assert.match(a.title, /Battery low/);
  assert.match(a.detail, /15%/);
});

test('AT-11: a failing collector raises a pipeline alert', async () => {
  const health = (await call('GET', '/health')).body.components as { name: string; ok: boolean; message: string }[];
  const ev = health.find((c) => c.name === 'eventlog')!;
  assert.equal(ev.ok, false, 'collector failure is visible in health');
  assert.match(ev.message, /Injected failure/);
  const a = await waitFor(async () => (await activeAlerts()).find((e) => e.ruleType === 'pipeline' && /Event Log/.test(e.title)), 150_000);
  assert.match(a.title, /failing/);
});

test('AT-02: CPU above threshold for the sustained window raises an alert', async () => {
  const a = await waitFor(async () => (await activeAlerts()).find((e) => e.ruleType === 'host_cpu'), 240_000);
  assert.match(a.title, /CPU high/);
});
