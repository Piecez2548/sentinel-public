import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

// The modules open the database on import: point it at a throwaway folder first.
const dir = mkdtempSync(join(tmpdir(), 'sentinel-load-'));
process.env.DATA_DIR = dir;
const { db, migrate, run } = await import('../db.js');
migrate();
const { collectorStale, failingSince, localOverload, localTrouble, othersNoResponse, shouldHold, OVERLOAD_HOLD_MS } = await import('./local-load.js');
const { alertTitleText, checkErrorTh } = await import('./i18n.js');
after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const now = Date.now();
const MIN = 60_000;
const host = Number(run("INSERT INTO assets (name, type, created_at, updated_at) VALUES ('PC', 'host', ?, ?)", now, now).lastInsertRowid);
run("INSERT INTO host_info (asset_id, collector) VALUES (?, 'local')", host);
const site = Number(run("INSERT INTO assets (name, type, target, created_at, updated_at) VALUES ('Site', 'website', 'https://x.test/', ?, ?)", now, now).lastInsertRowid);
const metric = (ts: number, cpu: number, mem: number) => run('INSERT INTO host_metrics (asset_id, ts, cpu_pct, mem_pct) VALUES (?, ?, ?, ?)', host, ts, cpu, mem);
const check = (ts: number, ok: boolean) => run('INSERT INTO check_results (asset_id, ts, ok) VALUES (?, ?, ?)', site, ts, ok ? 1 : 0);

test('overload = CPU or memory ≥ 95% in a recent sample; old samples do not count', () => {
  metric(now - 10 * MIN, 100, 99);
  assert.equal(localOverload(now), null);
  metric(now - 2 * MIN, 96, 87);
  metric(now - 1 * MIN, 88, 85);
  assert.deepEqual(localOverload(now), { cpu: 96, mem: 87 });
  metric(now - 0.5 * MIN, 50, 60);
  metric(now - 0.2 * MIN, 50, 60);
  assert.equal(localOverload(now), null);
});

test('failingSince is the first failure after the last success', () => {
  check(now - 5 * MIN, false);
  check(now - 4 * MIN, true);
  assert.equal(failingSince(site), null);
  check(now - 3 * MIN, false);
  check(now - 2 * MIN, false);
  assert.equal(failingSince(site), now - 3 * MIN);
});

test('the PC is the suspect when its own metrics are late or other sites fail too', () => {
  const later = now + 10 * MIN; // past every sample and check written above
  assert.equal(collectorStale(later), true, 'no local sample for 10 min while SENTINEL runs = PC choking');
  assert.equal(collectorStale(now), false);
  const other = Number(run("INSERT INTO assets (name, type, target, created_at, updated_at) VALUES ('Other', 'website', 'https://y.test/', ?, ?)", now, now).lastInsertRowid);
  assert.equal(othersNoResponse(site, now), 0);
  run('INSERT INTO check_results (asset_id, ts, ok, status_code) VALUES (?, ?, 0, 500)', other, now - MIN);
  assert.equal(othersNoResponse(site, now), 0, 'an HTTP error elsewhere is that site, not this PC');
  run('INSERT INTO check_results (asset_id, ts, ok) VALUES (?, ?, 0)', other, now - MIN);
  assert.equal(othersNoResponse(site, now), 1);
  assert.equal(localTrouble(site, now), 'many');
});

test('only no-response failures on a busy PC are held, and only for a while', () => {
  const base = { noResponse: true, overloaded: true, failingSince: now - MIN, now };
  assert.equal(shouldHold(base), true);
  assert.equal(shouldHold({ ...base, noResponse: false }), false, 'HTTP 500 is the site, not the PC');
  assert.equal(shouldHold({ ...base, overloaded: false }), false);
  assert.equal(shouldHold({ ...base, failingSince: now - OVERLOAD_HOLD_MS }), false, 'still down after the hold → report it');
});

test('alert lines and check errors read in Thai', () => {
  assert.equal(alertTitleText('Shop Main is DOWN'), 'เว็บ Shop Main ล่ม');
  assert.equal(alertTitleText('CPU high on my-pc'), 'CPU สูงบน my-pc');
  assert.equal(alertTitleText('Memory high on my-pc'), 'หน่วยความจำสูงบน my-pc');
  assert.equal(alertTitleText('Disk C: almost full on PC'), 'ดิสก์ C: ใกล้เต็มบน PC');
  assert.equal(alertTitleText('Something new'), 'Something new');
  assert.equal(checkErrorTh('Timeout after 10s'), 'รอ 10 วินาทีแล้วไม่ตอบ');
  assert.equal(checkErrorTh('HTTP 500'), 'เว็บตอบกลับรหัส 500');
});
