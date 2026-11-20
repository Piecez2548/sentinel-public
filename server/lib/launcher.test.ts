import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

// The modules open the database on import: point it and the shortcut folder at throwaway folders first.
const dir = mkdtempSync(join(tmpdir(), 'sentinel-launch-'));
const menu = join(dir, 'menu');
process.env.DATA_DIR = join(dir, 'data');
process.env.SENTINEL_TEST_LAUNCH_DIR = menu;
mkdirSync(join(menu, 'Steam'), { recursive: true });
mkdirSync(join(menu, 'Startup'), { recursive: true });
for (const f of ['Discord.lnk', 'Steam/Steam.lnk', 'Steam/Uninstall Steam.lnk', 'Command Prompt.lnk', 'Registry Editor.lnk', 'Startup/Sneaky.lnk', 'notes.txt', 'FC Online Thailand.lnk'])
  writeFileSync(join(menu, f), '');
const { db, migrate } = await import('../db.js');
migrate();
const { getFavourites, listApps } = await import('../modules/launcher.js');
after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

test('only real app shortcuts are listed: no uninstallers, system tools, Startup items or other files', () => {
  assert.deepEqual(
    listApps().map((a) => a.name),
    ['Discord', 'FC Online Thailand', 'Steam'],
  );
  assert.equal(listApps().find((a) => a.name === 'Steam')?.folder, 'Steam');
});

test('ids are stable and the first visit suggests common apps', () => {
  const a = listApps(Date.now() + 120_000);
  assert.deepEqual(a.map((x) => x.id), listApps(Date.now() + 240_000).map((x) => x.id));
  assert.deepEqual(getFavourites(a).map((id) => a.find((x) => x.id === id)!.name), ['Discord', 'FC Online Thailand', 'Steam']);
});
