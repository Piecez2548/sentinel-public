/**
 * Restore a backup made by SENTINEL (Settings → Backups, or the daily job).
 *
 *   npm run restore -- data/backups/sentinel-20261112-030000
 *   npm run restore -- "C:\Users\<you>\OneDrive\SENTINEL-backups\sentinel-20261112-030000.sbk"
 *
 * A .sbk file is an encrypted off-disk copy: it asks for the backup passphrase (or reads
 * SENTINEL_BACKUP_PASSPHRASE) and unpacks into data/unsealed-<timestamp>/ first.
 *
 * Stop SENTINEL first. The current database and key are moved to
 * data/pre-restore-<timestamp>/ (nothing is deleted).
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import net from 'node:net';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SEAL_EXT, unseal } from '../server/lib/backup-seal.js';

const dataDir = resolve(process.env.DATA_DIR ?? 'data');
let src = process.argv[2] ? resolve(process.argv[2]) : '';

function fail(msg: string): never {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

/** Asks without echoing what is typed. */
async function askHidden(question: string): Promise<string> {
  let muted = false;
  const out = new Writable({ write: (chunk, _enc, cb) => (muted || process.stdout.write(chunk), cb()) });
  const rl = createInterface({ input: process.stdin, output: out, terminal: true });
  const p = new Promise<string>((res) => rl.question(question, (a) => (rl.close(), process.stdout.write('\n'), res(a))));
  muted = true;
  return p;
}

if (src.toLowerCase().endsWith(SEAL_EXT) && existsSync(src)) {
  const pass = process.env.SENTINEL_BACKUP_PASSPHRASE ?? (await askHidden('Backup passphrase: '));
  let files;
  try {
    files = unseal(readFileSync(src), pass).files;
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const out = join(dataDir, `unsealed-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  mkdirSync(out, { recursive: true });
  for (const f of files) writeFileSync(join(out, f.name), f.data);
  console.log(`✓ Decrypted ${files.length} file(s) into ${out}`);
  src = out;
}

if (!src || !existsSync(join(src, 'sentinel.db'))) fail('Usage: npm run restore -- <backup folder containing sentinel.db, or a .sbk file>');

const port = Number(process.env.PORT ?? 3001);
const inUse = await new Promise<boolean>((res) => {
  const s = net.connect(port, '127.0.0.1');
  s.once('connect', () => (s.destroy(), res(true)));
  s.once('error', () => res(false));
});
if (inUse) fail(`Something is listening on port ${port}. Stop SENTINEL before restoring.`);

// 1. Verify the backup before touching anything.
const b = new DatabaseSync(join(src, 'sentinel.db'), { readOnly: true });
const integrity = (b.prepare('PRAGMA integrity_check').get() as { integrity_check: string }).integrity_check;
const assets = (b.prepare('SELECT COUNT(*) AS n FROM assets').get() as { n: number }).n;
const audit = (b.prepare('SELECT COUNT(*) AS n FROM audit_logs').get() as { n: number }).n;
b.close();
if (integrity !== 'ok') fail(`Backup failed integrity check: ${integrity}`);
console.log(`✓ Backup verified: integrity ok, ${assets} assets, ${audit} audit entries`);
if (!existsSync(join(src, 'master.key'))) console.warn('! Backup has no master.key — stored Telegram tokens will need to be re-entered.');

// 2. Move the current files aside.
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const aside = join(dataDir, `pre-restore-${stamp}`);
mkdirSync(aside, { recursive: true });
for (const f of ['sentinel.db', 'sentinel.db-wal', 'sentinel.db-shm', 'master.key']) {
  if (existsSync(join(dataDir, f))) renameSync(join(dataDir, f), join(aside, f));
}
console.log(`✓ Previous data moved to ${aside}`);

// 3. Copy the backup in.
copyFileSync(join(src, 'sentinel.db'), join(dataDir, 'sentinel.db'));
if (existsSync(join(src, 'master.key'))) copyFileSync(join(src, 'master.key'), join(dataDir, 'master.key'));
console.log('✓ Restore complete. Start SENTINEL with: npm start');
