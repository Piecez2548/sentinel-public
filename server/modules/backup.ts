import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { backup as sqliteBackup, DatabaseSync } from 'node:sqlite';
import { Router } from 'express';
import { DATA_DIR, db, get, getSetting, setSetting } from '../db.js';
import { audit, verifyAuditChain } from '../lib/audit.js';
import { timingSafeEqual } from 'node:crypto';
import { deriveKey, newSealKey, passphraseProblem, seal, SEAL_EXT, unseal, unsealWithKey } from '../lib/backup-seal.js';
import { drillDue, drillProblems, type DrillResult } from '../lib/restore-drill.js';
import { L } from '../lib/i18n.js';
import { escHtml } from '../lib/util.js';
import { runningGame } from './processes.js';
import { decrypt, encrypt, MASTER_KEY_PATH } from '../lib/crypto.js';
import { registerComponent, reportError, reportOk } from '../lib/health.js';
import { body, clientIp, HttpError } from '../lib/http.js';
import { stepUp } from './auth.js';
import { enqueue, securityNotice } from './notify.js';

/** Backups (NFR-03): consistent SQLite online backup + master key + manifest. Keeps the newest 7. */

export const BACKUP_DIR = resolve(DATA_DIR, 'backups');
const KEEP = 7;
registerComponent('backup', 'Backups', 10 * 60_000);
registerComponent('backup_drill', 'Monthly restore test');

/**
 * Second copy somewhere that survives this disk (e.g. a OneDrive / Google Drive folder that syncs to the cloud).
 * Holds the same newest-7 set. Note: each backup contains master.key, so this folder must be private.
 */
export const BACKUP_COPY_DIR = process.env.BACKUP_COPY_DIR?.trim() ? resolve(process.env.BACKUP_COPY_DIR.trim()) : null;
if (BACKUP_COPY_DIR) registerComponent('backup_copy', 'Off-disk backup copy', 10 * 60_000);

const backupNames = (dir: string) =>
  existsSync(dir) ? readdirSync(dir, { withFileTypes: true }).filter((d) => d.isDirectory() && /^sentinel-\d{8}-\d{6}$/.test(d.name)).map((d) => d.name).sort().reverse() : [];

/** Sealed copies (one encrypted .sbk file per backup), newest first, without the extension. */
const sealedNames = (dir: string) =>
  existsSync(dir)
    ? readdirSync(dir, { withFileTypes: true })
        .filter((d) => d.isFile() && /^sentinel-\d{8}-\d{6}\.sbk$/.test(d.name))
        .map((d) => d.name.slice(0, -SEAL_EXT.length))
        .sort()
        .reverse()
    : [];

const SEAL_SETTING = 'backup_seal';
type SealSetting = { salt: string; key: string; setAt: number };

/** The off-disk copy key (derived from the owner's passphrase), kept encrypted with master.key. Null = copies are plain. */
function sealKey(): { salt: Buffer; key: Buffer; setAt: number } | null {
  const raw = getSetting(SEAL_SETTING);
  if (!raw) return null;
  try {
    const s = JSON.parse(decrypt(raw)) as SealSetting;
    return { salt: Buffer.from(s.salt, 'base64'), key: Buffer.from(s.key, 'base64'), setAt: s.setAt };
  } catch {
    return null;
  }
}

/** Seal the newest local backups into BACKUP_COPY_DIR and remove every plain copy there (they hold master.key). */
function syncSealed(dir: string, k: { salt: Buffer; key: Buffer }): string[] {
  const copied: string[] = [];
  const there = new Set(sealedNames(dir));
  for (const name of backupNames(BACKUP_DIR).slice(0, KEEP)) {
    if (there.has(name)) continue;
    const src = join(BACKUP_DIR, name);
    const files = ['sentinel.db', 'master.key', 'manifest.json'].filter((f) => existsSync(join(src, f))).map((f) => ({ name: f, data: readFileSync(join(src, f)) }));
    const tmp = join(dir, `.partial-${name}${SEAL_EXT}`);
    writeFileSync(tmp, seal(files, k.key, k.salt));
    renameSync(tmp, join(dir, name + SEAL_EXT)); // appears only once complete
    copied.push(name);
  }
  for (const old of sealedNames(dir).slice(KEEP)) rmSync(join(dir, old + SEAL_EXT), { force: true });
  for (const plain of backupNames(dir)) rmSync(join(dir, plain), { recursive: true, force: true });
  return copied;
}

/** Make sure the newest local backups are in BACKUP_COPY_DIR; retries on every run until it works. */
export function syncBackupCopy(): { copied: string[] } {
  if (!BACKUP_COPY_DIR) return { copied: [] };
  const copied: string[] = [];
  try {
    mkdirSync(BACKUP_COPY_DIR, { recursive: true });
    const k = sealKey();
    if (k) {
      const done = syncSealed(BACKUP_COPY_DIR, k);
      const newest = sealedNames(BACKUP_COPY_DIR)[0];
      reportOk('backup_copy', newest ? `Newest sealed copy ${newest}` : 'No backups to copy yet', { dir: BACKUP_COPY_DIR, sealed: true });
      return { copied: done };
    }
    const there = new Set(backupNames(BACKUP_COPY_DIR));
    for (const name of backupNames(BACKUP_DIR).slice(0, KEEP)) {
      if (there.has(name)) continue;
      const tmp = join(BACKUP_COPY_DIR, `.partial-${name}`);
      rmSync(tmp, { recursive: true, force: true });
      cpSync(join(BACKUP_DIR, name), tmp, { recursive: true });
      renameSync(tmp, join(BACKUP_COPY_DIR, name)); // appears only once complete
      copied.push(name);
    }
    for (const old of backupNames(BACKUP_COPY_DIR).slice(KEEP)) rmSync(join(BACKUP_COPY_DIR, old), { recursive: true, force: true });
    const newest = backupNames(BACKUP_COPY_DIR)[0];
    reportOk('backup_copy', newest ? `Newest copy ${newest}` : 'No backups to copy yet', { dir: BACKUP_COPY_DIR });
  } catch (e) {
    reportError('backup_copy', `Copy to ${BACKUP_COPY_DIR} failed: ${e instanceof Error ? e.message.split('\n')[0] : e}`, { dir: BACKUP_COPY_DIR });
  }
  return { copied };
}

function stamp(d = new Date()) {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

const COUNT_TABLES = ['assets', 'alert_rules', 'alert_events', 'security_findings', 'incidents', 'audit_logs', 'log_events', 'check_results', 'host_metrics'];

export async function backupNow(reason: 'manual' | 'scheduled'): Promise<{ name: string; bytes: number; copied: boolean }> {
  mkdirSync(BACKUP_DIR, { recursive: true });
  const name = `sentinel-${stamp()}`;
  const dir = join(BACKUP_DIR, name);
  mkdirSync(dir);
  try {
    await sqliteBackup(db, join(dir, 'sentinel.db'));
    if (existsSync(MASTER_KEY_PATH)) copyFileSync(MASTER_KEY_PATH, join(dir, 'master.key'));
    const counts = Object.fromEntries(COUNT_TABLES.map((t) => [t, get<{ n: number }>(`SELECT COUNT(*) AS n FROM ${t}`)?.n ?? 0]));
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ createdAt: new Date().toISOString(), reason, counts }, null, 2));
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    reportError('backup', `Backup failed: ${e instanceof Error ? e.message : e}`);
    throw e;
  }
  // Retention
  const all = listBackups();
  for (const b of all.slice(KEEP)) rmSync(join(BACKUP_DIR, b.name), { recursive: true, force: true });
  const bytes = statSync(join(dir, 'sentinel.db')).size;
  reportOk('backup', `Last backup ${name}`);
  const { copied } = syncBackupCopy();
  return { name, bytes, copied: copied.includes(name) };
}

export function listBackups() {
  if (!existsSync(BACKUP_DIR)) return [];
  return readdirSync(BACKUP_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name.startsWith('sentinel-'))
    .map((d) => {
      const dir = join(BACKUP_DIR, d.name);
      let manifest: { createdAt?: string; reason?: string; counts?: Record<string, number> } = {};
      try {
        manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
      } catch {
        /* incomplete */
      }
      const dbFile = join(dir, 'sentinel.db');
      return {
        name: d.name,
        path: dir,
        createdAt: manifest.createdAt ? Date.parse(manifest.createdAt) : statSync(dir).mtimeMs,
        reason: manifest.reason ?? 'unknown',
        bytes: existsSync(dbFile) ? statSync(dbFile).size : 0,
        hasKey: existsSync(join(dir, 'master.key')),
        counts: manifest.counts ?? {},
      };
    })
    .sort((a, b) => b.createdAt - a.createdAt);
}

/** Open a backup read-only and check it (integrity + audit chain + counts). Used by restore tests (AT-12). */
export function verifyBackup(dir: string) {
  const file = join(dir, 'sentinel.db');
  if (!existsSync(file)) return { ok: false, reason: 'sentinel.db missing' };
  const b = new DatabaseSync(file, { readOnly: true });
  try {
    const integrity = (b.prepare('PRAGMA integrity_check').get() as { integrity_check: string }).integrity_check;
    const counts = Object.fromEntries(COUNT_TABLES.map((t) => [t, (b.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get() as { n: number }).n]));
    return { ok: integrity === 'ok', integrity, counts, hasKey: existsSync(join(dir, 'master.key')) };
  } finally {
    b.close();
  }
}

export async function maybeScheduledBackup() {
  const hour = Number(getSetting('backup_hour') ?? 3);
  const now = new Date();
  const today = now.toDateString();
  const skip = getSetting('backup_last_day') === today || (now.getHours() < hour && !!getSetting('backup_last_day')); // first ever backup runs immediately
  if (skip) {
    const last = listBackups()[0];
    reportOk('backup', last ? `Last backup ${last.name}` : `Next backup at ${String(hour).padStart(2, '0')}:00`);
    syncBackupCopy(); // catches up after a failed copy (e.g. cloud folder was unavailable)
    return;
  }
  setSetting('backup_last_day', today);
  const r = await backupNow('scheduled');
  audit('backup.created', { detail: { name: r.name, reason: 'scheduled', copied: r.copied } });
}

/* ---------- monthly restore test ---------- */

const DRILL_SETTING = 'backup_drill_last';
export const lastDrill = () => {
  try {
    return JSON.parse(getSetting(DRILL_SETTING) ?? 'null') as DrillResult | null;
  } catch {
    return null;
  }
};

/**
 * Restore test: open the newest encrypted copy in the cloud folder exactly as a restore would (decrypt, unpack,
 * open the database), check it, then delete what was unpacked. Only the cloud copy is tested: the local
 * backups die with this disk. Unpacked files go under data/ (administrators only) and are removed right away.
 */
export async function runRestoreDrill(reason: 'scheduled' | 'manual'): Promise<DrillResult> {
  const t0 = Date.now();
  const base = { at: t0, reason } as const;
  const k = sealKey();
  let result: DrillResult;
  if (!BACKUP_COPY_DIR) result = { ...base, ok: false, skipped: true, problems: ['No off-disk copy configured (BACKUP_COPY_DIR)'] };
  else if (!k) result = { ...base, ok: false, skipped: true, problems: ['The cloud copy is not encrypted yet, so there is no sealed copy to test'] };
  else {
    const name = sealedNames(BACKUP_COPY_DIR)[0];
    const tmp = join(DATA_DIR, `restore-test-${t0}`);
    try {
      if (!name) throw new Error('No sealed copy found in the cloud folder');
      const buf = readFileSync(join(BACKUP_COPY_DIR, name + SEAL_EXT));
      const { files, createdAt } = unsealWithKey(buf, k.key, k.salt);
      mkdirSync(tmp, { recursive: true });
      for (const f of files) writeFileSync(join(tmp, f.name), f.data);
      const manifest = files.some((f) => f.name === 'manifest.json') ? (JSON.parse(readFileSync(join(tmp, 'manifest.json'), 'utf8')) as { counts?: Record<string, number> }) : null;
      const v = verifyBackup(tmp);
      const keyFile = files.find((f) => f.name === 'master.key')?.data;
      const masterMatches = !!keyFile && existsSync(MASTER_KEY_PATH) && keyFile.equals(readFileSync(MASTER_KEY_PATH));
      const facts = {
        name, createdAt: Date.parse(createdAt), bytes: buf.length, files: files.map((f) => f.name),
        integrity: 'integrity' in v ? (v.integrity ?? null) : null, counts: 'counts' in v ? (v.counts ?? null) : null, manifestCounts: manifest?.counts ?? null, masterMatches,
      };
      const problems = drillProblems(facts, t0);
      result = { ...base, ok: !problems.length, problems, name, createdAt: facts.createdAt, bytes: facts.bytes, counts: facts.counts ?? undefined };
    } catch (e) {
      result = { ...base, ok: false, problems: [e instanceof Error ? e.message.split('\n')[0] : String(e)], name };
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  result.ms = Date.now() - t0;
  setSetting(DRILL_SETTING, JSON.stringify(result));
  audit('backup.restore_test', { detail: { ok: result.ok, skipped: !!result.skipped, name: result.name ?? null, problems: result.problems, reason } });
  if (result.ok) reportOk('backup_drill', `Restore test passed (${result.name})`);
  else if (result.skipped) reportOk('backup_drill', result.problems[0]);
  else {
    reportError('backup_drill', `Restore test failed: ${result.problems.join('; ')}`);
    enqueue('system', 'backup_drill', L(
      `🔴 <b>Backup restore test failed</b>\nThe newest encrypted copy in the cloud folder could not be restored:\n${result.problems.map((p) => `• ${escHtml(p)}`).join('\n')}\n\n👉 SENTINEL → Settings → Backups → Back up now, then Test restore.`,
      `🔴 <b>ทดสอบกู้คืนแบ็กอัปไม่ผ่าน</b>\nกู้คืนสำเนาเข้ารหัสล่าสุดบนคลาวด์ไม่ได้:\n${result.problems.map((p) => `• ${escHtml(p)}`).join('\n')}\n\n👉 SENTINEL → ตั้งค่า → สำรองข้อมูล → สำรองตอนนี้ แล้วกด ทดสอบกู้คืน`,
    ));
  }
  return result;
}

/** Hourly: runs the test once a month (and soon after it is first deployed), never while a game is running. */
export async function maybeRestoreDrill(now = Date.now()) {
  if (!drillDue(lastDrill(), now) || runningGame()) return;
  await runRestoreDrill('scheduled');
}

export const backupRouter = Router();

backupRouter.get('/', (_req, res) => {
  const k = sealKey();
  const copies = BACKUP_COPY_DIR ? new Set(k ? sealedNames(BACKUP_COPY_DIR) : backupNames(BACKUP_COPY_DIR)) : null;
  res.json({
    dir: BACKUP_DIR,
    copyDir: BACKUP_COPY_DIR,
    sealed: !!k,
    sealSetAt: k?.setAt ?? null,
    drill: lastDrill(),
    passCheckedAt: Number(getSetting(PASS_CHECKED)) || null,
    backups: listBackups().map(({ path: _p, ...b }) => ({ ...b, copied: copies ? copies.has(b.name) : null })),
  });
});

backupRouter.post('/', async (req, res) => {
  const r = await backupNow('manual');
  audit('backup.created', { ip: clientIp(req), detail: { name: r.name, reason: 'manual', copied: r.copied } });
  res.json(r);
});

/**
 * Turn on (or change) encryption of the off-disk copy. The passphrase is never stored: only the key derived from it,
 * encrypted with master.key, so the daily copy can run unattended. Changing it re-seals all copies with the new one.
 */
backupRouter.post('/seal', stepUp, (req, res) => {
  const b = body(req);
  const problem = passphraseProblem(b.passphrase);
  if (problem) throw new HttpError(400, problem);
  if (!BACKUP_COPY_DIR) throw new HttpError(409, 'No off-disk copy configured — set BACKUP_COPY_DIR in .env first');
  const had = !!sealKey();
  const { salt, key } = newSealKey(b.passphrase as string);
  setSetting(SEAL_SETTING, encrypt(JSON.stringify({ salt: salt.toString('base64'), key: key.toString('base64'), setAt: Date.now() } satisfies SealSetting)));
  for (const n of sealedNames(BACKUP_COPY_DIR)) rmSync(join(BACKUP_COPY_DIR, n + SEAL_EXT), { force: true }); // old passphrase
  const { copied } = syncBackupCopy();
  audit(had ? 'backup.seal_changed' : 'backup.seal_enabled', { ip: clientIp(req), detail: { copies: copied.length } });
  securityNotice(had ? 'Backup passphrase changed' : 'Off-disk backups are now encrypted', had ? 'เปลี่ยนรหัสผ่านสำรองข้อมูลแล้ว' : 'สำเนาสำรองบน cloud ถูกเข้ารหัสแล้ว', req);
  res.json({ ok: true, copied: copied.length });
});

/* ---------- "do I still remember the passphrase?" ---------- */

export const PASS_CHECKED = 'backup_pass_checked_at';
const PASS_WINDOW_MS = 15 * 60_000;
const PASS_MAX_TRIES = 5;
const passTries: number[] = [];

/**
 * The owner types the backup passphrase; SENTINEL says whether it is the right one and opens the newest cloud
 * copy with it, exactly as a restore on another PC would. The passphrase is never stored or logged.
 * Limited to 5 tries per 15 minutes; 3 wrong ones in a row are reported on Telegram.
 */
backupRouter.post('/check-passphrase', (req, res) => {
  const now = Date.now();
  while (passTries.length && now - passTries[0] > PASS_WINDOW_MS) passTries.shift();
  if (passTries.length >= PASS_MAX_TRIES) throw new HttpError(429, 'Too many tries — wait 15 minutes');
  const k = sealKey();
  if (!k) throw new HttpError(409, 'The cloud copy is not encrypted yet');
  const p = body(req).passphrase;
  if (typeof p !== 'string' || !p || p.length > 200) throw new HttpError(400, 'Type the passphrase');
  passTries.push(now);
  const ok = timingSafeEqual(deriveKey(p, k.salt), k.key);
  let opened: string | null = null;
  let fileProblem: string | null = null;
  if (ok) {
    passTries.length = 0;
    const name = BACKUP_COPY_DIR ? sealedNames(BACKUP_COPY_DIR)[0] : undefined;
    if (name) {
      try {
        unseal(readFileSync(join(BACKUP_COPY_DIR!, name + SEAL_EXT)), p);
        opened = name;
      } catch (e) {
        fileProblem = e instanceof Error ? e.message.split('\n')[0] : String(e);
      }
    }
    setSetting(PASS_CHECKED, String(now));
  } else if (passTries.length === 3) {
    securityNotice('3 wrong backup passphrases typed in SENTINEL', 'มีการพิมพ์รหัสผ่านแบ็กอัปผิด 3 ครั้งใน SENTINEL', req);
  }
  audit('backup.passphrase_checked', { ip: clientIp(req), detail: { ok, opened, fileProblem } });
  res.json({ ok, opened, fileProblem, triesLeft: ok ? PASS_MAX_TRIES : PASS_MAX_TRIES - passTries.length });
});

let drilling: Promise<DrillResult> | null = null;
backupRouter.post('/restore-test', async (req, res) => {
  drilling ??= runRestoreDrill('manual').finally(() => (drilling = null));
  const r = await drilling;
  audit('backup.restore_test_requested', { ip: clientIp(req) });
  res.json(r);
});

backupRouter.post('/:name/verify', (req, res) => {
  const b = listBackups().find((x) => x.name === req.params.name);
  if (!b) {
    res.status(404).json({ error: 'Backup not found' });
    return;
  }
  res.json(verifyBackup(b.path));
});

export { verifyAuditChain };
