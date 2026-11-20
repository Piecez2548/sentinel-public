import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DATA_DIR } from '../db.js';

/** Secrets (e.g. Telegram token) are encrypted with a key kept OUTSIDE the database file. */
export const MASTER_KEY_PATH = resolve(DATA_DIR, 'master.key');

let key: Buffer | null = null;
function masterKey(): Buffer {
  if (key) return key;
  if (!existsSync(MASTER_KEY_PATH)) {
    writeFileSync(MASTER_KEY_PATH, randomBytes(32).toString('base64'), { mode: 0o600 });
  }
  key = Buffer.from(readFileSync(MASTER_KEY_PATH, 'utf8').trim(), 'base64');
  if (key.length !== 32) throw new Error('data/master.key is corrupt (expected 32 bytes)');
  return key;
}

export function encrypt(plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', masterKey(), iv);
  const data = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), data.toString('base64')].join('.');
}

export function decrypt(blob: string): string {
  const [v, iv, tag, data] = blob.split('.');
  if (v !== 'v1' || !iv || !tag || !data) throw new Error('Unsupported ciphertext');
  const d = createDecipheriv('aes-256-gcm', masterKey(), Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]).toString('utf8');
}

export const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}
