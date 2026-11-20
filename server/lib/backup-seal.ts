import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';

/**
 * Sealed backups for the off-disk copy (OneDrive): one file per backup, encrypted with a key derived from a
 * passphrase only the owner knows. A plain backup holds master.key next to the database, so anyone who can read
 * the cloud folder could read every secret; a sealed one is useless without the passphrase.
 *
 * Format (.sbk):  "SNTLBK1\n" + header JSON + "\n" + AES-256-GCM ciphertext + 16-byte tag
 * The header (kdf params, salt, iv) is authenticated as AAD. The plaintext is gzip of
 * [u16 name length][name][u32 data length][data] for each file.
 *
 * No database or filesystem access here: scripts/restore.ts uses this on a PC where SENTINEL is not running.
 */

export const SEAL_EXT = '.sbk';
const MAGIC = Buffer.from('SNTLBK1\n');
/** scrypt cost: ~0.1 s and 32 MB per derivation, done once when the passphrase is set and once per restore. */
const KDF = { N: 2 ** 15, r: 8, p: 1 } as const;
const MAXMEM = 64 * 1024 * 1024;
export const MIN_PASSPHRASE = 12;

export type SealFile = { name: string; data: Buffer };
type Header = { v: 1; kdf: { alg: 'scrypt'; N: number; r: number; p: number; salt: string }; iv: string; createdAt: string };

export function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase.normalize('NFC'), salt, 32, { ...KDF, maxmem: MAXMEM });
}

/** A fresh salt and the key for it. Store both (key encrypted); the passphrase itself is never stored. */
export function newSealKey(passphrase: string): { salt: Buffer; key: Buffer } {
  const salt = randomBytes(16);
  return { salt, key: deriveKey(passphrase, salt) };
}

/** Why a passphrase is not acceptable, or null. */
export function passphraseProblem(p: unknown): string | null {
  if (typeof p !== 'string' || p.length < MIN_PASSPHRASE) return `Use at least ${MIN_PASSPHRASE} characters`;
  if (p.length > 200) return 'Too long (200 characters at most)';
  if (/^(.)\1+$/.test(p)) return 'Too easy to guess';
  return null;
}

function pack(files: SealFile[]): Buffer {
  const parts: Buffer[] = [];
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8');
    const h = Buffer.alloc(6);
    h.writeUInt16BE(name.length, 0);
    h.writeUInt32BE(f.data.length, 2);
    parts.push(h.subarray(0, 2), name, h.subarray(2), f.data);
  }
  return gzipSync(Buffer.concat(parts));
}

function unpack(buf: Buffer): SealFile[] {
  const raw = gunzipSync(buf);
  const out: SealFile[] = [];
  let i = 0;
  while (i < raw.length) {
    const n = raw.readUInt16BE(i);
    const name = raw.subarray(i + 2, i + 2 + n).toString('utf8');
    const len = raw.readUInt32BE(i + 2 + n);
    const start = i + 6 + n;
    if (start + len > raw.length) throw new Error('Sealed backup is truncated');
    // Names are plain file names written by SENTINEL; never let one escape the restore folder.
    if (!/^[\w.-]+$/.test(name)) throw new Error(`Unexpected file name in sealed backup: ${name}`);
    out.push({ name, data: raw.subarray(start, start + len) });
    i = start + len;
  }
  return out;
}

/** Encrypt files with a key from newSealKey (salt goes in the header so the passphrase alone can open it). */
export function seal(files: SealFile[], key: Buffer, salt: Buffer, createdAt = new Date()): Buffer {
  const iv = randomBytes(12);
  const header: Header = { v: 1, kdf: { alg: 'scrypt', ...KDF, salt: salt.toString('base64') }, iv: iv.toString('base64'), createdAt: createdAt.toISOString() };
  const hb = Buffer.from(JSON.stringify(header) + '\n');
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.concat([MAGIC, hb]));
  const body = Buffer.concat([c.update(pack(files)), c.final()]);
  return Buffer.concat([MAGIC, hb, body, c.getAuthTag()]);
}

/** Header without decrypting (for listings and to check a passphrase belongs to this file). */
export function readHeader(buf: Buffer): { header: Header; bodyAt: number } {
  if (!buf.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Not a SENTINEL sealed backup');
  const nl = buf.indexOf(0x0a, MAGIC.length);
  if (nl < 0) throw new Error('Sealed backup header is damaged');
  const header = JSON.parse(buf.subarray(MAGIC.length, nl).toString('utf8')) as Header;
  if (header.v !== 1 || header.kdf?.alg !== 'scrypt') throw new Error('Unsupported sealed backup version');
  return { header, bodyAt: nl + 1 };
}

/** Decrypt with the passphrase. Throws "Wrong passphrase…" when it does not match (GCM tag check). */
export function unseal(buf: Buffer, passphrase: string): { files: SealFile[]; createdAt: string } {
  const { header, bodyAt } = readHeader(buf);
  const { N, r, p, salt } = header.kdf;
  if (N > 2 ** 20 || r > 16 || p > 4) throw new Error('Sealed backup asks for unreasonable key-derivation cost');
  const key = scryptSync(passphrase.normalize('NFC'), Buffer.from(salt, 'base64'), 32, { N, r, p, maxmem: 256 * 1024 * 1024 });
  return open(buf, key, header, bodyAt);
}

/**
 * Decrypt with the key SENTINEL keeps (derived from the passphrase when it was set), for the monthly restore test.
 * The file's salt must be the key's salt, i.e. it was sealed with the current passphrase.
 */
export function unsealWithKey(buf: Buffer, key: Buffer, salt: Buffer): { files: SealFile[]; createdAt: string } {
  const { header, bodyAt } = readHeader(buf);
  if (!Buffer.from(header.kdf.salt, 'base64').equals(salt)) throw new Error('Sealed with a different passphrase than the current one');
  return open(buf, key, header, bodyAt);
}

function open(buf: Buffer, key: Buffer, header: Header, bodyAt: number) {
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(header.iv, 'base64'));
  d.setAAD(buf.subarray(0, bodyAt));
  d.setAuthTag(buf.subarray(buf.length - 16));
  let plain: Buffer;
  try {
    plain = Buffer.concat([d.update(buf.subarray(bodyAt, buf.length - 16)), d.final()]);
  } catch {
    throw new Error('Wrong passphrase, or the file is damaged');
  }
  return { files: unpack(plain), createdAt: header.createdAt };
}
