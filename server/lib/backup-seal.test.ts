import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { newSealKey, passphraseProblem, readHeader, seal, unseal, unsealWithKey } from './backup-seal.js';

const PASS = 'correct horse battery staple';
const files = [
  { name: 'sentinel.db', data: randomBytes(300_000) },
  { name: 'master.key', data: Buffer.from(randomBytes(32).toString('base64')) },
  { name: 'manifest.json', data: Buffer.from('{"reason":"scheduled"}') },
];

test('seal → unseal round trip with the passphrase only', () => {
  const { salt, key } = newSealKey(PASS);
  const buf = seal(files, key, salt, new Date('2026-11-17T03:00:00Z'));
  const out = unseal(buf, PASS);
  assert.equal(out.createdAt, '2026-11-17T03:00:00.000Z');
  assert.deepEqual(out.files.map((f) => f.name), files.map((f) => f.name));
  for (const [i, f] of out.files.entries()) assert.ok(f.data.equals(files[i].data), f.name);
});

test('the monthly restore test opens a copy with the stored key, not the passphrase', () => {
  const { salt, key } = newSealKey(PASS);
  const buf = seal(files, key, salt);
  assert.deepEqual(unsealWithKey(buf, key, salt).files.map((f) => f.name), files.map((f) => f.name));
  const other = newSealKey(PASS);
  assert.throws(() => unsealWithKey(buf, other.key, other.salt), /different passphrase/);
  const bad = Buffer.from(buf);
  bad[bad.length - 40] ^= 1;
  assert.throws(() => unsealWithKey(bad, key, salt), /damaged/);
});

test('no secret is readable in the sealed file', () => {
  const { salt, key } = newSealKey(PASS);
  const buf = seal(files, key, salt);
  assert.equal(buf.indexOf(files[1].data), -1, 'master.key must not appear');
  assert.equal(buf.indexOf(Buffer.from('scheduled')), -1);
  assert.equal(readHeader(buf).header.kdf.alg, 'scrypt');
});

test('wrong passphrase, tampered body and tampered header are refused', () => {
  const { salt, key } = newSealKey(PASS);
  const buf = seal(files, key, salt);
  assert.throws(() => unseal(buf, 'correct horse battery stapl3'), /Wrong passphrase/);
  const body = Buffer.from(buf);
  body[body.length - 40] ^= 1;
  assert.throws(() => unseal(body, PASS), /Wrong passphrase|damaged/);
  const head = Buffer.from(buf.toString('latin1').replace('"createdAt":"2', '"createdAt":"3'), 'latin1');
  assert.throws(() => unseal(head, PASS), /Wrong passphrase|damaged/);
  assert.throws(() => unseal(Buffer.from('not a backup'), PASS), /Not a SENTINEL sealed backup/);
});

test('passphrase rules', () => {
  assert.match(passphraseProblem('short')!, /12/);
  assert.match(passphraseProblem('aaaaaaaaaaaaaa')!, /easy/);
  assert.equal(passphraseProblem(PASS), null);
  assert.ok(passphraseProblem(42));
});
