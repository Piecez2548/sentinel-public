import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { checkSignature, imagePathToFile, signerName } from './signature.js';

test('imagePathToFile resolves the forms seen in event 7045', () => {
  const sr = 'C:\\Windows';
  assert.equal(imagePathToFile('"C:\\Program Files\\WSL\\wslservice.exe"', sr), 'C:\\Program Files\\WSL\\wslservice.exe');
  assert.equal(imagePathToFile('"C:\\Program Files (x86)\\Google\\updater.exe" --system --windows-service', sr), 'C:\\Program Files (x86)\\Google\\updater.exe');
  assert.equal(imagePathToFile('C:\\Program Files\\LGHUB\\lghub_updater.exe --run-as-service', sr), 'C:\\Program Files\\LGHUB\\lghub_updater.exe');
  assert.equal(imagePathToFile('\\SystemRoot\\System32\\drivers\\vmswitch.sys', sr), 'C:\\Windows\\System32\\drivers\\vmswitch.sys');
  assert.equal(imagePathToFile('system32\\drivers\\x.sys', sr), 'C:\\Windows\\system32\\drivers\\x.sys');
  assert.equal(imagePathToFile('\\??\\C:\\Temp\\evil.sys', sr), 'C:\\Temp\\evil.sys');
  assert.equal(imagePathToFile('', sr), null);
  assert.equal(imagePathToFile('cmd /c whoami', sr), null);
});

test('signerName extracts the CN, including quoted names', () => {
  assert.equal(signerName('CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, C=US'), 'Microsoft Corporation');
  assert.equal(signerName('CN="OpenAI OpCo, LLC", O="OpenAI OpCo, LLC", C=US'), 'OpenAI OpCo, LLC');
});

// cmd.exe exists on every Windows edition (Windows Server, e.g. the CI runner, has no notepad.exe).
test('checkSignature on real Windows binaries', { skip: process.platform !== 'win32' }, async () => {
  const signed = await checkSignature(`"${process.env.SystemRoot}\\System32\\cmd.exe"`);
  assert.equal(signed.state, 'signed');
  const missing = await checkSignature('"C:\\definitely\\not\\here.exe"');
  assert.equal(missing.state, 'unknown');
  // An unsigned script stands in for an unsigned service binary.
  const dir = mkdtempSync(join(tmpdir(), 'sentinel-sig-'));
  const file = join(dir, 'unsigned.ps1');
  writeFileSync(file, "'hello'\n");
  try {
    assert.equal((await checkSignature(`"${file}"`)).state, 'unsigned');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
