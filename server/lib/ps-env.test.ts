import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cleanPsModulePath } from './ps-env.js';

test('PSModulePath: PowerShell 7 folders are dropped, Windows PowerShell and user folders kept', () => {
  const v = [
    'C:\\Users\\me\\Documents\\PowerShell\\Modules',
    'C:\\Program Files\\PowerShell\\Modules',
    'c:\\program files\\powershell\\7\\Modules',
    'C:\\Users\\me\\Documents\\WindowsPowerShell\\Modules',
    'C:\\Program Files\\WindowsPowerShell\\Modules',
    'C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules',
    'D:\\MyModules',
  ].join(';');
  assert.equal(cleanPsModulePath(v), 'C:\\Users\\me\\Documents\\WindowsPowerShell\\Modules;C:\\Program Files\\WindowsPowerShell\\Modules;C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules;D:\\MyModules');
  assert.equal(cleanPsModulePath(undefined), undefined);
  assert.equal(cleanPsModulePath('C:\\Program Files\\PowerShell\\7\\Modules'), '');
});
