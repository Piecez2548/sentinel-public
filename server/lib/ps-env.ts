/**
 * SENTINEL runs Windows PowerShell 5.1 (powershell.exe). When it is started from PowerShell 7 (a pwsh
 * terminal, or a GitHub Actions step), PSModulePath lists PowerShell 7's module folders first, and 5.1 then
 * fails to load its own modules ("Get-AuthenticodeSignature … module could not be loaded"). Dropping the
 * PowerShell 7 folders before any child process starts fixes that; Windows PowerShell and user folders stay.
 * Importing this module applies it once.
 */
export function cleanPsModulePath(value: string | undefined): string | undefined {
  if (!value) return value;
  // "\PowerShell\" (7: Program Files\PowerShell\7\Modules, Documents\PowerShell\Modules), never "\WindowsPowerShell\".
  const kept = value.split(';').filter((p) => p && !/\\PowerShell\\/i.test(`${p}\\`));
  return kept.join(';');
}

const cleaned = cleanPsModulePath(process.env.PSModulePath);
if (cleaned !== undefined) {
  if (cleaned) process.env.PSModulePath = cleaned;
  else delete process.env.PSModulePath;
}
