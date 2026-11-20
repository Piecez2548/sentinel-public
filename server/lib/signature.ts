import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

/**
 * Authenticode check for the binary behind a new Windows service (event 7045).
 * Read-only: runs Get-AuthenticodeSignature, never changes anything.
 */

export type SignatureResult =
  | { state: 'signed'; signer: string; path: string }
  | { state: 'unsigned' | 'invalid'; detail: string; path: string }
  | { state: 'unknown'; detail: string; path: string | null };

/** Turn a 7045 ImagePath ("C:\x y\a.exe" --flag, \SystemRoot\..., system32\drivers\x.sys, \??\C:\...) into a file path. */
export function imagePathToFile(imagePath: string, systemRoot = process.env.SystemRoot ?? 'C:\\Windows'): string | null {
  let s = imagePath.trim();
  if (!s) return null;
  let file: string;
  if (s.startsWith('"')) {
    const end = s.indexOf('"', 1);
    if (end < 0) return null;
    file = s.slice(1, end);
  } else {
    // Unquoted: take everything up to the first known executable extension.
    const m = /^(.*?\.(?:exe|sys|dll|com|scr))(?=\s|$)/i.exec(s);
    file = m ? m[1] : s.split(/\s+/)[0];
  }
  file = file.replace(/^\\\?\?\\/, '');
  if (/^\\SystemRoot\\/i.test(file)) file = systemRoot + file.slice('\\SystemRoot'.length);
  else if (/^%SystemRoot%\\/i.test(file)) file = systemRoot + file.slice('%SystemRoot%'.length);
  else if (/^system32\\/i.test(file)) file = `${systemRoot}\\${file}`;
  return /^[a-z]:\\/i.test(file) ? file : null;
}

const cache = new Map<string, { at: number; result: SignatureResult }>();
const CACHE_MS = 60 * 60 * 1000;

export async function checkSignature(imagePath: string): Promise<SignatureResult> {
  const file = imagePathToFile(imagePath);
  if (!file) return { state: 'unknown', detail: 'could not resolve the service binary path', path: null };
  const hit = cache.get(file.toLowerCase());
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.result;

  let result: SignatureResult;
  try {
    // Path is passed through an environment variable, never interpolated into the command.
    const { stdout } = await exec(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command',
        "$ErrorActionPreference='Stop'; if (-not (Test-Path -LiteralPath $env:SENTINEL_SIG_PATH)) { '{\"missing\":true}'; exit }; $s = Get-AuthenticodeSignature -LiteralPath $env:SENTINEL_SIG_PATH; [pscustomobject]@{ status = [string]$s.Status; message = $s.StatusMessage; subject = $s.SignerCertificate.Subject } | ConvertTo-Json -Compress"],
      { env: { ...process.env, SENTINEL_SIG_PATH: file }, timeout: 20_000, windowsHide: true },
    );
    const r = JSON.parse(stdout.trim()) as { missing?: boolean; status?: string; message?: string; subject?: string | null };
    if (r.missing) result = { state: 'unknown', detail: 'service binary no longer exists', path: file };
    else if (r.status === 'Valid') result = { state: 'signed', signer: signerName(r.subject ?? ''), path: file };
    else if (r.status === 'NotSigned') result = { state: 'unsigned', detail: 'not digitally signed', path: file };
    else result = { state: 'invalid', detail: `signature ${r.status}${r.message ? `: ${r.message}` : ''}`, path: file };
  } catch (e) {
    result = { state: 'unknown', detail: `signature check failed: ${e instanceof Error ? e.message.split('\n')[0] : e}`, path: file };
  }
  cache.set(file.toLowerCase(), { at: Date.now(), result });
  return result;
}

/** "CN=Microsoft Corporation, O=..., C=US" → "Microsoft Corporation"; handles quoted CNs with commas. */
export function signerName(subject: string): string {
  const m = /CN=(?:"([^"]*)"|([^,]*))/.exec(subject);
  return (m?.[1] ?? m?.[2] ?? subject).trim() || 'unknown signer';
}
