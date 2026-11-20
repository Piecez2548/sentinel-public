/**
 * Which Microsoft Defender exclusions are dangerous. Malware commonly excludes whole drives,
 * system folders, user-writable folders it runs from, or system process names it impersonates,
 * so Defender never scans it. A narrow exclusion for one known program is usually deliberate.
 */

export type ExclusionKind = 'Paths' | 'Processes' | 'Extensions' | 'IpAddresses';

/** Real Windows binaries that malware names itself after. */
export const SYSTEM_BINARIES = new Set([
  'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'wininit.exe', 'explorer.exe',
  'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe', 'regsvr32.exe', 'spoolsv.exe', 'runtimebroker.exe',
  'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'msiexec.exe', 'sihost.exe',
]);

/** Short, plain description of an excluded location for chat messages, e.g. "ทั้งไดรฟ์ C:" / "the whole C: drive". */
export function exclusionPlain(value: string, th: boolean): string {
  const v = norm(value);
  if (/^[a-z]:$/.test(v)) return th ? `ทั้งไดรฟ์ ${v.toUpperCase()}` : `the whole ${v.toUpperCase()} drive`;
  if (/^[a-z]:\\windows$/.test(v)) return th ? 'โฟลเดอร์ Windows' : 'the Windows folder';
  if (/^[a-z]:\\program files( \(x86\))?$/.test(v)) return th ? 'Program Files (โปรแกรมทั้งหมด)' : 'Program Files (all programs)';
  if (/\\start menu\\programs\\startup$/.test(v)) return th ? 'โฟลเดอร์ Startup' : 'the Startup folder';
  if (/\\temp$/.test(v)) return th ? 'โฟลเดอร์ Temp' : 'the Temp folder';
  if (/\\appdata\\(roaming|local)$/.test(v)) return `AppData\\${/roaming$/.test(v) ? 'Roaming' : 'Local'}`;
  return value.trim().split(/[\\/]/).pop() || value;
}

const norm = (s: string) => s.trim().replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();

/** Returns why an exclusion is risky, or null when it looks like a narrow, deliberate one. */
export function exclusionRisk(kind: ExclusionKind, value: string): string | null {
  const v = norm(value);
  if (!v) return null;
  if (kind === 'Extensions') {
    return /^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr|com|msi|hta|lnk|jar)$/.test(v) ? 'excludes a whole executable file type' : null;
  }
  if (kind === 'IpAddresses') return null;
  if (kind === 'Processes') {
    const base = v.split('\\').pop()!;
    if (SYSTEM_BINARIES.has(base)) return `excludes the Windows process name ${base} (often impersonated by malware)`;
    if (/\\(temp|downloads)\\/.test(v)) return 'excludes a process running from a temporary/download folder';
    return null;
  }
  // Paths
  if (/^[a-z]:$/.test(v)) return 'excludes an entire drive';
  if (/^[a-z]:\\windows(\\|$)/.test(v)) return 'excludes the Windows folder';
  if (/^[a-z]:\\program files( \(x86\))?$/.test(v)) return 'excludes all installed programs';
  if (/^[a-z]:\\(users|programdata)$/.test(v)) return 'excludes all user data';
  if (/^[a-z]:\\users\\[^\\]+$/.test(v) || /^[a-z]:\\users\\[^\\]+\\appdata(\\(local|roaming|locallow))?$/.test(v)) return 'excludes a whole user profile folder';
  if (/\\(temp|downloads)$/.test(v) || /\\start menu\\programs\\startup$/.test(v)) return 'excludes a folder malware commonly runs from';
  const base = v.split('\\').pop()!;
  if (SYSTEM_BINARIES.has(base) && !/^[a-z]:\\windows\\/.test(v)) return `excludes a file named like the Windows binary ${base} outside the Windows folder`;
  if (/\\(temp|downloads)\\[^\\]+\.(exe|dll|scr|bat|ps1)$/.test(v)) return 'excludes an executable in a temporary/download folder';
  return null;
}
