/**
 * Detection rules for Sysmon events (config: scripts/sysmon-config.xml). Pure: one event in,
 * at most one verdict out. When a verdict depends on who signed the program, it names the file to
 * check and the level for signed / unsigned; the caller runs the Authenticode check.
 */

export const SYSMON_CHANNEL = 'Microsoft-Windows-Sysmon/Operational';
export const SYSMON_IDS = [1, 3, 8, 10, 11, 12, 13, 25];

export type SysmonRule =
  | 'sysmon_doc_spawn'
  | 'sysmon_powershell'
  | 'sysmon_tamper_cmd'
  | 'sysmon_temp_program'
  | 'sysmon_tool_network'
  | 'sysmon_lsass'
  | 'sysmon_injection'
  | 'sysmon_registry_hijack'
  | 'sysmon_startup_file'
  | 'sysmon_tampering';

export type Verdict = {
  rule: SysmonRule;
  severity: string;
  title: string;
  /** Plain Thai headline for Telegram. */
  th: string;
  /** Groups repeats into one finding (per asset). */
  key: string;
  /** Check this file's signature: signed → `signed` (null = ignore), unsigned/invalid/unknown → `severity`. */
  sig?: { path: string; signed: string | null };
};

const base = (p: string | undefined) => (p ?? '').split('\\').pop()!.toLowerCase();
const low = (s: string | undefined) => (s ?? '').toLowerCase();

const DOC_PARENTS = new Set(['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'acrord32.exe', 'acrobat.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']);
const SHELLS = new Set(['cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe', 'schtasks.exe', 'reg.exe']);
const NET_TOOLS = new Set(['mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe']);

/** Places programs should not normally run from. Downloads is left to the signature check. */
const DROP_DIR = /\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\\$recycle\.bin\\|^c:\\programdata\\[^\\]+\.(exe|scr|com)$/i;
const RISKY_DIR = /\\users\\public\\|\\\$recycle\.bin\\/i;

const ENCODED_PS = /\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[a-z0-9+/=]{20,}|frombase64string/i;
const DOWNLOAD_EXEC = /downloadstring|downloadfile|net\.webclient|start-bitstransfer|(iex|invoke-expression)\s*[(\s]/i;
const HIDDEN = /\s-(w|wi|win|windowstyle)\s+h(idden)?\b/i;

/** Commands that turn protection off or destroy backups — what ransomware runs first. */
const TAMPER: { re: RegExp; sev: string; th: string; en: string }[] = [
  { re: /(add|set)-mppreference\b.*-exclusion/i, sev: 'critical', th: 'มีคำสั่งเพิ่มข้อยกเว้นให้ Defender', en: 'Command adds a Defender exclusion' },
  { re: /set-mppreference\b.*-disable\w*\s+(\$true|1)/i, sev: 'critical', th: 'มีคำสั่งปิดการป้องกันของ Defender', en: 'Command turns Defender protection off' },
  { re: /vssadmin(\.exe)?\s+(delete|resize)\s+shadow/i, sev: 'critical', th: 'มีคำสั่งลบไฟล์สำรอง (Shadow Copy) — พฤติกรรมของแรนซัมแวร์', en: 'Command deletes shadow copies (ransomware behaviour)' },
  { re: /wbadmin(\.exe)?\s+delete/i, sev: 'critical', th: 'มีคำสั่งลบข้อมูลสำรองของ Windows', en: 'Command deletes Windows backups' },
  { re: /bcdedit(\.exe)?.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i, sev: 'critical', th: 'มีคำสั่งปิดการกู้คืนระบบตอนบูต', en: 'Command disables boot recovery' },
  { re: /wevtutil(\.exe)?\s+(cl|clear-log)\b/i, sev: 'high', th: 'มีคำสั่งล้าง Event Log', en: 'Command clears an event log' },
  { re: /netsh(\.exe)?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable)/i, sev: 'high', th: 'มีคำสั่งปิดไฟร์วอลล์', en: 'Command turns the firewall off' },
  { re: /net1?(\.exe)?\s+user\s+\S+\s+\S*\s*\/add/i, sev: 'high', th: 'มีคำสั่งสร้างบัญชีผู้ใช้ใหม่', en: 'Command creates a user account' },
  { re: /net1?(\.exe)?\s+localgroup\s+administrators\s+\S+.*\/add/i, sev: 'critical', th: 'มีคำสั่งเพิ่มบัญชีเข้ากลุ่ม Administrators', en: 'Command adds an account to Administrators' },
  { re: /certutil(\.exe)?.*\s[-/](urlcache|decode|decodehex)\b/i, sev: 'high', th: 'certutil ถูกใช้โหลดหรือถอดรหัสไฟล์ (วิธีที่มัลแวร์ชอบใช้)', en: 'certutil used to download or decode a file' },
  { re: /bitsadmin(\.exe)?.*\/transfer/i, sev: 'high', th: 'bitsadmin ถูกใช้โหลดไฟล์', en: 'bitsadmin used to download a file' },
  { re: /reg(\.exe)?\s+add\s+.*\\policies\\system.*enablelua.*\/d\s+0/i, sev: 'critical', th: 'มีคำสั่งปิด UAC', en: 'Command turns UAC off' },
];

const short = (s: string, n = 160) => (s.length > n ? `${s.slice(0, n)}…` : s);

export function classifySysmon(id: number, f: Record<string, string>): Verdict | null {
  const image = f.Image ?? '';
  const name = base(image);
  switch (id) {
    case 1: {
      const cmd = f.CommandLine ?? '';
      for (const t of TAMPER)
        if (t.re.test(cmd)) return { rule: 'sysmon_tamper_cmd', severity: t.sev, title: `${t.en}: ${short(cmd, 120)}`, th: t.th, key: `${t.en}` };
      const parent = base(f.ParentImage);
      if (DOC_PARENTS.has(parent) && SHELLS.has(name))
        return { rule: 'sysmon_doc_spawn', severity: 'high', title: `${parent} started ${name}`, th: `${parent} เปิด ${name} — เอกสารหรือสคริปต์อาจมีมัลแวร์ฝังอยู่`, key: `${parent}>${name}` };
      if ((name === 'powershell.exe' || name === 'pwsh.exe' || name === 'cmd.exe') && (ENCODED_PS.test(cmd) || DOWNLOAD_EXEC.test(cmd) || (HIDDEN.test(cmd) && /https?:/i.test(cmd))))
        return { rule: 'sysmon_powershell', severity: 'high', title: `Hidden or encoded PowerShell: ${short(cmd, 120)}`, th: 'มี PowerShell ที่ซ่อนคำสั่งหรือโหลดโค้ดจากเน็ตมารัน', key: `${low(base(f.ParentImage))}>${name}:${ENCODED_PS.test(cmd) ? 'enc' : 'dl'}` };
      if (DROP_DIR.test(image))
        return {
          rule: 'sysmon_temp_program', severity: RISKY_DIR.test(image) ? 'high' : 'medium', title: `Unsigned program started from ${image}`,
          th: `มีโปรแกรมไม่มีลายเซ็นรันจากโฟลเดอร์ชั่วคราว: ${name}`, key: low(image), sig: { path: image, signed: null },
        };
      return null;
    }
    case 3: {
      const dest = f.DestinationHostname || f.DestinationIp || '?';
      if (/^(127\.|::1$|10\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(f.DestinationIp ?? '')) return null; // local / Tailscale
      if (NET_TOOLS.has(name))
        return { rule: 'sysmon_tool_network', severity: name === 'rundll32.exe' ? 'medium' : 'high', title: `${name} connected to ${dest}:${f.DestinationPort ?? ''}`, th: `${name} (เครื่องมือของ Windows ที่มัลแวร์ชอบยืมใช้) เชื่อมต่อไปที่ ${dest}`, key: `${name}:${low(dest)}` };
      if (DROP_DIR.test(image))
        return { rule: 'sysmon_tool_network', severity: 'high', title: `Program in a temp folder connected to ${dest}`, th: `โปรแกรมในโฟลเดอร์ชั่วคราว (${name}) เชื่อมต่อไปที่ ${dest}`, key: `${low(image)}:${low(dest)}`, sig: { path: image, signed: null } };
      return null;
    }
    case 8: {
      const src = f.SourceImage ?? '';
      if (/^c:\\windows\\(system32|syswow64)\\/i.test(src)) return null;
      return { rule: 'sysmon_injection', severity: 'high', title: `${base(src)} injected code into ${base(f.TargetImage)}`, th: `${base(src)} ฝังโค้ดเข้าไปในโปรแกรม ${base(f.TargetImage)}`, key: `${low(src)}>${base(f.TargetImage)}`, sig: { path: src, signed: 'medium' } };
    }
    case 10: {
      const src = f.SourceImage ?? '';
      return { rule: 'sysmon_lsass', severity: 'critical', title: `${base(src)} read LSASS memory (${f.GrantedAccess ?? ''})`, th: `${base(src)} พยายามอ่านหน่วยความจำของ LSASS ที่เก็บรหัสผ่าน Windows — วิธีขโมยรหัสผ่าน`, key: low(src), sig: { path: src, signed: 'medium' } };
    }
    case 11: {
      const file = f.TargetFilename ?? '';
      if (!/\\start menu\\programs\\startup\\/i.test(file) || /desktop\.ini$/i.test(file)) return null;
      const risky = /\.(exe|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf)$/i.test(file);
      return { rule: 'sysmon_startup_file', severity: risky ? 'high' : 'low', title: `File added to Startup: ${base(file)} (by ${name})`, th: `มีไฟล์ถูกวางในโฟลเดอร์ Startup: ${base(file)} (โดย ${name})`, key: low(file) };
    }
    case 12:
    case 13: {
      const obj = f.TargetObject ?? '';
      const details = low(f.Details);
      const off = /dword \(0x00000000\)/.test(details);
      if (/\\policies\\system\\(enablelua|consentpromptbehavioradmin)$/i.test(obj) && off)
        return { rule: 'sysmon_registry_hijack', severity: 'critical', title: `UAC turned off in the registry by ${name}`, th: `UAC ถูกปิดผ่าน Registry โดย ${name}`, key: 'uac-off' };
      if (/\\policies\\system\\promptonsecuredesktop$/i.test(obj) && off)
        return { rule: 'sysmon_registry_hijack', severity: 'medium', title: `UAC secure desktop turned off by ${name}`, th: `หน้าต่างถามสิทธิ์ UAC ถูกย้ายออกจากหน้าจอปลอดภัย โดย ${name}`, key: 'uac-secure-desktop' };
      if (/\\winlogon\\shell$/i.test(obj) && !/^explorer\.exe$/i.test((f.Details ?? '').trim()))
        return { rule: 'sysmon_registry_hijack', severity: 'critical', title: `Winlogon Shell changed to ${f.Details}`, th: 'โปรแกรมที่เปิดตอนล็อกอิน Windows (Winlogon Shell) ถูกเปลี่ยน', key: 'winlogon-shell' };
      if (/\\winlogon\\userinit$/i.test(obj) && !/^c:\\windows\\system32\\userinit\.exe,?$/i.test((f.Details ?? '').trim()))
        return { rule: 'sysmon_registry_hijack', severity: 'critical', title: `Winlogon Userinit changed to ${f.Details}`, th: 'โปรแกรมที่รันตอนล็อกอิน Windows (Userinit) ถูกเปลี่ยน', key: 'winlogon-userinit' };
      if (/\\image file execution options\\[^\\]+\\debugger$/i.test(obj) && f.EventType !== 'DeleteValue')
        return { rule: 'sysmon_registry_hijack', severity: 'high', title: `Program hijack (IFEO Debugger) set for ${obj.split('\\').at(-2)}`, th: `มีการตั้งให้โปรแกรม ${obj.split('\\').at(-2)} เปิดโปรแกรมอื่นแทน (IFEO)`, key: `ifeo:${low(obj)}` };
      if (/\\policies\\microsoft\\windows defender\\.*(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring)$/i.test(obj) && /0x00000001/.test(details))
        return { rule: 'sysmon_registry_hijack', severity: 'critical', title: `Defender turned off by policy (${obj.split('\\').pop()})`, th: 'Defender ถูกปิดผ่าน Group Policy ใน Registry', key: `defender-policy:${low(obj.split('\\').pop())}` };
      return null;
    }
    case 25:
      return { rule: 'sysmon_tampering', severity: 'high', title: `Code of ${name} was replaced while running (${f.Type ?? ''})`, th: `โค้ดของ ${name} ถูกสับเปลี่ยนระหว่างทำงาน (process hollowing)`, key: low(image), sig: { path: image, signed: null } };
    default:
      return null;
  }
}

/** One-line summary for the log view. */
export function describeSysmon(id: number, f: Record<string, string>): { category: string; level: string; summary: string } {
  const who = base(f.Image) || '?';
  switch (id) {
    case 1:
      return { category: 'process', level: 'info', summary: `Process ${who} started by ${base(f.ParentImage) || '?'}: ${short(f.CommandLine ?? '', 200)}` };
    case 3:
      return { category: 'network', level: 'info', summary: `${who} connected to ${f.DestinationHostname || f.DestinationIp || '?'}:${f.DestinationPort ?? ''}` };
    case 8:
      return { category: 'injection', level: 'warning', summary: `${base(f.SourceImage)} created a thread in ${base(f.TargetImage)}` };
    case 10:
      return { category: 'credentials', level: 'warning', summary: `${base(f.SourceImage)} opened ${base(f.TargetImage)} (${f.GrantedAccess ?? ''})` };
    case 11:
      return { category: 'file', level: 'info', summary: `${who} created ${f.TargetFilename ?? '?'}` };
    case 12:
    case 13:
      return { category: 'registry', level: 'info', summary: `${who} ${f.EventType ?? 'changed'} ${f.TargetObject ?? '?'}${f.Details ? ` = ${f.Details}` : ''}` };
    case 25:
      return { category: 'tamper', level: 'warning', summary: `Process tampering: ${who} (${f.Type ?? ''})` };
    default:
      return { category: 'sysmon', level: 'info', summary: `Sysmon event ${id}` };
  }
}
