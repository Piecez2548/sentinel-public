import { compose, SEV_ICON, type Msg } from './device-messages.js';

/**
 * Trusted root certificates, inbound firewall "allow" rules and a few security settings (added 2026-11-21).
 * - A root certificate lets whoever holds its key fake the padlock of any website (bank, Google) and read
 *   HTTPS traffic; malware and some "free VPN" / ad tools add one next to a proxy.
 * - A firewall allow rule is how malware (or a remote-control tool) opens the PC to the network.
 * - Remote Desktop, WDigest, LSA protection, auto-logon password, SmartScreen, SMB1, Guest/Administrator
 *   accounts: switches attackers flip to get in again or to steal passwords.
 * The device-health script reads them; these pure helpers turn them into items, compare with the last run
 * and judge what is new. Same pattern as net-watch.ts.
 */

export type CertRow = { thumb: string; subject: string; issuer?: string; friendly?: string; until?: string; store: 'machine' | 'policy' | 'enterprise' | 'user' | 'authroot' };
export type FwRow = { id: string; src: 'local' | 'policy'; raw: string };
export type SysSettings = {
  rdp?: boolean | null;
  rdpNla?: boolean | null;
  lsaPpl?: boolean | null;
  wdigest?: boolean | null;
  autoLogonPassword?: boolean | null;
  smartScreenOff?: boolean | null;
  smb1?: boolean | null;
  users?: { name: string; sid: string }[] | null;
};
export type SysSnap = {
  certs?: CertRow[] | null;
  certsOk?: boolean;
  firewall?: FwRow[] | null;
  firewallOk?: boolean;
  settings?: SysSettings | null;
  settingsOk?: boolean;
};

export type SysSection = 'cert' | 'firewall' | 'setting';
export type FwRule = { name: string; app: string; svc: string; pfn: string; ports: string; protocol: string; profile: string; remote: string; iface: string; src: string; builtin: boolean };
export type SysItem = { key: string; section: SysSection; name: string; value: string; cert?: CertRow; rule?: FwRule; setting?: SettingId };

/** PowerShell turns one-element lists into a bare object. */
const arr = <T>(x: T | T[] | null | undefined): T[] => (x == null ? [] : Array.isArray(x) ? x : [x]);

/* ---------- certificates ---------- */

/** "CN=Foo Root, O=Foo Inc, C=US" → "Foo Root" (falls back to O= or the whole subject). */
export function certName(c: Pick<CertRow, 'subject' | 'friendly'>): string {
  const pick = (k: string) => new RegExp(`(?:^|,\\s*)${k}=("[^"]*"|[^,]*)`, 'i').exec(c.subject)?.[1]?.replace(/^"|"$/g, '').trim();
  return pick('CN') || pick('OU') || pick('O') || c.friendly || c.subject || '(no name)';
}

/* ---------- firewall ---------- */

const field = (raw: string, k: string) => {
  const all = [...raw.matchAll(new RegExp(`\\|${k}=([^|]*)`, 'g'))].map((m) => m[1]);
  return all.join(',');
};

const ENV_DIRS: [RegExp, string][] = [
  [/^%systemroot%/i, process.env.SystemRoot ?? 'C:\\Windows'],
  [/^%windir%/i, process.env.SystemRoot ?? 'C:\\Windows'],
  [/^%programfiles%/i, process.env.ProgramFiles ?? 'C:\\Program Files'],
  [/^%programfiles\(x86\)%/i, process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)'],
  [/^%systemdrive%/i, process.env.SystemDrive ?? 'C:'],
];
export const expandApp = (app: string) => ENV_DIRS.reduce((s, [re, v]) => s.replace(re, v), app);

const WINDOWS_APP = /^(?:system|[a-z]:\\windows\\(?:system32|syswow64)\\.*)$/i;

export function parseRule(raw: string, src: string): FwRule {
  const app = field(raw, 'App');
  const name = field(raw, 'Name');
  const builtin = name.startsWith('@') && (!app || WINDOWS_APP.test(expandApp(app)));
  const protoNum = field(raw, 'Protocol');
  const protocol = protoNum === '6' ? 'TCP' : protoNum === '17' ? 'UDP' : protoNum === '1' || protoNum === '58' ? 'ICMP' : protoNum ? `protocol ${protoNum}` : 'any';
  return {
    name,
    app,
    svc: field(raw, 'Svc'),
    pfn: field(raw, 'PFN'),
    ports: [field(raw, 'LPort'), field(raw, 'LPort2_10'), field(raw, 'LPort2_20')].filter(Boolean).join(','),
    protocol,
    profile: field(raw, 'Profile'),
    remote: [field(raw, 'RA4'), field(raw, 'RA6'), field(raw, 'RA42'), field(raw, 'RA62')].filter(Boolean).join(','),
    // Limited to one adapter (IF=) or to this PC's own address on one network (LA4/LA6=, e.g. Tailscale).
    iface: field(raw, 'IF') || [field(raw, 'LA4'), field(raw, 'LA6')].filter(Boolean).join(','),
    src,
    builtin,
  };
}

const baseName = (p: string) => p.split('\\').pop() || p;

export function ruleLabel(r: FwRule): string {
  if (!r.name.startsWith('@') && r.name) return r.name;
  if (r.app && !/^system$/i.test(r.app) && !WINDOWS_APP.test(expandApp(r.app))) return baseName(r.app);
  return r.svc ? `Windows service ${r.svc}` : 'Windows built-in rule';
}

/** "any program, port 3389 (TCP), any network" in plain words, for messages and the page. */
export function ruleSummary(r: FwRule): string {
  const who = r.app && !/^system$/i.test(r.app) ? expandApp(r.app) : r.svc ? `service ${r.svc}` : r.pfn ? `Store app ${r.pfn.split('_')[0]}` : r.app ? 'Windows (System)' : 'any program';
  const ports = r.ports ? `port ${r.ports}${r.protocol !== 'any' ? ` (${r.protocol})` : ''}` : r.protocol === 'ICMP' ? 'ping' : 'every port';
  const from = !r.remote || /^\*$/.test(r.remote) ? 'any address' : r.remote;
  const nets = r.iface ? 'one network adapter only' : r.profile ? r.profile.split(',').join('/') : 'every network type';
  return `${who} · ${ports} · from ${from} · ${nets}`;
}

/* ---------- settings ---------- */

export type SettingId = 'rdp' | 'rdp_no_nla' | 'lsa_off' | 'wdigest' | 'autologon_password' | 'smartscreen_off' | 'smb1' | 'guest' | 'builtin_admin';
const SETTING_NAME: Record<SettingId, string> = {
  rdp: 'Remote Desktop is on',
  rdp_no_nla: 'Remote Desktop without sign-in check (NLA off)',
  lsa_off: 'LSA protection is off',
  wdigest: 'WDigest keeps passwords in memory',
  autologon_password: 'Automatic sign-in with a stored password',
  smartscreen_off: 'SmartScreen is off',
  smb1: 'Old SMB1 file sharing is on',
  guest: 'Guest account is enabled',
  builtin_admin: 'Built-in Administrator account is enabled',
};
export const settingName = (id: SettingId) => SETTING_NAME[id];

function riskySettings(s: SysSettings): SettingId[] {
  const out: SettingId[] = [];
  if (s.rdp === true) out.push('rdp');
  if (s.rdp === true && s.rdpNla === false) out.push('rdp_no_nla');
  if (s.lsaPpl === false) out.push('lsa_off');
  if (s.wdigest === true) out.push('wdigest');
  if (s.autoLogonPassword === true) out.push('autologon_password');
  if (s.smartScreenOff === true) out.push('smartscreen_off');
  if (s.smb1 === true) out.push('smb1');
  for (const u of arr(s.users)) {
    if (/-501$/.test(u.sid)) out.push('guest');
    if (/-500$/.test(u.sid)) out.push('builtin_admin');
  }
  return [...new Set(out)];
}

/* ---------- items ---------- */

export function sysItems(n: SysSnap): { items: SysItem[]; ok: Record<SysSection, boolean> } {
  const items: SysItem[] = [];
  for (const c of arr(n.certs)) {
    if (!c?.thumb) continue;
    items.push({ key: `cert|${c.store}|${c.thumb.toUpperCase()}`, section: 'cert', name: certName(c), value: c.thumb.toUpperCase(), cert: c });
  }
  for (const f of arr(n.firewall)) {
    if (!f?.raw) continue;
    const r = parseRule(f.raw, f.src);
    items.push({ key: `fw|${f.src}|${f.id}|${r.app.toLowerCase()}|${r.ports}|${r.profile}`, section: 'firewall', name: ruleLabel(r), value: ruleSummary(r), rule: r });
  }
  if (n.settings) for (const id of riskySettings(n.settings)) items.push({ key: `set|${id}`, section: 'setting', name: SETTING_NAME[id], value: id, setting: id });
  return {
    items,
    ok: {
      cert: n.certsOk !== false && n.certs != null,
      firewall: n.firewallOk !== false && n.firewall != null,
      setting: n.settingsOk !== false && n.settings != null,
    },
  };
}

/* ---------- judging ---------- */

/** Debugging / interception / developer tools and game launchers that add their own root on purpose. */
const TOOL_CA = /fiddler|mitmproxy|charles proxy|portswigger|burp|mkcert|localhost|asp\.net core|iis express|local cert|zscaler|netfree|proxyman|telerik|httptoolkit|http toolkit|adguard|glasswire/i;
/** Antivirus "web shield" roots (they scan HTTPS by design). */
const AV_CA = /avast|\bavg\b|kaspersky|eset|bitdefender|norton|mcafee|sophos|trend ?micro|f-secure|malwarebytes|webroot|gen digital/i;
/** Well-known public CAs and Microsoft (Windows Update adds these). A name alone can be faked: medium if in the user store. */
const KNOWN_CA = /microsoft|digicert|globalsign|sectigo|comodo|usertrust|isrg|let's encrypt|entrust|godaddy|starfield|amazon|google trust|baltimore|certum|quovadis|identrust|thawte|verisign|symantec|geotrust|ssl\.com|actalis|buypass|telia|secom|swisssign|t-telesec|d-trust|harica|e-tugra|aaa certificate services|apple|thailand national root|thai digital id/i;

const TEMP_DIR = /\\(?:appdata\\local\\temp|windows\\temp|temp|downloads|users\\public)\\/i;
/** Remote control / admin ports: RDP, VNC, TeamViewer, SSH, Telnet, SMB, WinRM, common backdoor ports. */
const REMOTE_PORTS = new Set(['3389', '5900', '5901', '5938', '22', '23', '445', '139', '5985', '5986', '4444', '1337', '31337', '6666', '6667', '5800']);
const localOnly = (remote: string) => !!remote && remote.split(',').every((a) => /^(?:localsubnet|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fe80|127\.)/i.test(a.trim()));

export type Sig = { state: 'signed' | 'unsigned' | 'invalid' | 'unknown' | 'missing'; signer?: string };
export type SysReason =
  | 'cert_unknown' | 'cert_tool' | 'cert_av' | 'cert_known' | 'cert_windows'
  | 'fw_temp' | 'fw_missing' | 'fw_any_program' | 'fw_remote_port' | 'fw_unsigned' | 'fw_signed' | 'fw_builtin' | 'fw_store_app' | 'fw_service'
  | SettingId;
export type SysVerdict = { severity: 'low' | 'medium' | 'high'; reason: SysReason; detail: string };

const SETTING_SEV: Record<SettingId, 'medium' | 'high'> = {
  rdp: 'high', rdp_no_nla: 'high', wdigest: 'high', autologon_password: 'high', guest: 'high',
  lsa_off: 'medium', smartscreen_off: 'medium', smb1: 'medium', builtin_admin: 'medium',
};

/** A rule limited to the home network, or to one network adapter (e.g. Tailscale), is at most medium. */
const capRule = (v: SysVerdict, r: FwRule): SysVerdict =>
  v.severity !== 'high' ? v
  : localOnly(r.remote) ? { ...v, severity: 'medium', detail: `${v.detail} (home network only)` }
  : r.iface ? { ...v, severity: 'medium', detail: `${v.detail} (one network adapter only)` }
  : v;

export function judgeSys(it: SysItem, sig?: Sig): SysVerdict {
  if (it.section === 'setting') return { severity: SETTING_SEV[it.setting!], reason: it.setting!, detail: SETTING_NAME[it.setting!] };
  if (it.section === 'cert') {
    const c = it.cert!;
    const text = `${c.subject} ${c.friendly ?? ''}`;
    if (c.store === 'authroot') return { severity: 'low', reason: 'cert_windows', detail: `${it.name} — added by Windows' own root update list` };
    if (AV_CA.test(text)) return { severity: 'low', reason: 'cert_av', detail: `${it.name} — an antivirus that checks HTTPS pages` };
    if (TOOL_CA.test(text)) return { severity: 'medium', reason: 'cert_tool', detail: `${it.name} — a program on this PC (debugger, developer tool, game launcher) can read HTTPS` };
    if (KNOWN_CA.test(text) && c.store !== 'user') return { severity: 'low', reason: 'cert_known', detail: `${it.name} — looks like a well-known certificate authority` };
    return { severity: 'high', reason: 'cert_unknown', detail: `${it.name} — unknown root certificate: whoever owns it can fake any website's padlock` };
  }
  const r = it.rule!;
  const app = expandApp(r.app);
  const remotePort = r.ports.split(',').some((p) => REMOTE_PORTS.has(p.trim()));
  if (r.builtin) {
    return remotePort
      ? capRule({ severity: 'medium', reason: 'fw_builtin', detail: `Windows rule opened ${ruleSummary(r)}` }, r)
      : { severity: 'low', reason: 'fw_builtin', detail: `Windows feature rule: ${ruleSummary(r)}` };
  }
  if (r.pfn && !r.app) return { severity: 'low', reason: 'fw_store_app', detail: `Microsoft Store app rule: ${ruleSummary(r)}` };
  if (!r.app && !r.svc) {
    if (!r.ports || remotePort) return capRule({ severity: 'high', reason: r.ports ? 'fw_remote_port' : 'fw_any_program', detail: `any program may accept connections on ${r.ports ? `port ${r.ports}` : 'every port'}` }, r);
    return capRule({ severity: 'medium', reason: 'fw_any_program', detail: `any program may accept connections on port ${r.ports}` }, r);
  }
  if (!r.app && r.svc) return capRule({ severity: remotePort ? 'high' : 'medium', reason: 'fw_service', detail: `Windows service ${r.svc}: ${ruleSummary(r)}` }, r);
  if (TEMP_DIR.test(app)) return capRule({ severity: 'high', reason: 'fw_temp', detail: `${baseName(app)} runs from a temporary / download folder` }, r);
  // Uninstallers leave their rules behind; a rule for a file that is not there lets nothing in.
  if (sig?.state === 'missing') return { severity: 'low', reason: 'fw_missing', detail: `${baseName(app)} — the program is no longer on this PC` };
  if (remotePort && sig?.state !== 'signed') return capRule({ severity: 'high', reason: 'fw_remote_port', detail: `${baseName(app)} opened a remote-control port (${r.ports})` }, r);
  if (sig?.state === 'signed') {
    return remotePort
      ? capRule({ severity: 'medium', reason: 'fw_remote_port', detail: `${baseName(app)} (signed by ${sig.signer}) opened a remote-control port (${r.ports})` }, r)
      : { severity: 'low', reason: 'fw_signed', detail: `${baseName(app)} — signed by ${sig.signer}` };
  }
  const why = sig?.state === 'invalid' ? 'its signature is broken' : sig?.state === 'unsigned' ? 'not digitally signed' : 'signature could not be checked';
  // Unsigned programs in user folders are common (game launchers, Java runtimes): medium. A broken signature is not.
  return capRule({ severity: sig?.state === 'invalid' ? 'high' : 'medium', reason: 'fw_unsigned', detail: `${baseName(app)} — ${why}` }, r);
}

/* ---------- baseline diff ---------- */

/** Keys seen last time, with a display name for each (so a removed item can still be named). */
export type SysBaseline = { items: string[]; names?: Record<string, string> };
export type SysChange = { kind: 'added'; item: SysItem } | { kind: 'removed'; key: string; name: string };
export const sectionOf = (k: string): SysSection => (k.startsWith('cert|') ? 'cert' : k.startsWith('fw|') ? 'firewall' : 'setting');

/** First run records only. Sections that could not be read keep their old items and report nothing. */
export function diffSys(n: SysSnap, base: SysBaseline | null): { changes: SysChange[]; next: SysBaseline; items: SysItem[] } {
  const { items, ok } = sysItems(n);
  const old = new Set(base?.items ?? []);
  const now = new Set(items.filter((i) => ok[i.section]).map((i) => i.key));
  const kept = [...old].filter((k) => !ok[sectionOf(k)]);
  const changes: SysChange[] = [];
  if (base) {
    // A setting that was off at the first run is still "new" when it appears later; same for everything else.
    for (const it of items) if (ok[it.section] && !old.has(it.key)) changes.push({ kind: 'added', item: it });
    for (const k of old) if (ok[sectionOf(k)] && !now.has(k)) changes.push({ kind: 'removed', key: k, name: base.names?.[k] ?? k.split('|').slice(-1)[0] });
  }
  const names: Record<string, string> = {};
  for (const k of kept) if (base?.names?.[k]) names[k] = base.names[k];
  for (const i of items) if (now.has(i.key)) names[i.key] = i.name;
  return { changes, next: { items: [...now, ...kept], names }, items };
}

/* ---------- messages ---------- */

type Parts = { head: string; why: string; fix: string };

const CERT_FIX_TH = (name: string, store: string) =>
  `กด Win+R พิมพ์ ${store === 'user' ? 'certmgr.msc' : 'certlm.msc'} → Trusted Root Certification Authorities → Certificates → คลิกขวา "${name}" → Delete แล้วสแกน Full scan`;
const CERT_FIX_EN = (name: string, store: string) =>
  `Press Win+R, type ${store === 'user' ? 'certmgr.msc' : 'certlm.msc'} → Trusted Root Certification Authorities → Certificates → right-click "${name}" → Delete, then run a Full scan`;
const FW_FIX_TH = (name: string) => `Start → พิมพ์ "Windows Defender Firewall with Advanced Security" → Inbound Rules → หา "${name}" → คลิกขวา → Disable Rule`;
const FW_FIX_EN = (name: string) => `Start → type "Windows Defender Firewall with Advanced Security" → Inbound Rules → find "${name}" → right-click → Disable Rule`;

const SETTING_TEXT: Record<SettingId, { th: Parts; en: Parts }> = {
  rdp: {
    th: { head: 'เปิด Remote Desktop แล้ว', why: 'ใครที่รู้รหัสผ่าน Windows ของคุณเข้ามาคุมเครื่องจากเครือข่ายได้ — มัลแวร์ชอบเปิดไว้เป็นทางกลับเข้ามา', fix: 'Settings → System → Remote Desktop → ปิด' },
    en: { head: 'Remote Desktop was turned on', why: 'Anyone with your Windows password can control the PC over the network — malware turns it on as a way back in.', fix: 'Settings → System → Remote Desktop → Off' },
  },
  rdp_no_nla: {
    th: { head: 'Remote Desktop ไม่ตรวจรหัสก่อนเชื่อมต่อ (NLA ปิด)', why: 'เปิดช่องให้โจมตีหน้าจอล็อกอินจากเครือข่ายได้โดยไม่ต้องรู้รหัส', fix: 'Settings → System → Remote Desktop → Advanced settings → เปิด "Require devices to use Network Level Authentication" (หรือปิด Remote Desktop)' },
    en: { head: 'Remote Desktop without Network Level Authentication', why: 'The sign-in screen can be attacked from the network before any password check.', fix: 'Settings → System → Remote Desktop → Advanced settings → turn on "Require devices to use Network Level Authentication" (or turn Remote Desktop off)' },
  },
  lsa_off: {
    th: { head: 'ปิดการป้องกัน LSA แล้ว', why: 'LSA protection กันไม่ให้โปรแกรมอื่นขโมยรหัสผ่านจากหน่วยความจำ — โปรแกรมขโมยรหัสมักปิดมันก่อน', fix: 'Windows Security → Device security → Core isolation details → เปิด "Local Security Authority protection" แล้วรีสตาร์ต' },
    en: { head: 'LSA protection was turned off', why: 'It stops other programs reading passwords from memory — password stealers switch it off first.', fix: 'Windows Security → Device security → Core isolation details → turn on "Local Security Authority protection", then restart' },
  },
  wdigest: {
    th: { head: 'WDigest ถูกเปิดให้เก็บรหัสผ่านในหน่วยความจำ', why: 'ทำให้รหัสผ่านอยู่ในหน่วยความจำแบบอ่านออกได้ — เป็นการเตรียมขโมยรหัสแบบคลาสสิก (Mimikatz)', fix: 'แจ้งผมให้ปิดให้ หรือ regedit → HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest → UseLogonCredential = 0 แล้วรีสตาร์ต และเปลี่ยนรหัสผ่าน' },
    en: { head: 'WDigest set to keep passwords in memory', why: 'Passwords become readable in memory — a classic step before stealing them (Mimikatz).', fix: 'regedit → HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest → UseLogonCredential = 0, restart, then change your password' },
  },
  autologon_password: {
    th: { head: 'ตั้งล็อกอินอัตโนมัติโดยเก็บรหัสผ่านไว้ในเครื่อง', why: 'รหัสผ่าน Windows ถูกเก็บเป็นข้อความธรรมดาใน registry ใครเข้าเครื่องได้ก็อ่านได้', fix: 'กด Win+R พิมพ์ netplwiz → ติ๊ก "Users must enter a user name and password" → OK แล้วเปลี่ยนรหัสผ่าน' },
    en: { head: 'Automatic sign-in with a stored password', why: 'The Windows password is stored as plain text in the registry, readable by anything on the PC.', fix: 'Press Win+R, type netplwiz → tick "Users must enter a user name and password" → OK, then change your password' },
  },
  smartscreen_off: {
    th: { head: 'ปิด SmartScreen แล้ว', why: 'SmartScreen เตือนก่อนเปิดไฟล์ดาวน์โหลดที่อันตราย — มัลแวร์ชอบปิดเพื่อให้ตัวอื่นตามมาได้ง่าย', fix: 'Windows Security → App & browser control → Reputation-based protection → เปิดทุกข้อ' },
    en: { head: 'SmartScreen was turned off', why: 'It warns before running dangerous downloads — malware turns it off so more can follow.', fix: 'Windows Security → App & browser control → Reputation-based protection → turn everything on' },
  },
  smb1: {
    th: { head: 'เปิดการแชร์ไฟล์แบบเก่า SMB1', why: 'SMB1 เป็นช่องที่ WannaCry ใช้แพร่ — เครื่องสมัยนี้ไม่ต้องใช้แล้ว', fix: 'Start → พิมพ์ "Turn Windows features on or off" → เอาติ๊ก "SMB 1.0/CIFS File Sharing Support" ออก → OK แล้วรีสตาร์ต' },
    en: { head: 'Old SMB1 file sharing is on', why: 'SMB1 is how WannaCry spread — modern PCs do not need it.', fix: 'Start → type "Turn Windows features on or off" → untick "SMB 1.0/CIFS File Sharing Support" → OK, then restart' },
  },
  guest: {
    th: { head: 'เปิดบัญชี Guest แล้ว', why: 'บัญชี Guest เข้าเครื่องได้โดยไม่ต้องมีรหัสผ่าน — ปกติต้องปิดไว้', fix: 'เปิด Terminal (Admin) แล้วพิมพ์ net user Guest /active:no' },
    en: { head: 'Guest account was enabled', why: 'Guest can sign in without a password — it should stay off.', fix: 'Open Terminal (Admin) and run: net user Guest /active:no' },
  },
  builtin_admin: {
    th: { head: 'เปิดบัญชี Administrator ในตัวแล้ว', why: 'บัญชีนี้ไม่ถูก UAC ถาม และเป็นเป้าเดารหัสผ่านที่นิยม — ปกติต้องปิดไว้', fix: 'เปิด Terminal (Admin) แล้วพิมพ์ net user Administrator /active:no' },
    en: { head: 'Built-in Administrator account was enabled', why: 'It skips UAC prompts and is a favourite password-guessing target — it should stay off.', fix: 'Open Terminal (Admin) and run: net user Administrator /active:no' },
  },
};

export function sysMessage(it: SysItem, v: SysVerdict, asset: string): Msg {
  let p: { th: Parts; en: Parts };
  if (it.section === 'setting') p = SETTING_TEXT[it.setting!];
  else if (it.section === 'cert') {
    const c = it.cert!;
    const fixTh = CERT_FIX_TH(it.name, c.store);
    const fixEn = CERT_FIX_EN(it.name, c.store);
    p =
      v.reason === 'cert_tool'
        ? {
            th: { head: `มีใบรับรอง Root ใหม่จากโปรแกรมบนเครื่อง: ${it.name}`, why: 'โปรแกรมนี้อ่านเว็บ HTTPS ได้ (เครื่องมือดักเว็บ, เครื่องมือทำเว็บ, ตัวเปิดเกม) — ปกติถ้าคุณติดตั้งเอง', fix: `ถ้าไม่ได้ติดตั้งเอง: ${fixTh}` },
            en: { head: `New root certificate from a program on this PC: ${it.name}`, why: 'This program can read HTTPS pages (debugging proxy, developer tool, game launcher) — normal if you installed it.', fix: `If you didn't install it: ${fixEn}` },
          }
        : {
            th: { head: `มีใบรับรอง Root ใหม่ที่ไม่รู้จัก: ${it.name}`, why: 'ใครที่ถือใบนี้ทำเว็บปลอม (ธนาคาร, Google) ให้ขึ้นรูปกุญแจเหมือนของจริง และอ่านข้อมูลที่ส่งผ่าน HTTPS ได้', fix: fixTh },
            en: { head: `New unknown root certificate: ${it.name}`, why: "Whoever holds it can make fake sites (bank, Google) show a real-looking padlock and read HTTPS traffic.", fix: fixEn },
          };
  } else {
    const r = it.rule!;
    const label = it.name;
    const summary = ruleSummary(r);
    const fixTh = FW_FIX_TH(label);
    const fixEn = FW_FIX_EN(label);
    const why: Record<string, { th: string; en: string }> = {
      fw_temp: { th: `โปรแกรมในโฟลเดอร์ชั่วคราว/ดาวน์โหลดเปิดรับการเชื่อมต่อจากเครือข่าย — ลักษณะของมัลแวร์ (${summary})`, en: `A program in a temporary / download folder accepts network connections — a malware pattern (${summary}).` },
      fw_any_program: { th: `เปิดให้ทุกโปรแกรมรับการเชื่อมต่อจากเครือข่าย (${summary})`, en: `Any program may accept network connections (${summary}).` },
      fw_remote_port: { th: `เปิดพอร์ตของโปรแกรมควบคุมระยะไกล (${summary})`, en: `A remote-control port was opened (${summary}).` },
      fw_unsigned: { th: `${v.detail.split(' — ')[1] === 'not digitally signed' ? 'ไม่มีลายเซ็นยืนยัน' : v.detail.split(' — ')[1] === 'its signature is broken' ? 'ลายเซ็นเสีย' : 'ตรวจลายเซ็นไม่ได้'} แต่ขอเปิดรับการเชื่อมต่อจากเครือข่าย (${summary})`, en: `${v.detail} — yet it accepts network connections (${summary}).` },
      fw_service: { th: `บริการของ Windows เปิดรับการเชื่อมต่อ (${summary})`, en: `A Windows service accepts connections (${summary}).` },
      fw_builtin: { th: `กฎของ Windows ถูกเปิด (${summary}) — เกิดจากการเปิดฟีเจอร์ เช่น แชร์ไฟล์`, en: `A Windows rule was switched on (${summary}) — usually from turning on a feature such as file sharing.` },
      fw_signed: { th: `มีลายเซ็นยืนยัน (${summary})`, en: `Signed (${summary}).` },
      fw_missing: { th: `โปรแกรมนี้ไม่มีอยู่ในเครื่องแล้ว (${summary})`, en: `The program is no longer on this PC (${summary}).` },
      fw_store_app: { th: `แอปจาก Microsoft Store (${summary})`, en: `A Microsoft Store app (${summary}).` },
    };
    const w = why[v.reason] ?? why.fw_any_program;
    const maybe = v.severity !== 'high';
    p = {
      th: { head: `มีกฎไฟร์วอลล์ใหม่เปิดรับจากเครือข่าย: ${label}`, why: w.th, fix: `${maybe ? 'ถ้าไม่รู้จักโปรแกรมนี้: ' : ''}${fixTh}${maybe ? '' : ' แล้วสแกน Full scan'}` },
      en: { head: `New firewall rule accepts network connections: ${label}`, why: w.en, fix: `${maybe ? "If you don't know this program: " : ''}${fixEn}${maybe ? '' : ', then run a Full scan'}` },
    };
  }
  const icon = SEV_ICON[v.severity] ?? '🟡';
  return { th: compose(icon, p.th, asset, true), en: compose(icon, p.en, asset, false), headlineTh: p.th.head, headlineEn: p.en.head };
}

/* ---------- events (page history) ---------- */

export type SysEvent = { kind: 'added' | 'removed'; section: SysSection; name: string; value: string; at: number; severity?: string; reason?: SysReason };
const KEEP_MS = 90 * 86_400_000;
export const trimSysEvents = (ev: SysEvent[], now: number) => ev.filter((e) => now - e.at < KEEP_MS).slice(-200);
