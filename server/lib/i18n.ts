import { getSetting } from '../db.js';

/**
 * Language for outgoing notifications (Telegram). Stored as the `language` setting,
 * default Thai. Data kept in the database (alert titles, event summaries) stays English
 * so search and evidence are stable; only the message text sent out is localized.
 */

export type Lang = 'th' | 'en';

export const notifyLang = (): Lang => (getSetting('language') === 'en' ? 'en' : 'th');

/** Pick the text for the current notification language. */
export const L = (en: string, th: string) => (notifyLang() === 'th' ? th : en);

const SEV_TH: Record<string, string> = { critical: 'วิกฤต', high: 'สูง', medium: 'กลาง', low: 'ต่ำ' };
export const sevText = (sev: string) => (notifyLang() === 'th' ? SEV_TH[sev] ?? sev : sev.toUpperCase());

/** Duration in the notification language: "1h 5m" / "1 ชม. 5 นาที". */
export function durText(ms: number): string {
  const th = notifyLang() === 'th';
  const u = th ? { s: ' วินาที', m: ' นาที', h: ' ชม.', d: ' วัน' } : { s: 's', m: 'm', h: 'h', d: 'd' };
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}${u.s}`;
  if (s < 3600) return `${Math.floor(s / 60)}${u.m} ${s % 60}${u.s}`;
  if (s < 86400) return `${Math.floor(s / 3600)}${u.h} ${Math.floor((s % 3600) / 60)}${u.m}`;
  return `${Math.floor(s / 86400)}${u.d} ${Math.floor((s % 86400) / 3600)}${u.h}`;
}

/** Thai labels for the health components and detection rules, used in messages. */
const COMPONENT_TH: Record<string, string> = {
  'Windows Event Log collector': 'ตัวอ่าน Windows Event Log',
  'Host metrics collector': 'ตัวเก็บข้อมูลเครื่อง',
  'Website checks': 'ตัวตรวจเว็บไซต์',
  'Monthly restore test': 'ทดสอบกู้คืนรายเดือน',
  'Telegram delivery': 'การส่ง Telegram',
  Backups: 'สำรองข้อมูล',
  'External heartbeat': 'สัญญาณชีพไปบริการภายนอก',
  'Device health checks': 'ตัวตรวจสุขภาพเครื่อง',
  'Off-disk backup copy': 'สำเนา backup นอกดิสก์',
};
export const componentText = (label: string) => (notifyLang() === 'th' ? COMPONENT_TH[label] ?? label : label);

const RULE_TH: Record<string, string> = {
  brute_force: 'มีคนพยายามเดารหัสผ่าน',
  slow_brute_force: 'มีคนค่อยๆ เดารหัสผ่าน (แบบช้า)',
  success_after_failures: 'ล็อกอินสำเร็จหลังล้มเหลวหลายครั้ง',
  new_local_user: 'มีการสร้างบัญชีผู้ใช้ใหม่',
  admin_group_add: 'มีบัญชีถูกเพิ่มเข้ากลุ่มสิทธิ์สูง',
  log_cleared: 'มีการล้าง Audit log',
  service_installed: 'มีการติดตั้ง Service ใหม่',
  account_lockout: 'บัญชีถูกล็อก',
  defender_threat: 'Defender พบมัลแวร์',
  defender_exclusion_added: 'มีการเพิ่มข้อยกเว้นใน Defender',
  device_protection: 'การป้องกันของเครื่องอ่อนลง',
  sysmon_doc_spawn: 'เอกสารหรือสคริปต์เปิดหน้าต่างคำสั่ง (Sysmon)',
  sysmon_powershell: 'PowerShell ที่ซ่อนหรือเข้ารหัสคำสั่ง (Sysmon)',
  sysmon_tamper_cmd: 'คำสั่งปิดการป้องกันหรือลบข้อมูลสำรอง (Sysmon)',
  sysmon_temp_program: 'โปรแกรมไม่มีลายเซ็นรันจากโฟลเดอร์ชั่วคราว (Sysmon)',
  sysmon_tool_network: 'สคริปต์หรือเครื่องมือระบบเชื่อมต่อออกเน็ต (Sysmon)',
  sysmon_lsass: 'มีโปรแกรมอ่านความลับการล็อกอินของ Windows (Sysmon)',
  sysmon_injection: 'มีการฝังโค้ดเข้าโปรแกรมอื่น (Sysmon)',
  sysmon_registry_hijack: 'UAC, การล็อกอิน หรือ Defender ถูกแก้ใน Registry (Sysmon)',
  sysmon_startup_file: 'มีไฟล์ถูกวางในโฟลเดอร์ Startup (Sysmon)',
  sysmon_tampering: 'โค้ดของโปรแกรมถูกสับเปลี่ยนระหว่างทำงาน (Sysmon)',
  persistence_added: 'มีโปรแกรมเริ่มอัตโนมัติหรือ Scheduled Task ใหม่',
  program_installed: 'มีการติดตั้งโปรแกรมใหม่',
  browser_extension: 'มีส่วนขยายเบราว์เซอร์ใหม่',
  network_changed: 'ไฟล์ hosts / DNS / proxy เปลี่ยน',
  sentinel_login_failed: 'มีคนเดารหัสผ่านเข้า SENTINEL',
  sentinel_mfa_failed: 'รหัสผ่าน SENTINEL ถูก แต่รหัส 6 หลักผิด',
  sentinel_new_device: 'เข้าสู่ระบบ SENTINEL จากอุปกรณ์ใหม่',
  defender_disabled:'Defender ถูกปิดการป้องกันแบบเรียลไทม์',
  remote_logon: 'มีการล็อกอินผ่าน Remote Desktop',
  unexpected_shutdown: 'เครื่องดับผิดปกติ',
  web_security_headers: 'เว็บไซต์ขาด security headers',
};
export const ruleText = (id: string, fallback: string) => (notifyLang() === 'th' ? RULE_TH[id] ?? fallback : fallback);

/** Website check error in plain Thai ("Timeout after 10s" → "รอ 10 วินาทีแล้วไม่ตอบ"). */
export function checkErrorTh(err: string | null): string {
  if (!err) return 'ตรวจไม่ผ่าน';
  let m: RegExpMatchArray | null;
  if ((m = err.match(/^Timeout after (\d+)s$/))) return `รอ ${m[1]} วินาทีแล้วไม่ตอบ`;
  if ((m = err.match(/^HTTP (\d+)(?: \(expected (.+)\))?$/))) return `เว็บตอบกลับรหัส ${m[1]}${m[2] ? ` (ควรเป็น ${m[2]})` : ''}`;
  if ((m = err.match(/^Keyword "(.*)" not found$/))) return `ไม่เจอคำว่า "${m[1]}" ในหน้าเว็บ`;
  if (err === 'Too many redirects') return 'เว็บส่งต่อ (redirect) วนหลายรอบเกินไป';
  if (err === 'ENOTFOUND' || err === 'EAI_AGAIN') return `หาชื่อเว็บไม่เจอ (DNS) — ${err}`;
  if (err === 'ECONNREFUSED') return 'เซิร์ฟเวอร์ปฏิเสธการเชื่อมต่อ';
  if (err === 'ECONNRESET') return 'การเชื่อมต่อถูกตัดกลางทาง';
  return err;
}

/** Stored alert titles are English (see top of file); this gives the Thai line for chat messages. */
export function alertTitleText(title: string): string {
  if (notifyLang() !== 'th') return title;
  const rules: [RegExp, (m: RegExpMatchArray) => string][] = [
    [/^(.+) is DOWN$/, (m) => `เว็บ ${m[1]} ล่ม`],
    [/^(.+) is slow$/, (m) => `เว็บ ${m[1]} ช้า`],
    [/^(.+) is offline$/, (m) => `${m[1]} ออฟไลน์`],
    [/^CPU high on (.+)$/, (m) => `CPU สูงบน ${m[1]}`],
    [/^Memory high on (.+)$/, (m) => `หน่วยความจำสูงบน ${m[1]}`],
    [/^Disk (.+) almost full on (.+)$/, (m) => `ดิสก์ ${m[1]} ใกล้เต็มบน ${m[2]}`],
    [/^Battery low on (.+)$/, (m) => `แบตเตอรี่ใกล้หมดบน ${m[1]}`],
    [/^TLS certificate of (.+) expires has EXPIRED$/, (m) => `ใบรับรอง TLS ของ ${m[1]} หมดอายุแล้ว`],
    [/^TLS certificate of (.+) expires in (-?\d+) day\(s\)$/, (m) => `ใบรับรอง TLS ของ ${m[1]} จะหมดอายุในอีก ${m[2]} วัน`],
    [/^SENTINEL: (.+) is failing$/, (m) => `SENTINEL: ${componentText(m[1])} มีปัญหา`],
  ];
  for (const [re, f] of rules) {
    const m = title.match(re);
    if (m) return f(m);
  }
  return title;
}
