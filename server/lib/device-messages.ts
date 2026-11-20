import type { Check } from '../modules/device-health.js';
import { exclusionPlain } from './exclusions.js';
import { escHtml } from './util.js';

/**
 * Plain-language Telegram messages for device health findings: what happened, why it matters,
 * and exactly where to click to fix it. Short enough to read on a phone lock screen.
 */

export const SEV_ICON: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' };

export type Msg = { en: string; th: string; headlineEn: string; headlineTh: string };

export type Parts = { head: string; why: string; list?: string[]; fix: string };

export const compose = (icon: string, p: Parts, asset: string, th: boolean) =>
  [
    `${icon} <b>${escHtml(p.head)}</b>`,
    escHtml(p.why),
    ...(p.list?.length ? ['', ...p.list.map((x) => `• ${escHtml(x)}`)] : []),
    '',
    `👉 <b>${th ? 'วิธีแก้' : 'Fix'}:</b> ${escHtml(p.fix)}`,
    '',
    `💻 ${escHtml(asset)}`,
  ].join('\n');

const WS_TH = 'Windows Security → การป้องกันไวรัสและภัยคุกคาม';
const WS_EN = 'Windows Security → Virus & threat protection';

export function checkParts(c: Check, th: boolean): Parts {
  const v = c.vars ?? {};
  const n = v.n ?? '';
  switch (c.id) {
    case 'defender_av':
      return th
        ? { head: 'การป้องกันไวรัสแบบเรียลไทม์ถูกปิด', why: 'ไวรัสที่เข้ามาใหม่จะไม่ถูกบล็อก', fix: `${WS_TH} → จัดการการตั้งค่า → เปิด "การป้องกันแบบเรียลไทม์"` }
        : { head: 'Real-time virus protection is off', why: 'New malware will not be blocked.', fix: `${WS_EN} → Manage settings → turn on Real-time protection` };
    case 'defender_signatures':
      return th
        ? { head: `ฐานข้อมูลไวรัสไม่ได้อัปเดตมา ${n} วัน`, why: 'Defender จะไม่รู้จักไวรัสตัวใหม่', fix: `${WS_TH} → การอัปเดตการป้องกัน → ตรวจหาการอัปเดต` }
        : { head: `Virus definitions are ${n} days old`, why: 'Defender will not recognise new malware.', fix: `${WS_EN} → Protection updates → Check for updates` };
    case 'defender_exclusions': {
      // Dangerous entries first (marked ⚠ by the check), shown in plain words.
      const risky = (c.items ?? []).filter((x) => x.startsWith('⚠')).map((x) => x.slice(1).trim().split(' — ')[0]);
      // Broadest first: whole drive, Windows, all programs, then the rest.
      const rank = (x: string) => (/^[a-z]:\\?$/i.test(x.trim()) ? 0 : /^[a-z]:\\windows\\?$/i.test(x.trim()) ? 1 : /^[a-z]:\\program files/i.test(x.trim()) ? 2 : 3);
      const shown = [...new Set([...risky].sort((a, b) => rank(a) - rank(b)).map((x) => exclusionPlain(x, th)))];
      const list = shown.slice(0, 4);
      if (shown.length > 4) list.push(th ? `และอีก ${shown.length - 4} จุด (ดูในหน้า สุขภาพเครื่อง)` : `and ${shown.length - 4} more (see Device health)`);
      return th
        ? { head: `Defender ถูกตั้งให้ "ข้าม" ${n} จุด`, why: 'ไฟล์ในจุดเหล่านี้จะไม่ถูกตรวจไวรัสเลย มัลแวร์มักตั้งแบบนี้เพื่อซ่อนตัว', list, fix: `${WS_TH} → จัดการการตั้งค่า → การยกเว้น → ลบรายการที่คุณไม่ได้เพิ่มเอง แล้วสแกนแบบ Offline` }
        : { head: `Defender is set to skip ${n} location(s)`, why: 'Files there are never scanned. Malware sets this up to hide.', list, fix: `${WS_EN} → Manage settings → Exclusions → remove anything you did not add, then run an Offline scan` };
    }
    case 'defender_scan':
      return th
        ? { head: `ไม่ได้สแกนไวรัสมา ${v.q ?? ''} วัน`, why: 'ควรสแกนอย่างน้อยสัปดาห์ละครั้ง', fix: `${WS_TH} → สแกนด่วน` }
        : { head: `No virus scan for ${v.q ?? ''} days`, why: 'Scan at least weekly.', fix: `${WS_EN} → Quick scan` };
    case 'firewall':
      return th
        ? { head: `ไฟร์วอลล์ปิดอยู่ (${v.list ?? ''})`, why: 'เครื่องอื่นในเครือข่ายเดียวกันเชื่อมต่อเข้ามาได้โดยไม่ถูกกรอง', fix: 'Windows Security → ไฟร์วอลล์และการป้องกันเครือข่าย → เปิดให้ครบทุกเครือข่าย' }
        : { head: `Firewall is off (${v.list ?? ''})`, why: 'Other devices on the same network can connect without filtering.', fix: 'Windows Security → Firewall & network protection → turn it on for every network' };
    case 'updates':
      if (c.msg.startsWith('Restart'))
        return th
          ? { head: 'ต้องรีสตาร์ทเครื่องเพื่อติดตั้งอัปเดตให้เสร็จ', why: 'อัปเดตความปลอดภัยยังไม่มีผลจนกว่าจะรีสตาร์ท', fix: 'บันทึกงานแล้วรีสตาร์ทเครื่อง' }
          : { head: 'Restart needed to finish updates', why: 'Security updates do not apply until you restart.', fix: 'Save your work and restart' };
      return th
        ? { head: `Windows ไม่ได้อัปเดตมา ${n} วัน`, why: 'ช่องโหว่ที่ยังไม่ได้แก้คือทางเข้าหลักของมัลแวร์', fix: 'การตั้งค่า → Windows Update → ติดตั้งอัปเดตแล้วรีสตาร์ท' }
        : { head: `Windows has not updated for ${n} days`, why: 'Unpatched holes are the main way malware gets in.', fix: 'Settings → Windows Update → install and restart' };
    case 'encryption':
      return th
        ? { head: `ไดรฟ์ ${v.d ?? 'C:'} ไม่ได้เข้ารหัส`, why: 'ถ้าโน๊ตบุ๊คหาย คนอื่นถอดดิสก์ไปอ่านไฟล์ได้', fix: 'การตั้งค่า → ความเป็นส่วนตัวและความปลอดภัย → การเข้ารหัสอุปกรณ์' }
        : { head: `Drive ${v.d ?? 'C:'} is not encrypted`, why: 'If the laptop is lost, the files can be read.', fix: 'Settings → Privacy & security → Device encryption' };
    case 'disks':
      if (c.status === 'bad')
        return th
          ? { head: `ดิสก์ ${n} ลูกรายงานว่ามีปัญหา`, why: 'ดิสก์อาจเสียเร็วๆ นี้', fix: 'สำรองไฟล์สำคัญทันที แล้วเตรียมเปลี่ยนดิสก์' }
          : { head: `${n} disk(s) report a problem`, why: 'The disk may fail soon.', fix: 'Back up important files now and plan a replacement' };
      return th
        ? { head: `SSD ${n} ลูกใกล้หมดอายุ`, why: 'ใช้งานมามากแล้ว', fix: 'สำรองข้อมูลสม่ำเสมอ และเตรียมเปลี่ยน' }
        : { head: `${n} SSD(s) near end of life`, why: 'Heavily used.', fix: 'Keep backups current and plan a replacement' };
    case 'battery':
      return th
        ? { head: `แบตเตอรี่เสื่อม เก็บไฟได้ ${v.p ?? ''}% ของตอนใหม่`, why: 'ใช้งานแบบไม่เสียบสายได้สั้นลง และเครื่องอาจดับกะทันหัน', fix: 'เปลี่ยนแบตเมื่อใช้งานไม่พอ' }
        : { head: `Battery holds ${v.p ?? ''}% of its original charge`, why: 'Shorter runtime; the laptop may shut down suddenly.', fix: 'Replace the battery when runtime is not enough' };
    case 'uac':
      if (c.status === 'warn')
        return th
          ? { head: 'หน้าต่างถามสิทธิ์ UAC ไม่ได้แสดงบนหน้าจอปลอดภัย', why: 'โปรแกรมอื่นอาจกดปุ่ม "Yes" แทนคุณได้', fix: 'Start → พิมพ์ UAC → Change User Account Control settings → เลื่อนไปขั้นที่ 3 จากล่าง → OK' }
          : { head: 'UAC prompt is not on the secure desktop', why: 'Another program could click "Yes" for you.', fix: 'Start → type UAC → Change User Account Control settings → third notch from the bottom → OK' };
      return th
        ? { head: 'UAC ถูกปิด', why: 'โปรแกรมไหนก็ได้สิทธิ์ admin โดยไม่ถามคุณ มัลแวร์ชอบปิด UAC เพื่อให้ตัวเองทำอะไรก็ได้ ถ้าคุณไม่ได้ปิดเอง ถือว่าอันตราย', fix: 'Start → พิมพ์ UAC → Change User Account Control settings → เลื่อนไปขั้นที่ 3 จากล่าง → OK → รีสตาร์ท แล้วสแกนแบบ Microsoft Defender Offline' }
        : { head: 'UAC has been turned off', why: 'Any program gets administrator rights without asking. Malware turns UAC off so it can do anything. If you did not do this, treat it as dangerous.', fix: 'Start → type UAC → Change User Account Control settings → third notch from the bottom → OK → restart, then run a Microsoft Defender Offline scan' };
    case 'remote_tools': {
      const list = (c.items ?? []).filter((x) => x.startsWith('⚠')).map((x) => x.slice(1).trim());
      return th
        ? { head: `พบโปรแกรมควบคุมเครื่องจากระยะไกลที่คุณไม่ได้อนุมัติ: ${v.list ?? ''}`, why: 'โปรแกรมแบบนี้ให้คนอื่นเห็นหน้าจอและบังคับเครื่องได้ มิจฉาชีพมักแอบติดตั้งไว้', list, fix: 'ถ้าไม่ได้ติดตั้งเอง: การตั้งค่า → แอป → แอปที่ติดตั้ง → ถอนการติดตั้ง แล้วเปลี่ยนรหัสผ่านสำคัญ ถ้าติดตั้งเอง: ศูนย์ความปลอดภัย → เปิดรายการนี้ → กด "ปิดเรื่อง" ระบบจะจำว่าอนุมัติแล้ว' }
        : { head: `Remote-control program you have not approved: ${v.list ?? ''}`, why: 'These let someone see your screen and control the PC. Scammers install them quietly.', list, fix: 'If you did not install it: Settings → Apps → Installed apps → Uninstall, then change important passwords. If you did: Security Center → open this finding → Resolve, and it is remembered as approved' };
    }
    case 'open_ports': {
      const list = (c.items ?? []).filter((x) => !x.endsWith('(known)')).map((x) => x.replace(/^⚠\s*/, '').replace(/\s*\(.*\)$/, ''));
      return th
        ? { head: `มีโปรแกรมใหม่เปิดรับการเชื่อมต่อจากทุกเครือข่าย: ${v.list ?? ''}`, why: 'เครื่องอื่นในเครือข่ายเดียวกัน (เช่น Wi-Fi ร้านกาแฟ) อาจเชื่อมต่อเข้ามาที่โปรแกรมนี้ได้', list, fix: 'ถ้าไม่รู้จักหรือไม่ได้ใช้: ปิดหรือถอนโปรแกรมนั้น ถ้ารู้จัก: ศูนย์ความปลอดภัย → เปิดรายการนี้ → กด "ปิดเรื่อง" ระบบจะไม่เตือนโปรแกรมนี้อีก' }
        : { head: `New program open to every network: ${v.list ?? ''}`, why: 'Other devices on the same network (e.g. café Wi-Fi) may be able to connect to it.', list, fix: 'If you do not know or use it: stop or uninstall it. If you do: Security Center → open this finding → Resolve, and it will not alert again' };
    }
    default:
      return { head: c.id, why: c.msg, fix: th ? 'ดูในหน้า สุขภาพเครื่อง' : 'See Device health' };
  }
}

export function checkMessage(c: Check, asset: string): Msg {
  const icon = SEV_ICON[c.severity ?? 'medium'];
  const th = checkParts(c, true);
  const en = checkParts(c, false);
  return { th: compose(icon, th, asset, true), en: compose(icon, en, asset, false), headlineTh: th.head, headlineEn: en.head };
}

export type PersistVerdict = { kind: 'startup' | 'task'; name: string; command: string; severity: string; reason: 'masquerade' | 'missing' | 'unsigned' | 'unknown' | 'signed'; signer?: string };

/** "C:\Users\me\AppData\Local\svchost.exe" → "AppData\Local\svchost.exe" */
const shortPath = (p: string) => p.replace(/^"?[a-z]:\\users\\[^\\]+\\/i, '').replace(/"/g, '');

export function persistenceMessage(v: PersistVerdict, asset: string): Msg {
  const icon = SEV_ICON[v.severity] ?? '🟡';
  const where = shortPath(v.command.split(' ; ')[0]);
  const fixTh = v.kind === 'startup' ? `Task Manager → Startup apps → คลิกขวา "${v.name}" → Disable` : `Task Scheduler → หา "${v.name}" → Disable หรือ Delete`;
  const fixEn = v.kind === 'startup' ? `Task Manager → Startup apps → right-click "${v.name}" → Disable` : `Task Scheduler → find "${v.name}" → Disable or Delete`;
  const thing = { th: v.kind === 'startup' ? 'โปรแกรมเปิดอัตโนมัติ' : 'Scheduled Task', en: v.kind === 'startup' ? 'auto-start program' : 'scheduled task' };
  const base = where.split('\\').pop() ?? where;
  const parts: Record<PersistVerdict['reason'], { th: Parts; en: Parts }> = {
    masquerade: {
      th: { head: `พบ${thing.th}ปลอม: ${v.name}`, why: `ตั้งชื่อเหมือนไฟล์ระบบ Windows (${base}) แต่อยู่ที่ ${where} — ของจริงอยู่ใน C:\\Windows เท่านั้น`, fix: `${fixTh} แล้วสแกนแบบ Microsoft Defender Offline` },
      en: { head: `Fake ${thing.en}: ${v.name}`, why: `Named like the Windows file ${base} but lives in ${where} — the real one is only in C:\\Windows.`, fix: `${fixEn}, then run a Microsoft Defender Offline scan` },
    },
    missing: {
      th: { head: `${thing.th}ใหม่ชี้ไปที่ไฟล์ที่ไม่มีอยู่: ${v.name}`, why: `ไฟล์ ${where} ไม่มีแล้ว มักเป็นร่องรอยของโปรแกรมที่ถูกลบ รวมถึงมัลแวร์`, fix: `ถ้าไม่รู้จัก: ${fixTh}` },
      en: { head: `New ${thing.en} points to a missing file: ${v.name}`, why: `${where} no longer exists — often left behind by removed software, including malware.`, fix: `If you don't recognise it: ${fixEn}` },
    },
    unsigned: {
      th: { head: `${thing.th}ใหม่ ไม่มีลายเซ็นดิจิทัล: ${v.name}`, why: `ไม่รู้ว่าใครสร้างโปรแกรมนี้ (${where})`, fix: `ถ้าไม่ได้ติดตั้งเอง: ${fixTh}` },
      en: { head: `New unsigned ${thing.en}: ${v.name}`, why: `Nobody vouches for this program (${where}).`, fix: `If you didn't install it: ${fixEn}` },
    },
    unknown: {
      th: { head: `${thing.th}ใหม่: ${v.name}`, why: `ตรวจลายเซ็นไม่ได้ (${where})`, fix: `ถ้าไม่ได้ติดตั้งเอง: ${fixTh}` },
      en: { head: `New ${thing.en}: ${v.name}`, why: `Signature could not be checked (${where}).`, fix: `If you didn't install it: ${fixEn}` },
    },
    signed: {
      th: { head: `${thing.th}ใหม่: ${v.name}`, why: `มีลายเซ็นจาก ${v.signer ?? '?'} — ปกติเป็นโปรแกรมที่คุณติดตั้ง`, fix: 'ถ้าไม่ได้ติดตั้งเอง ปิดได้ใน Task Manager → Startup apps' },
      en: { head: `New ${thing.en}: ${v.name}`, why: `Signed by ${v.signer ?? '?'} — usually something you installed.`, fix: 'If not, disable it in Task Manager → Startup apps' },
    },
  };
  const p = parts[v.reason];
  return { th: compose(icon, p.th, asset, true), en: compose(icon, p.en, asset, false), headlineTh: p.th.head, headlineEn: p.en.head };
}
