import { extensionsPage, powersTh } from './browser-ext.js';
import { checkParts } from './device-messages.js';
import { exclusionPlain } from './exclusions.js';

/**
 * Plain Thai wording for a security finding, for the Thai UI: what happened in everyday words,
 * whether it is a worry, and what to do. Built when the finding is read (not stored), so findings
 * recorded before this existed get it too. The original technical title/summary stay as evidence.
 */

export type PlainText = { title: string; summary: string; fix?: string };

type Input = { ruleId: string; severity: string; title: string; summary: string; evidence: { condition?: string; details?: Record<string, unknown> } };

const after = (s: string, prefix: RegExp) => s.replace(prefix, '').trim();
const str = (v: unknown) => (typeof v === 'string' ? v : '');

/** "\GoogleSystem\GoogleUpdater\GoogleUpdaterTaskSystem159.0.8140.0{624C…}" → "GoogleUpdaterTaskSystem159.0.8140.0" */
const shortName = (name: string) => (name.split('\\').filter(Boolean).pop() ?? name).replace(/\{[0-9a-f-]{36}\}$/i, '').trim() || name;
/** "Google Updater Service (GoogleUpdaterService159.0.8140.0)" → "Google Updater Service" */
const friendly = (name: string) => name.replace(/\s*\([^)]*\)\s*$/, '').trim() || name;

const IF_NOT_YOU = 'ถ้าไม่ได้ทำเอง ให้เปลี่ยนรหัสผ่านและตรวจเครื่องทันที';

export function plainFinding(f: Input): PlainText | null {
  const d = f.evidence.details ?? {};
  switch (f.ruleId) {
    case 'service_installed': {
      const name = friendly(after(f.title, /^New service:\s*/));
      const signer = /signed by (.+?) \(valid\)/.exec(f.summary)?.[1];
      const cond = f.evidence.condition ?? '';
      if (signer) return { title: `มีโปรแกรมติดตั้งบริการเบื้องหลังใหม่: ${name}`, summary: `มีลายเซ็นยืนยันจาก ${signer} — ปกติเกิดตอนติดตั้งหรืออัปเดตโปรแกรม ไม่ต้องทำอะไร` };
      if (/Authenticode: (unsigned|invalid)/.test(cond)) return { title: `บริการเบื้องหลังใหม่ ไม่รู้ว่าใครสร้าง: ${name}`, summary: 'ไม่มีลายเซ็นยืนยันผู้ผลิต มัลแวร์มักติดตั้งตัวเองแบบนี้', fix: 'ถ้าไม่ได้ติดตั้งโปรแกรมอะไรช่วงนั้น ให้สแกนไวรัสแบบ Full scan' };
      return { title: `บริการเบื้องหลังใหม่: ${name}`, summary: 'ตรวจไม่ได้ว่าใครสร้าง', fix: 'ถ้าไม่รู้จักชื่อนี้ ให้สแกนไวรัสแบบ Full scan' };
    }
    case 'persistence_added': {
      const kind = str(d.kind) || (/^Scheduled task/.test(f.title) ? 'task' : 'startup');
      const name = shortName(str(d.name) || after(f.title, /^[^:]+:\s*/));
      const what = kind === 'startup' ? 'โปรแกรมที่เปิดเองตอนเปิดเครื่อง' : 'งานตั้งเวลาอัตโนมัติ';
      const assess = str(d.assessment);
      const signer = /^signed by (.+)$/.exec(assess)?.[1];
      const fix = kind === 'startup' ? `Task Manager → Startup apps → คลิกขวา "${name}" → Disable` : `Task Scheduler → หา "${name}" → Disable`;
      if (f.severity === 'critical') return { title: `พบ${what}ปลอมตัวเป็นไฟล์ระบบ: ${name}`, summary: 'ตั้งชื่อเหมือนไฟล์ของ Windows แต่อยู่ผิดที่ — ลักษณะของมัลแวร์', fix: `${fix} แล้วสแกนแบบ Microsoft Defender Offline` };
      if (signer) return { title: `${what}ใหม่: ${name}`, summary: `มีลายเซ็นยืนยันจาก ${signer} — ปกติเป็นโปรแกรมที่คุณติดตั้ง ไม่ต้องทำอะไร` };
      if (f.severity === 'high') return { title: `${what}ใหม่ ไม่รู้ว่าใครสร้าง: ${name}`, summary: 'ไม่มีลายเซ็นยืนยัน หรือชี้ไปที่ไฟล์ที่ไม่มีอยู่แล้ว', fix: `ถ้าไม่ได้ติดตั้งเอง: ${fix}` };
      return { title: `${what}ใหม่: ${name}`, summary: 'ตรวจไม่ได้ว่าใครสร้าง', fix: `ถ้าไม่รู้จัก: ${fix}` };
    }
    case 'system_changed': {
      const th = str(d.headlineTh);
      const section = str(d.section);
      const name = str(d.name);
      const low = f.severity === 'low';
      const fix =
        section === 'cert' ? `กด Win+R พิมพ์ ${str(d.store) === 'user' ? 'certmgr.msc' : 'certlm.msc'} → Trusted Root Certification Authorities → Certificates → คลิกขวา "${name}" → Delete`
        : section === 'firewall' ? `Start → พิมพ์ "Windows Defender Firewall with Advanced Security" → Inbound Rules → หา "${name}" → คลิกขวา → Disable Rule`
        : 'ดูวิธีเปลี่ยนกลับในข้อความแจ้งเตือน หรือเปิดรายละเอียดเรื่องนี้';
      return { title: th || f.title, summary: low ? 'ดูไม่อันตราย ถ้าคุณติดตั้งหรือเปิดเองก็ไม่ต้องทำอะไร' : str(d.assessment) || f.summary, fix: `${f.severity !== 'high' ? 'ถ้าไม่ได้ทำเอง: ' : ''}${fix}${f.severity === 'high' ? ' แล้วสแกน Full scan' : ''}` };
    }
    case 'network_changed': {
      const th = str(d.headlineTh);
      const reason = str(d.reason);
      const kind = str(d.kind);
      const fix =
        kind === 'hosts' ? 'เปิด Notepad แบบ Run as administrator → เปิด C:\\Windows\\System32\\drivers\\etc\\hosts → ลบบรรทัดนั้น → Save'
        : kind === 'dns' ? 'Settings → Network & internet → การ์ดเน็ตนั้น → DNS server assignment → Edit → Automatic (DHCP)'
        : kind === 'winhttp' ? 'เปิด Terminal (Admin) แล้วพิมพ์ netsh winhttp reset proxy'
        : kind === 'nrpt' ? 'PowerShell (Admin) → Get-DnsClientNrptRule ดูว่ามาจากโปรแกรมไหน'
        : 'Settings → Network & internet → Proxy → ปิด "Use a proxy server" และ "Use setup script"';
      const safe = reason === 'dns_public' || reason === 'hosts_blocklist';
      return { title: th || f.title, summary: safe ? 'ดูไม่อันตราย ถ้าคุณตั้งเองก็ไม่ต้องทำอะไร' : str(d.assessment) || f.summary, fix: `${safe || f.severity === 'medium' ? 'ถ้าไม่ได้ตั้งเอง: ' : ''}${fix}${f.severity === 'high' ? ' แล้วสแกน Full scan' : ''}` };
    }
    case 'browser_extension': {
      const name = str(d.name) || after(f.title, /^[^:]+:\s*/);
      const browser = str(d.browser) || 'เบราว์เซอร์';
      const page = extensionsPage(browser);
      const powers = Array.isArray(d.powers) ? (d.powers as unknown[]).map(String) : [];
      const gained = Array.isArray(d.gained) ? (d.gained as unknown[]).map(String) : [];
      const fix = `ถ้าไม่ได้ติดตั้งเอง: เปิด ${page} ใน ${browser} → "${name}" → นำออก แล้วเปลี่ยนรหัสผ่านเว็บสำคัญ`;
      switch (str(d.reason)) {
        case 'policy':
          return { title: `ส่วนขยายที่ถูกบังคับติดตั้งใน ${browser}: ${name}`, summary: 'ติดตั้งผ่าน policy จึงลบจากเบราว์เซอร์ไม่ได้ — เครื่องส่วนตัวไม่ควรมี', fix: `ดู ${page.replace('extensions', 'policy')} ว่าใครตั้ง แล้วสแกน Full scan` };
        case 'sideloaded':
          return { title: `ส่วนขยายที่ไม่ได้มาจาก Web Store ใน ${browser}: ${name}`, summary: 'ถูกโปรแกรมหรือไฟล์บนเครื่องใส่เข้ามา — ลักษณะของส่วนขยายขโมยข้อมูล', fix: `${fix} และสแกน Full scan` };
        case 'gained':
          return { title: `ส่วนขยายได้สิทธิ์เพิ่มหลังอัปเดต: ${name}`, summary: `ได้สิทธิ์ใหม่: ${powersTh(gained)}`, fix: `ถ้าไม่ได้ใช้ฟีเจอร์ใหม่: เปิด ${page} → "${name}" → นำออก` };
        case 'powerful':
          return { title: `ส่วนขยายใหม่ใน ${browser}: ${name}`, summary: `มาจาก Web Store แต่มีสิทธิ์สูง: ${powersTh(powers)}`, fix };
        default:
          return { title: `ส่วนขยายใหม่ใน ${browser}: ${name}`, summary: 'มาจาก Web Store และไม่ได้ขอสิทธิ์กว้าง ถ้าคุณติดตั้งเองก็ไม่ต้องทำอะไร' };
      }
    }
    case 'program_installed': {
      const name = str(d.name) || after(f.title, /^[^:]+:\s*/);
      const reason = str(d.reason);
      const fix = `ถ้าไม่ได้ติดตั้งเอง: Settings → Apps → Installed apps → "${name}" → Uninstall แล้วสแกน Full scan`;
      if (reason === 'crack') return { title: `ติดตั้งโปรแกรมที่น่าจะเป็นตัวแคร็ก: ${name}`, summary: 'ตัวแคร็กมักแฝงมัลแวร์ และไม่ได้รับอัปเดตความปลอดภัย', fix: `ถอนออกใน Settings → Apps → Installed apps → "${name}" แล้วสแกน Full scan` };
      if (reason === 'tampered') return { title: `ติดตั้งโปรแกรมที่ไฟล์ถูกดัดแปลง: ${name}`, summary: 'ไฟล์โปรแกรมถูกแก้หลังผู้ผลิตเซ็น — ลักษณะของตัวแคร็ก', fix: `ถอนออกใน Settings → Apps → Installed apps → "${name}" แล้วสแกน Full scan` };
      if (reason === 'unsigned') return { title: `ติดตั้งโปรแกรมใหม่ที่ไม่มีลายเซ็น: ${name}`, summary: 'ไม่รู้ว่าใครสร้างโปรแกรมนี้', fix };
      if (reason === 'signed') return { title: `ติดตั้งโปรแกรมใหม่: ${name}`, summary: `มีลายเซ็นยืนยันจาก ${str(d.signer) || '?'} — ปกติเป็นโปรแกรมที่คุณติดตั้ง ไม่ต้องทำอะไร` };
      return { title: `ติดตั้งโปรแกรมใหม่: ${name}`, summary: 'ตรวจลายเซ็นไม่ได้ ถ้าคุณติดตั้งเองก็ไม่ต้องทำอะไร', fix };
    }
    case 'device_protection': {
      const check = str(d.check);
      if (!check) return null;
      const items = Array.isArray(d.items) ? (d.items as unknown[]).map(String) : [];
      if (check === 'defender_exclusions' && items.length && !items.some((x) => x.startsWith('⚠'))) {
        const names = [...new Set(items.map((x) => exclusionPlain(x.split(' — ')[0], true)))].slice(0, 3).join(', ');
        return { title: `Defender ข้ามการตรวจ ${items.length} รายการ — ดูไม่อันตราย`, summary: `${names} · ถ้าคุณเพิ่มเอง (เช่น ให้โปรแกรมทำงานเร็วขึ้น) ไม่ต้องทำอะไร`, fix: 'ถ้าไม่ได้เพิ่มเอง ให้ลบออกใน Windows Security → จัดการการตั้งค่า → การยกเว้น' };
      }
      if (check === 'encryption') {
        const p = checkParts({ id: check, status: 'warn', msg: str(d.observed), vars: {} }, true);
        return { title: str(d.headlineTh) || p.head, summary: `${p.why} — ไม่บังคับ แค่แนะนำ`, fix: `${p.fix} (ถ้าไม่มีเมนูนี้ แปลว่า Windows รุ่นนี้ไม่รองรับ ข้ามได้)` };
      }
      const p = checkParts({ id: check, status: (str(d.status) || 'warn') as 'warn', msg: str(d.observed), items: (d.items as string[]) ?? [], vars: {} }, true);
      return { title: str(d.headlineTh) || p.head, summary: p.why, fix: p.fix };
    }
    case 'defender_exclusion_added': {
      const head = str(d.headlineTh) || `Defender ถูกสั่งไม่ให้ตรวจ ${after(f.title, /^Defender exclusion added:\s*/)}`;
      return f.severity === 'critical'
        ? { title: head, summary: 'เป็นจุดที่กว้างหรืออันตราย มัลแวร์มักตั้งแบบนี้เพื่อซ่อนตัว', fix: 'Windows Security → การป้องกันไวรัสและภัยคุกคาม → จัดการการตั้งค่า → การยกเว้น → ลบรายการนี้ แล้วสแกนแบบ Offline' }
        : { title: head, summary: 'ถ้าคุณเพิ่มเอง (เช่น ให้โปรแกรมทำงานเร็วขึ้น) ไม่ต้องทำอะไร', fix: 'ถ้าไม่ได้เพิ่มเอง ให้ลบออกใน Windows Security → การยกเว้น' };
    }
    case 'brute_force':
    case 'slow_brute_force': {
      const src = after(f.title, /^(Slow )?Password guessing from\s*/);
      const n = /^(\d+) failed/.exec(f.summary)?.[1] ?? 'หลาย';
      const span = f.ruleId === 'brute_force' ? `ภายใน ${/within (\d+) min/.exec(f.summary)?.[1] ?? '?'} นาที` : `ตลอด ~${/over ~(\d+) h/.exec(f.summary)?.[1] ?? '?'} ชั่วโมง`;
      const from = ['local', '-', '127.0.0.1', '::1'].includes(src) ? 'ที่เครื่องนี้เอง' : `จาก ${src}`;
      return { title: `มีคนพยายามเดารหัสผ่าน ${from}`, summary: `ใส่รหัสผิด ${n} ครั้ง${span} — ถ้าเป็นคุณพิมพ์ผิดเองก็ไม่เป็นไร`, fix: 'ถ้าไม่ใช่คุณ ให้ตั้งรหัสผ่านให้ยาวขึ้น และอย่าเปิด Remote Desktop สู่อินเทอร์เน็ต' };
    }
    case 'success_after_failures': {
      const m = /^Logon succeeded after (\d+) failures:\s*(.*)$/.exec(f.title);
      return { title: `เข้าระบบสำเร็จหลังใส่รหัสผิด ${m?.[1] ?? 'หลาย'} ครั้ง: ${m?.[2] ?? ''}`, summary: 'ถ้าเป็นคุณพิมพ์ผิดแล้วเข้าได้ ก็ไม่เป็นไร ถ้าไม่ใช่ แปลว่ามีคนเดารหัสถูก', fix: IF_NOT_YOU };
    }
    case 'new_local_user':
      return { title: `มีบัญชีผู้ใช้ใหม่ในเครื่อง: ${after(f.title, /^New user account:\s*/)}`, summary: 'ผู้บุกรุกมักสร้างบัญชีไว้แอบเข้าเครื่องภายหลัง', fix: 'ถ้าไม่ได้สร้างเอง: การตั้งค่า → บัญชี → ลบบัญชีนั้น แล้วเปลี่ยนรหัสผ่าน' };
    case 'admin_group_add':
      return { title: `มีบัญชีได้สิทธิ์ผู้ดูแลเพิ่ม (กลุ่ม ${after(f.title, /^Added to privileged group\s*/)})`, summary: 'บัญชีนี้จะทำอะไรกับเครื่องก็ได้', fix: IF_NOT_YOU };
    case 'log_cleared':
      return { title: 'บันทึกเหตุการณ์ของ Windows ถูกลบทิ้ง', summary: 'ผู้บุกรุกมักลบบันทึกเพื่อลบร่องรอย', fix: 'ถ้าไม่ได้ลบเอง ให้สแกนไวรัสแบบ Offline และเปลี่ยนรหัสผ่าน' };
    case 'account_lockout':
      return { title: `บัญชี ${after(f.title, /^Account locked out:\s*/)} ถูกล็อกชั่วคราว`, summary: 'เพราะใส่รหัสผ่านผิดหลายครั้งติดกัน', fix: 'ถ้าไม่ใช่คุณพิมพ์ผิด แปลว่ามีคนพยายามเดารหัส' };
    case 'defender_threat':
      return { title: `Defender เจอไวรัส/มัลแวร์: ${after(f.title, /^Malware:\s*/)}`, summary: 'ดูใน Windows Security ว่าถูกกักกันหรือลบแล้วหรือยัง', fix: 'Windows Security → การป้องกันไวรัสและภัยคุกคาม → ประวัติการป้องกัน' };
    case 'defender_disabled':
      return { title: 'การป้องกันไวรัสแบบเรียลไทม์ถูกปิด', summary: 'ระหว่างที่ปิด ไวรัสที่เข้ามาจะไม่ถูกบล็อก', fix: 'Windows Security → การป้องกันไวรัสและภัยคุกคาม → จัดการการตั้งค่า → เปิดการป้องกันแบบเรียลไทม์' };
    case 'remote_logon':
      return { title: `มีคนเข้าเครื่องจากระยะไกล (Remote Desktop): ${after(f.title, /^Remote Desktop logon:\s*/)}`, summary: 'มีการล็อกอินเข้าเครื่องผ่านเครือข่าย', fix: IF_NOT_YOU };
    case 'unexpected_shutdown':
      return { title: 'เครื่องดับกะทันหัน', summary: 'ไม่ได้ปิดเครื่องตามปกติ — มักเกิดจากแบตหมด ไฟดับ กดปุ่มค้าง หรือเครื่องค้าง ไม่ใช่เรื่องความปลอดภัยโดยตรง' };
    case 'web_security_headers': {
      const n = (/Missing: ([^·]+)/.exec(f.summary)?.[1].split(',').length) ?? 0;
      return { title: 'เว็บไซต์ยังขาดการตั้งค่าความปลอดภัยบางอย่าง', summary: `${n ? `ขาด ${n} รายการ ` : ''}ไม่ใช่ช่องโหว่ร้ายแรง แต่ช่วยกันการโจมตีบางแบบได้`, fix: 'เพิ่ม security headers ในการตั้งค่าเว็บ (เช่น vercel.json)' };
    }
    case 'sentinel_login_failed':
    case 'sentinel_mfa_failed':
    case 'sentinel_new_device': {
      const ip = str(d.ip);
      const where = ip === '127.0.0.1' || ip === '::1' ? 'จากเครื่องนี้เอง' : ip ? `จาก IP ${ip}` : '';
      const n = typeof d.attempts === 'number' ? d.attempts : null;
      const pw = 'SENTINEL → ตั้งค่า → เปลี่ยนรหัสผ่าน แล้วกด "ออกจากระบบทุกที่"';
      if (f.ruleId === 'sentinel_new_device')
        return { title: `เข้าสู่ระบบ SENTINEL จากอุปกรณ์ใหม่: ${str(d.device)}`, summary: `${where} — ถ้าเป็นคุณ (เช่น เปิดจากมือถือ) ไม่ต้องทำอะไร`, fix: `ถ้าไม่ใช่คุณ: ${pw}` };
      if (f.ruleId === 'sentinel_mfa_failed')
        return f.severity === 'critical'
          ? { title: `มีคนรู้รหัสผ่าน SENTINEL และกำลังเดารหัส 6 หลัก${n ? ` (${n} ครั้ง)` : ''}`, summary: `${where} — รหัสผ่านหลุดแล้ว ตอนนี้เหลือแค่รหัส 6 หลักที่กันไว้`, fix: pw }
          : { title: 'รหัสผ่าน SENTINEL ถูก แต่รหัส 6 หลักผิด', summary: `${where} — ถ้าเป็นคุณพิมพ์ผิดเอง ไม่ต้องทำอะไร ถ้าไม่ใช่ แปลว่ามีคนรู้รหัสผ่านของคุณ`, fix: `ถ้าไม่ใช่คุณ: ${pw}` };
      return d.locked
        ? { title: 'มีคนเดารหัสผ่านเข้า SENTINEL จนบัญชีถูกล็อก', summary: `${where} ใส่รหัสผิด${n ? ` ${n} ครั้ง` : ''}ใน 15 นาที — ระบบล็อกไว้ 15 นาทีแล้ว`, fix: 'ถ้าไม่ใช่คุณ: ตั้งรหัสผ่านให้ยาวและไม่ซ้ำกับที่อื่น และตรวจว่าใครเข้าถึง Tailscale ได้บ้าง' }
        : { title: `ใส่รหัสผ่าน SENTINEL ผิด${n ? ` ${n} ครั้ง` : ''}`, summary: `${where} ภายใน 15 นาที — ถ้าเป็นคุณจำรหัสไม่ได้ ก็ไม่เป็นไร`, fix: 'ถ้าไม่ใช่คุณ: เปลี่ยนรหัสผ่าน SENTINEL ให้ยาวและไม่ซ้ำกับที่อื่น' };
    }
    default:
      return null;
  }
}
