import { compose, SEV_ICON, type Msg } from './device-messages.js';

/**
 * USB drives, keyboard devices and Wi-Fi (added 2026-11-21).
 * - A disk the PC has never seen = someone plugged in a USB drive (Windows remembers every one, so a drive
 *   plugged in and pulled out between two checks is still caught).
 * - A new "keyboard" can be a BadUSB stick that types commands; one built on a hobby micro-controller board
 *   (Arduino, Teensy, Raspberry Pi Pico…) or arriving together with a new drive is treated as an attack.
 * - A saved open Wi-Fi that auto-connects, or being on a Wi-Fi without a password right now, lets anyone
 *   nearby watch or tamper with the traffic.
 * Same baseline pattern as net-watch / sys-watch: the first run only records.
 */

export type PnpRow = { id: string; name?: string; present?: boolean };
export type WifiRow = { ssid: string; auth?: string; enc?: string; mode?: string };
export type PeriphSnap = {
  disks?: PnpRow[] | null;
  disksOk?: boolean;
  keyboards?: PnpRow[] | null;
  keyboardsOk?: boolean;
  wifi?: WifiRow[] | null;
  wifiOk?: boolean;
  /** Network name of the Wi-Fi in use ('' = not on Wi-Fi, null = could not read). */
  wifiNow?: string | null;
};

export type PeriphSection = 'disk' | 'keyboard' | 'wifi' | 'wifinow';
export type PeriphItem = { key: string; section: PeriphSection; name: string; value: string; usb?: boolean; vid?: string; auth?: string; auto?: boolean };

const arr = <T>(x: T | T[] | null | undefined): T[] => (x == null ? [] : Array.isArray(x) ? x : [x]);

/** Keyboard makers, so "HID Keyboard Device" can say whose it is. */
const VENDORS: Record<string, string> = {
  '046D': 'Logitech', '045E': 'Microsoft', '05AC': 'Apple', '1532': 'Razer', '1B1C': 'Corsair', '1038': 'SteelSeries', '0951': 'HyperX', '03F0': 'HP',
  '413C': 'Dell', '17EF': 'Lenovo', '0B05': 'ASUS', '3434': 'Keychron', '258A': 'gaming keyboard (Sino Wealth)', '2717': 'Xiaomi', '04D9': 'Holtek', '1A2C': 'China Resource Semico',
  '0C45': 'Microdia', '24AE': 'Rapoo', '1EA7': 'SHARKOON', '2516': 'Cooler Master', '3554': 'gaming mouse/keyboard', '093A': 'Pixart', '04F2': 'Chicony', '0461': 'Primax', '048D': 'ITE',
};
/** Hobby / development boards that BadUSB "rubber duckies" are built on. A keyboard from one of these is not a keyboard. */
const DEV_BOARDS: Record<string, string> = {
  '2341': 'Arduino', '2A03': 'Arduino', '1B4F': 'SparkFun', '16C0': 'Teensy / V-USB', '239A': 'Adafruit', '2E8A': 'Raspberry Pi Pico', '03EB': 'Atmel', '1A86': 'CH340 USB chip',
  '0483': 'STMicroelectronics', '1209': 'pid.codes (hobby)', '10C4': 'Silicon Labs', '303A': 'Espressif (ESP32)', '1D50': 'OpenMoko (hobby)', '0403': 'FTDI', 'F000': 'unknown maker',
};

const vidPid = (id: string) => {
  const m = /VID_([0-9A-F]{4})&PID_([0-9A-F]{4})/i.exec(id);
  return m ? { vid: m[1].toUpperCase(), pid: m[2].toUpperCase() } : null;
};

/** Open = no password. OWE ("Enhanced Open") encrypts, WEP is broken. */
export const wifiRisk = (auth = '', enc = ''): 'open' | 'weak' | 'ok' =>
  /wep|shared/i.test(auth) || /^wep$/i.test(enc) ? 'weak' : /^open$/i.test(auth) && !/aes|gcmp/i.test(enc) ? 'open' : 'ok';

export function periphItems(n: PeriphSnap): { items: PeriphItem[]; ok: Record<PeriphSection, boolean> } {
  const items: PeriphItem[] = [];
  for (const d of arr(n.disks)) {
    if (!d?.id) continue;
    const usb = /^USBSTOR\\/i.test(d.id) || /USB/i.test(d.id.split('\\')[0]);
    items.push({ key: `disk|${d.id.toUpperCase()}`, section: 'disk', name: d.name || 'Disk', value: usb ? 'USB drive' : 'disk', usb });
  }
  // One item per keyboard product (VID/PID): the same device in another USB port gets a new instance id.
  const seenKbd = new Set<string>();
  for (const k of arr(n.keyboards)) {
    if (!k?.id) continue;
    const vp = vidPid(k.id);
    const key = vp ? `kbd|VID_${vp.vid}&PID_${vp.pid}` : `kbd|${k.id.split('\\').slice(0, 2).join('\\').toUpperCase()}`;
    if (seenKbd.has(key)) continue;
    seenKbd.add(key);
    const maker = vp ? DEV_BOARDS[vp.vid] ?? VENDORS[vp.vid] : null;
    const name = vp ? `${maker ?? 'Keyboard device'} (VID ${vp.vid} PID ${vp.pid})` : k.name || 'Keyboard';
    items.push({ key, section: 'keyboard', name, value: k.name || 'keyboard', vid: vp?.vid });
  }
  const seenWifi = new Set<string>();
  const authOf = new Map<string, WifiRow>();
  for (const w of arr(n.wifi)) {
    if (!w?.ssid) continue;
    const key = `wifi|${w.ssid}|${(w.auth ?? '').toLowerCase()}`;
    if (!authOf.has(w.ssid) || wifiRisk(w.auth, w.enc) !== 'ok') authOf.set(w.ssid, w);
    if (seenWifi.has(key)) continue;
    seenWifi.add(key);
    items.push({ key, section: 'wifi', name: w.ssid, value: `${w.auth || '?'}${w.enc ? `/${w.enc}` : ''}`, auth: w.auth, auto: w.mode !== 'manual' });
  }
  // On a password-less Wi-Fi right now: an item while connected, gone (and resolved) once off it.
  const now = n.wifiNow ?? '';
  const prof = now ? authOf.get(now) : undefined;
  if (prof && wifiRisk(prof.auth, prof.enc) !== 'ok') items.push({ key: `wifinow|${now}`, section: 'wifinow', name: now, value: prof.auth || 'open', auth: prof.auth });
  return {
    items,
    ok: {
      disk: n.disksOk !== false && n.disks != null,
      keyboard: n.keyboardsOk !== false && n.keyboards != null,
      wifi: n.wifiOk !== false && n.wifi != null,
      wifinow: n.wifiOk !== false && n.wifi != null && n.wifiNow != null,
    },
  };
}

export type PeriphReason = 'usb_drive' | 'disk' | 'keyboard' | 'keyboard_devboard' | 'keyboard_with_drive' | 'wifi_open_auto' | 'wifi_open' | 'wifi_weak' | 'wifi_ok' | 'wifinow_open';
export type PeriphVerdict = { severity: 'low' | 'medium' | 'high'; reason: PeriphReason; detail: string };

/** `newDrive`: a new USB drive showed up in the same check (a BadUSB stick is often both). */
export function judgePeriph(it: PeriphItem, ctx: { newDrive: boolean } = { newDrive: false }): PeriphVerdict {
  switch (it.section) {
    case 'disk':
      return it.usb
        ? { severity: 'medium', reason: 'usb_drive', detail: `${it.name} — a USB drive this PC has never seen was plugged in` }
        : { severity: 'low', reason: 'disk', detail: `${it.name} — a new disk` };
    case 'keyboard': {
      const board = it.vid ? DEV_BOARDS[it.vid] : undefined;
      if (board) return { severity: 'high', reason: 'keyboard_devboard', detail: `a "keyboard" made from a ${board} board — how BadUSB sticks that type commands are built` };
      if (ctx.newDrive) return { severity: 'high', reason: 'keyboard_with_drive', detail: `${it.name} appeared together with a new USB drive — BadUSB sticks show up as both` };
      return { severity: 'low', reason: 'keyboard', detail: `${it.name} — a new keyboard / mouse / gaming device` };
    }
    case 'wifi': {
      const r = wifiRisk(it.auth, it.value.split('/')[1]);
      if (r === 'open' && it.auto) return { severity: 'medium', reason: 'wifi_open_auto', detail: `"${it.name}" has no password and the PC joins it by itself` };
      if (r === 'open') return { severity: 'low', reason: 'wifi_open', detail: `"${it.name}" has no password (joined by hand only)` };
      if (r === 'weak') return { severity: 'medium', reason: 'wifi_weak', detail: `"${it.name}" uses WEP, which can be cracked in minutes` };
      return { severity: 'low', reason: 'wifi_ok', detail: `"${it.name}" (${it.value})` };
    }
    case 'wifinow':
      return { severity: 'medium', reason: 'wifinow_open', detail: `connected to "${it.name}", a Wi-Fi without a password` };
  }
}

/* ---------- baseline diff ---------- */

export type PeriphBaseline = { items: string[]; names?: Record<string, string> };
export type PeriphChange = { kind: 'added'; item: PeriphItem } | { kind: 'removed'; key: string; name: string };
export const periphSectionOf = (k: string): PeriphSection => (k.startsWith('disk|') ? 'disk' : k.startsWith('kbd|') ? 'keyboard' : k.startsWith('wifinow|') ? 'wifinow' : 'wifi');

/**
 * First run records only. Disks / keyboards stay remembered by Windows after unplugging, so "removed"
 * means really uninstalled. The current open Wi-Fi is different: it is reported even at the first run
 * (being on one is a state, not a change) and resolves when the PC leaves it.
 */
export function diffPeriph(n: PeriphSnap, base: PeriphBaseline | null): { changes: PeriphChange[]; next: PeriphBaseline; items: PeriphItem[] } {
  const { items, ok } = periphItems(n);
  const old = new Set(base?.items ?? []);
  const now = new Set(items.filter((i) => ok[i.section]).map((i) => i.key));
  const kept = [...old].filter((k) => !ok[periphSectionOf(k)]);
  const changes: PeriphChange[] = [];
  for (const it of items) {
    if (!ok[it.section] || old.has(it.key)) continue;
    if (base || it.section === 'wifinow') changes.push({ kind: 'added', item: it });
  }
  if (base) for (const k of old) if (ok[periphSectionOf(k)] && !now.has(k)) changes.push({ kind: 'removed', key: k, name: base.names?.[k] ?? k.split('|')[1] ?? k });
  const names: Record<string, string> = {};
  for (const k of kept) if (base?.names?.[k]) names[k] = base.names[k];
  for (const i of items) if (now.has(i.key)) names[i.key] = i.name;
  return { changes, next: { items: [...now, ...kept], names }, items };
}

/* ---------- messages ---------- */

type Parts = { head: string; why: string; fix: string };

export function periphMessage(it: PeriphItem, v: PeriphVerdict, asset: string): Msg {
  const forget = `Settings → Network & internet → Wi-Fi → Manage known networks → "${it.name}" → Forget`;
  const forgetTh = `Settings → Network & internet → Wi-Fi → Manage known networks → "${it.name}" → Forget`;
  const text: Record<PeriphReason, { th: Parts; en: Parts }> = {
    usb_drive: {
      th: { head: `มีคนเสียบ USB ไดรฟ์ใหม่: ${it.name}`, why: 'เครื่องนี้ไม่เคยเห็นไดรฟ์นี้มาก่อน — ถ้าไม่ใช่คุณ อาจมีคนแอบคัดลอกไฟล์หรือวางมัลแวร์', fix: 'ถ้าไม่ใช่ของคุณ: ถอดออก แล้วสแกน Quick scan และดูหน้า "โปรแกรมเริ่มอัตโนมัติ" ใน SENTINEL' },
      en: { head: `New USB drive plugged in: ${it.name}`, why: 'This PC has never seen it — if it was not you, someone may have copied files or dropped malware.', fix: "If it isn't yours: unplug it, run a Quick scan and check SENTINEL's auto-start list" },
    },
    disk: {
      th: { head: `มีดิสก์ใหม่: ${it.name}`, why: 'เครื่องเห็นดิสก์ที่ไม่เคยเห็นมาก่อน', fix: 'ถ้าไม่ได้ติดตั้งเอง: ตรวจว่าเป็นดิสก์อะไรใน Disk Management' },
      en: { head: `New disk: ${it.name}`, why: 'The PC sees a disk it has not seen before.', fix: "If you didn't add it: check it in Disk Management" },
    },
    keyboard: {
      th: { head: `มีอุปกรณ์คีย์บอร์ดใหม่: ${it.name}`, why: 'คีย์บอร์ด เมาส์ หรืออุปกรณ์เกมใหม่ (หลายรุ่นแสดงตัวเป็นคีย์บอร์ด)', fix: 'ถ้าไม่ได้เสียบเอง: ถอดอุปกรณ์ที่ไม่รู้จักออก' },
      en: { head: `New keyboard device: ${it.name}`, why: 'A new keyboard, mouse or gaming device (many show up as keyboards).', fix: "If you didn't plug it in: unplug the unknown device" },
    },
    keyboard_devboard: {
      th: { head: `อุปกรณ์ปลอมตัวเป็นคีย์บอร์ด: ${it.name}`, why: 'ทำจากบอร์ดสำหรับนักพัฒนา — แบบเดียวกับ BadUSB ที่เสียบแล้วพิมพ์คำสั่งเองได้ภายในไม่กี่วินาที', fix: 'ถอดอุปกรณ์ออกทันที ล็อกเครื่อง แล้วสแกน Full scan และดูโปรแกรมเริ่มอัตโนมัติ/งานตั้งเวลาที่เพิ่งเพิ่ม' },
      en: { head: `Device pretending to be a keyboard: ${it.name}`, why: 'Built on a developer board — like BadUSB sticks that type commands within seconds of being plugged in.', fix: 'Unplug it now, lock the PC, run a Full scan and check new auto-start entries / scheduled tasks' },
    },
    keyboard_with_drive: {
      th: { head: `คีย์บอร์ดใหม่มาพร้อม USB ไดรฟ์ใหม่: ${it.name}`, why: 'BadUSB มักแสดงตัวเป็นทั้งไดรฟ์และคีย์บอร์ดพร้อมกัน', fix: 'ถ้าไม่ได้เสียบเอง: ถอดออกทันที แล้วสแกน Full scan' },
      en: { head: `New keyboard arrived with a new USB drive: ${it.name}`, why: 'BadUSB sticks often show up as a drive and a keyboard at once.', fix: "If you didn't plug it in: unplug it now and run a Full scan" },
    },
    wifi_open_auto: {
      th: { head: `บันทึก Wi-Fi ไม่มีรหัสผ่านที่ต่ออัตโนมัติ: ${it.name}`, why: 'เครื่องจะต่อเองทุกครั้งที่เจอชื่อนี้ — คนทำ Wi-Fi ปลอมชื่อเดียวกันดักข้อมูลได้', fix: `ถ้าไม่ได้ใช้ประจำ: ${forgetTh}` },
      en: { head: `Saved password-less Wi-Fi that auto-connects: ${it.name}`, why: 'The PC joins any network with this name — a fake hotspot with the same name can watch the traffic.', fix: `If you don't use it often: ${forget}` },
    },
    wifi_open: {
      th: { head: `บันทึก Wi-Fi ไม่มีรหัสผ่าน: ${it.name}`, why: 'ต่อเองด้วยมือเท่านั้น', fix: `ถ้าไม่ได้ใช้แล้ว: ${forgetTh}` },
      en: { head: `Saved password-less Wi-Fi: ${it.name}`, why: 'Joined by hand only.', fix: `If you no longer use it: ${forget}` },
    },
    wifi_weak: {
      th: { head: `บันทึก Wi-Fi ที่ใช้ WEP: ${it.name}`, why: 'WEP ถูกเจาะได้ในไม่กี่นาที เท่ากับไม่มีรหัส', fix: `${forgetTh} และเปลี่ยนเราเตอร์เป็น WPA2/WPA3` },
      en: { head: `Saved Wi-Fi using WEP: ${it.name}`, why: 'WEP can be cracked in minutes — as good as no password.', fix: `${forget}, and switch the router to WPA2/WPA3` },
    },
    wifi_ok: {
      th: { head: `บันทึก Wi-Fi ใหม่: ${it.name}`, why: `มีรหัสผ่าน (${it.value})`, fix: 'ไม่ต้องทำอะไร' },
      en: { head: `New saved Wi-Fi: ${it.name}`, why: `Password-protected (${it.value}).`, fix: 'Nothing to do' },
    },
    wifinow_open: {
      th: { head: `กำลังต่อ Wi-Fi ที่ไม่มีรหัสผ่าน: ${it.name}`, why: 'คนในบริเวณเดียวกันดักดูหรือแก้ข้อมูลที่ไม่เข้ารหัสได้ — งดเข้าเว็บธนาคาร หรือเปิด VPN ก่อน', fix: 'เปลี่ยนไปใช้ Wi-Fi ที่มีรหัส หรือแชร์เน็ตจากมือถือ' },
      en: { head: `On a Wi-Fi without a password: ${it.name}`, why: 'People nearby can watch or tamper with unencrypted traffic — avoid banking or turn on a VPN first.', fix: 'Switch to a password-protected Wi-Fi or tether to your phone' },
    },
  };
  const p = text[v.reason];
  const icon = SEV_ICON[v.severity] ?? '🟡';
  return { th: compose(icon, p.th, asset, true), en: compose(icon, p.en, asset, false), headlineTh: p.th.head, headlineEn: p.en.head };
}

export type PeriphEvent = { kind: 'added' | 'removed'; section: PeriphSection; name: string; value: string; at: number; severity?: string; reason?: PeriphReason };
const KEEP_MS = 90 * 86_400_000;
export const trimPeriphEvents = (ev: PeriphEvent[], now: number) => ev.filter((e) => now - e.at < KEEP_MS).slice(-200);
