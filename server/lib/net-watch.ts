import { compose, SEV_ICON, type Msg } from './device-messages.js';

/**
 * Hosts file, hand-typed DNS servers and proxies (added 2026-11-20). Malware edits these to send the
 * owner to fake bank / Google pages, to read traffic through someone else's proxy, or to block Defender
 * and Telegram (so SENTINEL can't warn). The device-health script reads them; these pure helpers turn
 * them into items, compare with the last run and judge what is new.
 */

export type NetSnap = {
  hosts?: string[] | null;
  hostsOk?: boolean;
  dns?: { iface: string; name?: string | null; servers: string[] }[] | null;
  dnsOk?: boolean;
  proxies?: { who: string; server?: string; pac?: string }[] | null;
  proxyOk?: boolean;
  winhttp?: string | null;
  nrpt?: { ns: string; servers: string[] }[] | null;
  nrptOk?: boolean;
};

export type NetKind = 'hosts' | 'dns' | 'proxy' | 'pac' | 'winhttp' | 'nrpt';
export type NetItem = { key: string; kind: NetKind; section: 'hosts' | 'dns' | 'proxy' | 'nrpt'; name: string; value: string; where?: string };

/** PowerShell turns one-element lists into a bare object. */
const arr = <T>(x: T | T[] | null | undefined): T[] => (x == null ? [] : Array.isArray(x) ? x : [x]);

const TAILSCALE_IP = /^(?:100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+|fd7a:115c:a1e0:.*)$/i;
const TAILSCALE_DNS = new Set(['100.100.100.100', 'fd7a:115c:a1e0::53']);
const LOCAL_NAMES = new Set(['localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback']);

/** Who a user hive is: the SID tail is enough to tell users apart. */
const whoLabel = (who: string) => (who === 'machine' ? 'whole PC' : who === 'policy' ? 'policy' : /^S-1-5-(18|19|20)$/.test(who) ? 'system account' : `user …${who.slice(-4)}`);

export function netItems(n: NetSnap): { items: NetItem[]; ok: Record<NetItem['section'], boolean> } {
  const items: NetItem[] = [];
  for (const line of arr(n.hosts)) {
    const [ip, ...names] = String(line).trim().split(/\s+/);
    if (!ip) continue;
    for (const raw of names) {
      const name = raw.toLowerCase().replace(/\.$/, '');
      if (LOCAL_NAMES.has(name)) continue;
      // Tailscale writes its own peers here (e.g. the phone); they change whenever a device is added.
      if (TAILSCALE_IP.test(ip) && !importantDomain(name)) continue;
      items.push({ key: `hosts|${name}|${ip}`, kind: 'hosts', section: 'hosts', name, value: ip });
    }
  }
  for (const d of arr(n.dns))
    for (const s of arr(d.servers)) items.push({ key: `dns|${d.iface}|${s}`, kind: 'dns', section: 'dns', name: d.name || 'network adapter', value: s, where: d.iface });
  for (const p of arr(n.proxies)) {
    if (p.server) items.push({ key: `proxy|${p.who}|${p.server}`, kind: 'proxy', section: 'proxy', name: whoLabel(p.who), value: p.server, where: p.who });
    if (p.pac) items.push({ key: `pac|${p.who}|${p.pac}`, kind: 'pac', section: 'proxy', name: whoLabel(p.who), value: p.pac, where: p.who });
  }
  if (n.winhttp) items.push({ key: `winhttp|${n.winhttp}`, kind: 'winhttp', section: 'proxy', name: 'Windows services (WinHTTP)', value: n.winhttp });
  for (const r of arr(n.nrpt)) {
    const servers = arr(r.servers).map(String);
    if (servers.length && servers.every((s) => TAILSCALE_DNS.has(s))) continue;
    items.push({ key: `nrpt|${r.ns}|${servers.join(',')}`, kind: 'nrpt', section: 'nrpt', name: r.ns, value: servers.join(', ') || '(none)' });
  }
  return {
    items,
    ok: { hosts: n.hostsOk !== false && n.hosts != null, dns: n.dnsOk !== false && n.dns != null, proxy: n.proxyOk !== false && n.proxies != null && n.winhttp !== null, nrpt: n.nrptOk !== false && n.nrpt != null },
  };
}

/** Sites worth faking or blocking: banks, mail, cloud, security updates, and Telegram (SENTINEL's alerts). */
const IMPORTANT = [
  'google.com', 'gmail.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'windows.com', 'windowsupdate.com', 'msftncsi.com', 'bing.com',
  'apple.com', 'icloud.com', 'facebook.com', 'instagram.com', 'line.me', 'naver.jp', 'github.com', 'githubusercontent.com', 'paypal.com', 'binance.com', 'bitkub.com', 'kasikornbank.com', 'kbank.co.th', 'scb.co.th', 'krungthai.com', 'bangkokbank.com', 'krungsri.com', 'ttbbank.com', 'gsb.or.th', 'truemoney.com',
  'shopee.co.th', 'lazada.co.th', 'vercel.com', 'vercel.app', 'supabase.co', 'supabase.com', 'anthropic.com', 'claude.ai', 'telegram.org', 't.me', 'tailscale.com', 'discord.com', 'steampowered.com', 'steamcommunity.com',
  'virustotal.com', 'malwarebytes.com', 'kaspersky.com', 'eset.com', 'avast.com', 'bitdefender.com', 'mcafee.com', 'norton.com', 'trendmicro.com',
];
export function importantDomain(name: string): string | null {
  const n = name.toLowerCase().replace(/\.$/, '');
  return IMPORTANT.find((d) => n === d || n.endsWith(`.${d}`)) ?? null;
}

const BLOCK_IP = /^(?:0\.0\.0\.0|127\.\d+\.\d+\.\d+|::1?|0:0:0:0:0:0:0:[01])$/;
const LOOPBACK = /^(?:127\.\d+\.\d+\.\d+|::1|localhost)(?::\d+)?$/i;
const PRIVATE = /^(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|fe80:.*|f[cd][0-9a-f]{2}:.*|fec0:.*)$/i;
/** Well-known public resolvers (Google, Cloudflare, Quad9, OpenDNS, AdGuard). */
const PUBLIC_DNS = new Set([
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15',
  '2001:4860:4860::8888', '2001:4860:4860::8844', '2606:4700:4700::1111', '2606:4700:4700::1001', '2620:fe::fe', '2620:fe::9',
]);

export type NetVerdict = { severity: 'low' | 'medium' | 'high'; reason: 'redirect' | 'block' | 'hosts_other' | 'hosts_blocklist' | 'dns_public' | 'dns_local' | 'dns_unknown' | 'proxy_local' | 'proxy_remote' | 'nrpt'; detail: string };

/** Host part of a proxy setting like `http=1.2.3.4:8080;https=…` or a PAC URL. */
const proxyHost = (v: string) => {
  const first = v.split(';')[0].replace(/^[a-z]+=/i, '');
  try {
    return /^[a-z]+:\/\//i.test(first) ? new URL(first).host : first;
  } catch {
    return first;
  }
};

export function judgeNet(it: NetItem): NetVerdict {
  switch (it.kind) {
    case 'hosts': {
      const imp = importantDomain(it.name);
      const blocked = BLOCK_IP.test(it.value);
      if (imp && blocked) return { severity: 'high', reason: 'block', detail: `${it.name} is blocked (sent to ${it.value})` };
      if (imp) return { severity: 'high', reason: 'redirect', detail: `${it.name} is sent to ${it.value} instead of the real site` };
      if (blocked) return { severity: 'low', reason: 'hosts_blocklist', detail: `${it.name} is blocked (ad/tracker list style)` };
      return { severity: 'medium', reason: 'hosts_other', detail: `${it.name} is sent to ${it.value}` };
    }
    case 'dns':
      if (PUBLIC_DNS.has(it.value)) return { severity: 'low', reason: 'dns_public', detail: `${it.value} is a well-known public DNS` };
      if (LOOPBACK.test(it.value) || PRIVATE.test(it.value)) return { severity: 'medium', reason: 'dns_local', detail: `${it.value} is a program or device on this PC / network` };
      return { severity: 'high', reason: 'dns_unknown', detail: `${it.value} is not a known public DNS` };
    case 'proxy':
    case 'pac':
    case 'winhttp': {
      const host = it.kind === 'pac' ? proxyHost(it.value) : proxyHost(it.value);
      if (LOOPBACK.test(host) || /^file:/i.test(it.value)) return { severity: 'medium', reason: 'proxy_local', detail: `${it.value} is a program on this PC (VPN, debugging proxy…)` };
      return { severity: 'high', reason: 'proxy_remote', detail: `web traffic goes through ${host}` };
    }
    case 'nrpt':
      return { severity: 'high', reason: 'nrpt', detail: `names ${it.name} are looked up at ${it.value}` };
  }
}

/** Baseline: what each section looked like last time it was read. */
export type NetBaseline = { items: string[] };
export type NetChange = { kind: 'added'; item: NetItem; verdict: NetVerdict } | { kind: 'removed'; key: string };

/** First run records only. Sections that could not be read keep their old items and report nothing. */
export function diffNet(n: NetSnap, base: NetBaseline | null): { changes: NetChange[]; next: NetBaseline; items: NetItem[] } {
  const { items, ok } = netItems(n);
  const sectionOf = (k: string) => (k.startsWith('hosts|') ? 'hosts' : k.startsWith('dns|') ? 'dns' : k.startsWith('nrpt|') ? 'nrpt' : 'proxy');
  const old = new Set(base?.items ?? []);
  const now = new Set(items.filter((i) => ok[i.section]).map((i) => i.key));
  const kept = [...old].filter((k) => !ok[sectionOf(k)]);
  const changes: NetChange[] = [];
  if (base) {
    for (const it of items) if (ok[it.section] && !old.has(it.key)) changes.push({ kind: 'added', item: it, verdict: judgeNet(it) });
    for (const k of old) if (ok[sectionOf(k)] && !now.has(k)) changes.push({ kind: 'removed', key: k });
  }
  return { changes, next: { items: [...now, ...kept] }, items };
}

const HOSTS_PATH = 'C:\\Windows\\System32\\drivers\\etc\\hosts';

export function netMessage(it: NetItem, v: NetVerdict, asset: string): Msg {
  const hostsFixTh = `เปิด Notepad แบบ Run as administrator → File → Open → ${HOSTS_PATH} → ลบบรรทัด "${it.value} ${it.name}" → Save แล้วสแกน Full scan`;
  const hostsFixEn = `Open Notepad as administrator → File → Open → ${HOSTS_PATH} → delete the line "${it.value} ${it.name}" → Save, then run a Full scan`;
  const dnsFixTh = `Settings → Network & internet → ${it.name} → DNS server assignment → Edit → Automatic (DHCP)`;
  const dnsFixEn = `Settings → Network & internet → ${it.name} → DNS server assignment → Edit → Automatic (DHCP)`;
  const proxyFixTh = it.kind === 'winhttp' ? 'เปิด Terminal (Admin) แล้วพิมพ์ netsh winhttp reset proxy' : 'Settings → Network & internet → Proxy → ปิด "Use a proxy server" และ "Use setup script"';
  const proxyFixEn = it.kind === 'winhttp' ? 'Open Terminal (Admin) and run: netsh winhttp reset proxy' : 'Settings → Network & internet → Proxy → turn off "Use a proxy server" and "Use setup script"';
  const parts: Record<NetVerdict['reason'], { th: { head: string; why: string; fix: string }; en: { head: string; why: string; fix: string } }> = {
    redirect: {
      th: { head: `ไฟล์ hosts ส่ง ${it.name} ไปที่อื่น`, why: `${it.name} ถูกชี้ไปที่ ${it.value} แทนเว็บจริง — วิธีที่ใช้พาไปหน้าล็อกอินปลอม`, fix: hostsFixTh },
      en: { head: `Hosts file sends ${it.name} elsewhere`, why: `${it.name} now goes to ${it.value} instead of the real site — the trick behind fake login pages.`, fix: hostsFixEn },
    },
    block: {
      th: { head: `ไฟล์ hosts บล็อก ${it.name}`, why: 'มัลแวร์ชอบบล็อกเว็บอัปเดตความปลอดภัย แอนติไวรัส หรือ Telegram เพื่อไม่ให้ถูกจับหรือแจ้งเตือน', fix: hostsFixTh },
      en: { head: `Hosts file blocks ${it.name}`, why: 'Malware blocks security updates, antivirus sites or Telegram so it is not caught or reported.', fix: hostsFixEn },
    },
    hosts_other: {
      th: { head: `มีบรรทัดใหม่ในไฟล์ hosts: ${it.name}`, why: `${it.name} ถูกชี้ไปที่ ${it.value} — ถ้าไม่ได้เพิ่มเอง (เช่นตอนทำเว็บ) ถือว่าผิดปกติ`, fix: `ถ้าไม่ได้เพิ่มเอง: ${hostsFixTh}` },
      en: { head: `New line in the hosts file: ${it.name}`, why: `${it.name} now goes to ${it.value} — unusual unless you added it (e.g. for web development).`, fix: `If you didn't add it: ${hostsFixEn}` },
    },
    hosts_blocklist: {
      th: { head: `ไฟล์ hosts บล็อก ${it.name}`, why: 'ลักษณะเหมือนรายการบล็อกโฆษณา', fix: `ถ้าไม่ได้เพิ่มเอง: ${hostsFixTh}` },
      en: { head: `Hosts file blocks ${it.name}`, why: 'Looks like an ad/tracker block list.', fix: `If you didn't add it: ${hostsFixEn}` },
    },
    dns_public: {
      th: { head: `ตั้ง DNS เองที่ ${it.name}: ${it.value}`, why: 'เป็น DNS สาธารณะที่รู้จัก (Google/Cloudflare/Quad9…) ปลอดภัย', fix: `ถ้าไม่ได้ตั้งเอง: ${dnsFixTh}` },
      en: { head: `DNS set by hand on ${it.name}: ${it.value}`, why: 'A well-known public DNS (Google/Cloudflare/Quad9…), safe.', fix: `If you didn't set it: ${dnsFixEn}` },
    },
    dns_local: {
      th: { head: `DNS ของ ${it.name} ถูกตั้งเป็น ${it.value}`, why: 'ชี้ไปที่โปรแกรมบนเครื่องหรืออุปกรณ์ในบ้าน — ปกติถ้าคุณใช้ VPN หรือตัวกรองโฆษณา', fix: `ถ้าไม่ได้ตั้งเอง: ${dnsFixTh}` },
      en: { head: `DNS of ${it.name} set to ${it.value}`, why: 'Points to a program on this PC or a device at home — normal for some VPNs or ad filters.', fix: `If you didn't set it: ${dnsFixEn}` },
    },
    dns_unknown: {
      th: { head: `DNS ของ ${it.name} ถูกเปลี่ยนเป็น ${it.value}`, why: 'ไม่ใช่ DNS สาธารณะที่รู้จัก — DNS ปลอมพาไปเว็บธนาคาร/Google ปลอมได้ทุกเว็บ', fix: `${dnsFixTh} แล้วสแกน Full scan` },
      en: { head: `DNS of ${it.name} changed to ${it.value}`, why: 'Not a known public DNS — a rogue DNS can send any site (bank, Google) to a fake one.', fix: `${dnsFixEn}, then run a Full scan` },
    },
    proxy_local: {
      th: { head: `เปิด proxy ผ่านโปรแกรมบนเครื่อง (${it.name})`, why: `${it.value} — ปกติถ้าคุณใช้ VPN หรือเครื่องมือดักเว็บ (เช่น Fiddler)`, fix: `ถ้าไม่ได้ตั้งเอง: ${proxyFixTh}` },
      en: { head: `Proxy through a program on this PC (${it.name})`, why: `${it.value} — normal for some VPNs or debugging tools (e.g. Fiddler).`, fix: `If you didn't set it: ${proxyFixEn}` },
    },
    proxy_remote: {
      th: { head: `เว็บทั้งหมดถูกส่งผ่าน proxy (${it.name})`, why: `ทราฟฟิกผ่าน ${it.value} — คนคุม proxy เห็นและแก้ข้อมูลเว็บได้`, fix: `${proxyFixTh} แล้วสแกน Full scan` },
      en: { head: `Web traffic sent through a proxy (${it.name})`, why: `Traffic goes through ${it.value} — whoever runs it can see and change web pages.`, fix: `${proxyFixEn}, then run a Full scan` },
    },
    nrpt: {
      th: { head: 'มีกฎ DNS พิเศษใหม่ (NRPT)', why: `ชื่อ ${it.name} ถูกส่งไปถามที่ ${it.value} — เครื่องส่วนตัวปกติมีแค่ของ Tailscale`, fix: 'แจ้งผมให้ตรวจ หรือเปิด PowerShell (Admin) → Get-DnsClientNrptRule ดูว่ามาจากโปรแกรมไหน' },
      en: { head: 'New DNS rule (NRPT)', why: `Names ${it.name} are looked up at ${it.value} — a personal PC normally has only Tailscale's.`, fix: 'Open PowerShell (Admin) → Get-DnsClientNrptRule to see which program added it' },
    },
  };
  const p = parts[v.reason];
  const icon = SEV_ICON[v.severity] ?? '🟡';
  return { th: compose(icon, p.th, asset, true), en: compose(icon, p.en, asset, false), headlineTh: p.th.head, headlineEn: p.en.head };
}

export type NetEvent = { kind: 'added' | 'removed'; what: NetKind; name: string; value: string; at: number; severity?: string; reason?: NetVerdict['reason'] };
const KEEP_MS = 90 * 86_400_000;
export const trimNetEvents = (ev: NetEvent[], now: number) => ev.filter((e) => now - e.at < KEEP_MS).slice(-200);
export const keyParts = (k: string): { what: NetKind; name: string; value: string } => {
  const [what, a, ...rest] = k.split('|');
  return { what: what as NetKind, name: a ?? '', value: rest.join('|') };
};
