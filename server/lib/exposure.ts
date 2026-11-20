/**
 * Ways into this PC that the owner should know about: is UAC on, which remote-control programs are
 * installed, and which programs accept network connections from anywhere (not just this PC).
 * Pure functions over the device-health snapshot, so they can be tested without a PC.
 */

export type Uac = { enableLua: number | null; consentAdmin: number | null; secureDesktop: number | null };
export type Software = { programs: string[]; services: { name: string; display: string; path: string; state: string }[]; apps?: import('./new-programs.js').App[] };
export type Listener = { port: number; process: string; path: string };

/* ---------- UAC ---------- */

export type UacVerdict = { status: 'ok' | 'warn' | 'bad'; severity?: string; msg: string };

export function uacVerdict(u: Uac): UacVerdict {
  if (u.enableLua === 0) return { status: 'bad', severity: 'high', msg: 'UAC is turned off — any program gets administrator rights without asking' };
  if (u.consentAdmin === 0) return { status: 'bad', severity: 'high', msg: 'UAC never asks — programs are elevated silently' };
  if (u.secureDesktop === 0) return { status: 'warn', severity: 'low', msg: 'UAC prompt is not on the secure desktop' };
  return { status: 'ok', msg: 'UAC is on and asks before a program gets administrator rights' };
}

/* ---------- remote-control programs ---------- */

/**
 * Known remote-control / remote-support tools. Each regex is matched against installed program names and
 * against service names, display names and paths. Kept specific: "Docker Desktop" and browser web-app
 * shortcuts such as "Chrome Remote Desktop" (only the website, not the host) must not match.
 */
export const REMOTE_TOOLS: [string, RegExp][] = [
  ['AnyDesk', /anydesk/i],
  ['TeamViewer', /teamviewer/i],
  ['RustDesk', /rustdesk/i],
  ['HopToDesk', /hoptodesk/i],
  ['DeskIn', /deskin/i],
  ['ToDesk', /todesk/i],
  ['Radmin', /radmin/i],
  ['UltraViewer', /ultraviewer/i],
  ['Chrome Remote Desktop Host', /chrome remote desktop host|chromoting|remoting_host/i],
  ['Splashtop', /splashtop/i],
  ['Parsec', /parsec/i],
  ['VNC', /realvnc|tightvnc|ultravnc|tigervnc|vnc server|winvnc/i],
  ['LogMeIn / GoTo', /logmein|gotoassist|goto resolve|goto opener/i],
  ['ScreenConnect', /screenconnect|connectwise control/i],
  ['NetSupport', /netsupport|client32\.exe/i],
  ['Ammyy Admin', /ammyy/i],
  ['Supremo', /supremo/i],
  ['Zoho Assist', /zoho assist|zohoassist|zohomeeting/i],
  ['Atera', /\batera/i],
  ['MeshCentral', /meshagent|mesh agent/i],
  ['SimpleHelp', /simplehelp|simple-help/i],
  ['Action1', /action1/i],
  ['NoMachine', /nomachine/i],
  ['RemotePC', /remotepc/i],
  ['AeroAdmin', /aeroadmin/i],
  ['Iperius Remote', /iperius remote|iperiusremote/i],
  ['Sunlogin', /sunlogin|\boray\b/i],
  ['DWService', /dwagent|dwservice/i],
  ['Level', /level\.io|levelagent/i],
  ['BeyondTrust / Bomgar', /bomgar|beyondtrust remote/i],
];

/** Tools the owner chose to keep. Edit to match the remote tool you use on purpose. */
export const DEFAULT_TRUSTED_TOOLS = ['RustDesk'];

export type FoundTool = { name: string; where: string };

/** Which known remote tools are installed or have a service, one entry per tool. */
export function findRemoteTools(s: Software): FoundTool[] {
  const out = new Map<string, FoundTool>();
  for (const [name, re] of REMOTE_TOOLS) {
    const svc = s.services.find((x) => re.test(x.name) || re.test(x.display) || re.test(x.path));
    if (svc) {
      out.set(name, { name, where: `service ${svc.display || svc.name} (${svc.state})` });
      continue;
    }
    const prog = s.programs.find((p) => re.test(p));
    if (prog) out.set(name, { name, where: `installed: ${prog}` });
  }
  return [...out.values()];
}

/* ---------- ports open to every network ---------- */

/** Windows' own network services. They only count when they really run from the Windows folder (or are protected and hide their path). */
const WINDOWS_PROCS = new Set(['system', 'idle', 'svchost', 'lsass', 'wininit', 'services', 'spoolsv', 'searchindexer', 'msmpeng']);

/** Ports that are a way in if left open: remote control, remote shells and databases. */
export const RISKY_PORTS = new Set([21, 22, 23, 1433, 3306, 3389, 5432, 5800, 5900, 5938, 6379, 6568, 7070, 8291, 9200, 11211, 27017, 33060]);

export type OpenProgram = { key: string; process: string; path: string; ports: number[] };

/** Programs listening on all interfaces, grouped by program, Windows services left out. */
export function openPrograms(listeners: Listener[], windir = 'C:\\Windows'): OpenProgram[] {
  const byKey = new Map<string, OpenProgram>();
  const win = `${windir.toLowerCase()}\\`;
  for (const l of listeners) {
    const name = (l.process || '?').toLowerCase();
    if (WINDOWS_PROCS.has(name) && (!l.path || l.path.toLowerCase().startsWith(win))) continue;
    const key = name;
    const p = byKey.get(key) ?? { key, process: l.process || '?', path: l.path, ports: [] };
    if (!p.ports.includes(l.port)) p.ports.push(l.port);
    if (!p.path && l.path) p.path = l.path;
    byKey.set(key, p);
  }
  for (const p of byKey.values()) p.ports.sort((a, b) => a - b);
  return [...byKey.values()].sort((a, b) => a.key.localeCompare(b.key));
}

export const isRiskyListener = (p: OpenProgram) =>
  p.ports.some((n) => RISKY_PORTS.has(n)) || REMOTE_TOOLS.some(([, re]) => re.test(p.process) || re.test(p.path));

export const describeOpen = (p: OpenProgram) => `${p.process} — port ${p.ports.join(', ')}${p.path ? ` (${p.path})` : ''}`;
