import { useState } from 'react';
import { ScanCard } from '../components/ScanCard';
import { ThreatCard } from '../components/ThreatCard';
import { Button, Card, Empty, ErrorNote, PageHeader, SevBadge } from '../components/ui';
import { api, findingText, type PlainText } from '../lib/api';
import { ago } from '../lib/format';
import { getLang, t } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';

type Check = { id: string; status: 'ok' | 'warn' | 'bad' | 'unknown'; severity?: string; msg: string; vars?: Record<string, string | number>; items?: string[] };
type TailDevice = { name: string; os: string; online: boolean; lastSeen: string | null; self: boolean };
type Latest = {
  at: number;
  isAdmin: boolean;
  checks: Check[];
  persistence: { startup: number; tasks: number; baselineAt: number | null };
  devices: TailDevice[] | null;
  programs?: { count: number; baselineAt: number | null; added: number } | null;
  extensions?: { count: number; baselineAt: number | null; added: number; list: InstalledExt[] } | null;
  system?: SysSummary | null;
  peripherals?: PeriphSummary | null;
  network?: { baselineAt: number | null; added: number; hosts: { name: string; ip: string }[]; dns: { name: string; servers: string[] }[]; proxies: { name: string; value: string }[]; rules: { name: string; value: string }[] } | null;
};
type NetEvent = { kind: 'added' | 'removed'; what: string; name: string; value: string; at: number; severity?: string };
type SysSummary = {
  baselineAt: number | null;
  added: number;
  certs: { total: number; added: number; byHand: { name: string; store: string; until?: string }[] };
  firewall: { total: number; open: number };
  settings: { id: string; name: string }[];
  readable: { cert: boolean; firewall: boolean; setting: boolean };
};
type PeriphSummary = { baselineAt: number | null; added: number; usbDrives: number; disks: number; keyboards: number; wifi: { saved: number; openAuto: string[]; now: string | null; nowOpen: boolean } };
type PeriphEvent = { kind: 'added' | 'removed'; section: 'disk' | 'keyboard' | 'wifi' | 'wifinow'; name: string; value: string; at: number; severity?: string };
type SysEvent = { kind: 'added' | 'removed'; section: 'cert' | 'firewall' | 'setting'; name: string; value: string; at: number; severity?: string };
type InstalledExt = { browser: string; profile: string; id: string; name: string; version?: string; severity: string; reason: string; powers: string[] };
type ExtEvent = { kind: 'added' | 'removed' | 'gained'; name: string; browser: string; at: number; severity?: string; reason?: string; powers?: string[] };
type ProgramEvent = { kind: 'added' | 'removed'; name: string; version?: string; publisher?: string; at: number; severity?: string; reason?: string; signer?: string };
type Resp = {
  latest: Latest | null;
  labels: Record<string, string>;
  findings: { id: number; ruleId: string; severity: string; title: string; summary: string; lastSeen: number; plainTh?: PlainText | null }[];
  recentPrograms?: ProgramEvent[];
  recentExtensions?: ExtEvent[];
  recentNetwork?: NetEvent[];
  recentSystem?: SysEvent[];
  recentPeripherals?: PeriphEvent[];
  everyMs: number;
  running: boolean;
};

const TONE: Record<Check['status'], { dot: string; text: string; label: string }> = {
  ok: { dot: 'bg-ok', text: 'text-ok', label: 'OK' },
  warn: { dot: 'bg-warn', text: 'text-warn', label: 'Needs attention' },
  bad: { dot: 'bg-bad', text: 'text-bad', label: 'Problem' },
  unknown: { dot: 'bg-muted', text: 'text-muted', label: 'Unknown' },
};

/** What to do about each check, in the admin's words. Shown only when the check is not OK. */
const FIX: Record<string, string> = {
  defender_av: 'Windows Security → Virus & threat protection → Manage settings → turn Real-time protection on.',
  defender_signatures: 'Windows Security → Virus & threat protection → Protection updates → Check for updates.',
  defender_exclusions: 'Windows Security → Virus & threat protection → Manage settings → Exclusions → remove every entry you did not add yourself. Then run a Microsoft Defender Offline scan.',
  defender_scan: 'Windows Security → Virus & threat protection → Quick scan.',
  firewall: 'Windows Security → Firewall & network protection → turn the firewall on for each network type.',
  updates: 'Settings → Windows Update → install updates and restart.',
  encryption: 'Settings → Privacy & security → Device encryption (Windows Home) or BitLocker (Pro).',
  disks: 'Back up important files now and plan to replace the disk.',
  battery: 'Normal ageing. Replace the battery when runtime is no longer enough.',
  uac: 'Start → type UAC → Change User Account Control settings → third notch from the bottom → OK, then restart.',
  remote_tools: 'Not yours? Settings → Apps → Installed apps → Uninstall it. Yours? Security Center → open the finding → Resolve, and it is remembered as approved.',
  open_ports: 'Not used? Stop or uninstall that program. Yours? Security Center → open the finding → Resolve, and it will not alert again.',
};

const IOS_TIPS = [
  'Updates on: Settings → General → Software Update → Automatic Updates (including Security Responses).',
  'Use a 6-digit or longer passcode with Face ID / Touch ID: Settings → Face ID & Passcode.',
  'iPhone: turn on Stolen Device Protection in Settings → Face ID & Passcode.',
  'Remove profiles you did not install (they can add a root certificate or a proxy): Settings → General → VPN & Device Management.',
  'Apple Account: Settings → your name → Sign-In & Security → two-factor on; remove devices you do not know.',
  'Run Safety Check: Settings → Privacy & Security → Safety Check → review who and which apps have access.',
  'Find My on: Settings → your name → Find My → Find My iPhone / iPad.',
  'To open SENTINEL: install Tailscale from the App Store, sign in with the same account, then Safari → Share → Add to Home Screen.',
];

const ANDROID_TIPS = [
  'Play Protect on: Play Store → profile → Play Protect → Scan.',
  'Install system updates: Settings → System → Software update (and Google Play system update).',
  'Install apps only from the Play Store; turn off "Install unknown apps" for browsers and chat apps.',
  'Review apps with Accessibility or Device admin access — malware abuses these.',
  'Screen lock + Find My Device on, so a lost phone can be locked or wiped.',
];

const fill = (msg: string, vars?: Record<string, string | number>) => t(msg, vars as Record<string, string | number> | undefined);

function CheckRow({ c, label }: { c: Check; label: string }) {
  const [open, setOpen] = useState(c.status === 'bad');
  const tone = TONE[c.status];
  return (
    <li className="py-3">
      <button type="button" className="flex w-full items-start gap-3 text-left" onClick={() => setOpen(!open)}>
        <span className={`mt-1.5 size-2.5 shrink-0 rounded-full ${tone.dot}`} />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{t(label)}</span>
            <span className={`text-xs ${tone.text}`}>{t(tone.label)}</span>
            {c.severity && c.status !== 'ok' && <SevBadge sev={c.severity} />}
          </span>
          <span className="block text-sm text-muted">{fill(c.msg, c.vars)}</span>
        </span>
        {(c.items?.length || (c.status !== 'ok' && FIX[c.id])) && <span className="text-xs text-muted">{open ? '▲' : '▼'}</span>}
      </button>
      {open && (
        <div className="ml-5.5 mt-2 space-y-2 pl-0.5 text-xs">
          {c.items && c.items.length > 0 && (
            <ul className="space-y-1">
              {c.items.map((x, i) => (
                <li key={i} className={`break-all rounded bg-panel-2 px-2.5 py-1.5 ${x.startsWith('⚠') ? 'text-bad' : 'text-muted'}`}>
                  {x}
                </li>
              ))}
            </ul>
          )}
          {c.status !== 'ok' && c.status !== 'unknown' && FIX[c.id] && (
            <p className="rounded-lg border border-line px-2.5 py-2">
              <span className="font-medium">{t('How to fix')}: </span>
              {t(FIX[c.id])}
            </p>
          )}
        </div>
      )}
    </li>
  );
}

const REASON: Record<string, string> = {
  crack: 'Looks like cracked software',
  tampered: 'File modified after signing',
  unsigned: 'Not signed',
  signed: 'Signed by {who}',
  unknown: 'Signature not checked',
};

const EXT_REASON: Record<string, string> = {
  sideloaded: 'Not from the Web Store',
  policy: 'Forced in by a policy',
  powerful: 'Broad permissions',
  gained: 'Gained permissions in an update',
  store: 'From the Web Store',
};
const powers = (p: string[] | undefined) => (p ?? []).map((x) => t(`power.${x}`)).join(', ');
const SEV_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };

function FindingList({ findings, go }: { findings: Resp['findings']; go: (p: string) => void }) {
  if (!findings.length) return null;
  return (
    <ul className="mb-3 divide-y divide-line rounded-lg border border-line">
      {findings.map((f) => (
        <li key={f.id}>
          <button type="button" className="flex w-full items-start gap-3 px-3 py-2.5 text-left hover:bg-panel-2/60" onClick={() => go(`security/${f.id}`)}>
            <SevBadge sev={f.severity} />
            <span className="min-w-0 flex-1">
              <span className="block text-sm">{findingText(f, getLang()).title}</span>
              <span className="block truncate text-xs text-muted">{findingText(f, getLang()).summary}</span>
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

const NET_WHAT: Record<string, string> = { hosts: 'hosts file', dns: 'DNS', proxy: 'Proxy', pac: 'Proxy script (PAC)', winhttp: 'WinHTTP proxy', nrpt: 'DNS rule (NRPT)' };

/** Hosts file, DNS servers typed in by hand and proxies: what is set now and what changed lately. */
function NetworkCard({ l, events, findings, go }: { l: Latest; events: NetEvent[]; findings: Resp['findings']; go: (p: string) => void }) {
  const n = l.network;
  const row = (label: string, value: string) => (
    <li className="flex items-start justify-between gap-3 py-1.5">
      <span className="text-muted">{label}</span>
      <span className="min-w-0 break-words text-right">{value}</span>
    </li>
  );
  return (
    <Card title={`🌐 ${t('Hosts file, DNS and proxy')}`}>
      <p className="mb-3 text-xs text-muted">
        {n ? t('Watched every 30 minutes. Faking or blocking a bank, Google, Microsoft, Defender or Telegram, an unknown DNS or a proxy on another machine → high. Tailscale\'s own entries are ignored.') : t('Not read yet.')}
        {n?.baselineAt && ` ${t('Baseline taken {when}.', { when: ago(n.baselineAt) })}`}
      </p>
      <FindingList findings={findings} go={go} />
      {n && (
        <ul className="mb-3 divide-y divide-line text-sm">
          {row(t('hosts file'), n.hosts.length ? t('{n} extra lines', { n: n.hosts.length }) : t('Only Tailscale / localhost'))}
          {n.dns.length ? n.dns.map((d) => <span key={d.name}>{row(`DNS · ${d.name === 'network adapter' ? t('network adapter') : d.name}`, d.servers.join(', '))}</span>) : row('DNS', t('Automatic (from the network)'))}
          {n.proxies.length ? n.proxies.map((p) => <span key={p.name + p.value}>{row(`Proxy · ${p.name}`, p.value)}</span>) : row('Proxy', t('None'))}
          {n.rules.map((r) => <span key={r.name}>{row(`NRPT · ${r.name}`, r.value)}</span>)}
        </ul>
      )}
      {events.length > 0 && (
        <>
          <p className="mb-1 text-xs font-medium text-muted">{t('Last 30 days')}</p>
          <ul className="divide-y divide-line text-sm">
            {events.map((e, i) => (
              <li key={i} className="flex items-start gap-2 py-2">
                <span>{e.kind === 'removed' ? '🗑️' : e.severity === 'high' ? '🟠' : e.severity === 'medium' ? '🟡' : '🆕'}</span>
                <span className="min-w-0 flex-1 break-words">
                  {t(NET_WHAT[e.what] ?? e.what)}: {e.what === 'hosts' ? `${e.name} → ${e.value}` : e.value}
                  <span className="block text-xs text-muted">{e.kind === 'removed' ? t('Removed') : e.name}</span>
                </span>
                <span className="whitespace-nowrap text-xs text-muted">{ago(e.at)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

const PER_WHAT: Record<PeriphEvent['section'], string> = { disk: 'Drive', keyboard: 'Keyboard device', wifi: 'Saved Wi-Fi', wifinow: 'Open Wi-Fi' };

/** USB drives ever plugged in, keyboard devices and Wi-Fi networks. */
function PeripheralsCard({ l, events, findings, go }: { l: Latest; events: PeriphEvent[]; findings: Resp['findings']; go: (p: string) => void }) {
  const p = l.peripherals;
  const row = (label: string, value: string, warn = false) => (
    <li className="flex items-start justify-between gap-3 py-1.5">
      <span className="text-muted">{label}</span>
      <span className={`min-w-0 break-words text-right ${warn ? 'text-warn' : ''}`}>{value}</span>
    </li>
  );
  return (
    <Card title={`🔌 ${t('USB drives, keyboards and Wi-Fi')}`}>
      <p className="mb-3 text-xs text-muted">
        {p ? t('Watched every 30 minutes. A new USB drive or being on a Wi-Fi without a password → medium; a "keyboard" made from a developer board or arriving with a new drive (BadUSB) → high.') : t('Not read yet.')}
        {p?.baselineAt && ` ${t('Baseline taken {when}.', { when: ago(p.baselineAt) })}`}
      </p>
      <FindingList findings={findings} go={go} />
      {p && (
        <ul className="mb-3 divide-y divide-line text-sm">
          {row(t('USB drives ever plugged in'), String(p.usbDrives))}
          {row(t('Disks'), String(p.disks))}
          {row(t('Keyboard devices'), String(p.keyboards))}
          {row(t('Wi-Fi now'), p.wifi.now ? `${p.wifi.now}${p.wifi.nowOpen ? ` · ${t('no password')}` : ''}` : p.wifi.now === '' ? t('Not on Wi-Fi') : t('Could not read'), p.wifi.nowOpen)}
          {row(t('Saved Wi-Fi networks'), String(p.wifi.saved))}
          {p.wifi.openAuto.length > 0 && row(t('No password, joins by itself'), p.wifi.openAuto.join(', '), true)}
        </ul>
      )}
      {events.length > 0 && (
        <>
          <p className="mb-1 text-xs font-medium text-muted">{t('Last 30 days')}</p>
          <ul className="divide-y divide-line text-sm">
            {events.map((e, i) => (
              <li key={i} className="flex items-start gap-2 py-2">
                <span>{e.kind === 'removed' ? '🗑️' : e.severity === 'high' ? '🟠' : e.severity === 'medium' ? '🟡' : '🆕'}</span>
                <span className="min-w-0 flex-1 break-words">
                  {t(PER_WHAT[e.section] ?? e.section)}: {e.name}
                  <span className="block text-xs text-muted">{e.kind === 'removed' ? t('Removed') : e.section === 'disk' ? t(e.value === 'USB drive' ? 'USB drive' : 'Disk') : e.value}</span>
                </span>
                <span className="whitespace-nowrap text-xs text-muted">{ago(e.at)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

const SYS_WHAT: Record<SysEvent['section'], string> = { cert: 'Root certificate', firewall: 'Firewall rule', setting: 'Security setting' };
const STORE_LABEL: Record<string, string> = { machine: 'whole PC', user: 'this user only', policy: 'set by policy', enterprise: 'enterprise store', authroot: 'Windows root update' };

/** Trusted root certificates, inbound firewall allow rules and risky security switches. */
function SystemCard({ l, events, findings, go }: { l: Latest; events: SysEvent[]; findings: Resp['findings']; go: (p: string) => void }) {
  const s = l.system;
  const row = (label: string, value: string, warn = false) => (
    <li className="flex items-start justify-between gap-3 py-1.5">
      <span className="text-muted">{label}</span>
      <span className={`min-w-0 break-words text-right ${warn ? 'text-warn' : ''}`}>{value}</span>
    </li>
  );
  return (
    <Card title={`🛡️ ${t('Certificates, firewall and security settings')}`}>
      <p className="mb-3 text-xs text-muted">
        {s ? t('Watched every 30 minutes. An unknown root certificate, a firewall rule for a program in a temp folder or for any program on every port, Remote Desktop, WDigest or the Guest account turned on → high.') : t('Not read yet.')}
        {s?.baselineAt && ` ${t('Baseline taken {when}.', { when: ago(s.baselineAt) })}`}
      </p>
      <FindingList findings={findings} go={go} />
      {s && (
        <ul className="mb-3 divide-y divide-line text-sm">
          {row(t('Root certificates'), s.readable.cert ? t('{n} trusted · {m} added outside Windows\' own list', { n: s.certs.total, m: s.certs.added }) : t('Could not read'))}
          {row(t('Firewall: inbound allow rules'), s.readable.firewall ? t('{n} rules · {m} from programs', { n: s.firewall.total, m: s.firewall.open }) : t('Could not read'))}
          {s.readable.setting
            ? s.settings.length
              ? s.settings.map((x) => <span key={x.id}>{row(t('Security setting'), t(x.name), true)}</span>)
              : row(t('Security settings'), t('All safe'))
            : row(t('Security settings'), t('Could not read'))}
        </ul>
      )}
      {s && s.certs.byHand.length > 0 && (
        <details className="mb-3 text-sm">
          <summary className="cursor-pointer text-xs text-muted">{t('Root certificates added outside Windows\' own list ({n})', { n: s.certs.byHand.length })}</summary>
          <ul className="mt-1 divide-y divide-line">
            {s.certs.byHand.map((c, i) => (
              <li key={i} className="py-1.5">
                <span className="break-words">{c.name}</span>
                <span className="block text-xs text-muted">{[t(STORE_LABEL[c.store] ?? c.store), c.until ? t('valid until {date}', { date: c.until }) : null].filter(Boolean).join(' · ')}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
      {events.length > 0 && (
        <>
          <p className="mb-1 text-xs font-medium text-muted">{t('Last 30 days')}</p>
          <ul className="divide-y divide-line text-sm">
            {events.map((e, i) => (
              <li key={i} className="flex items-start gap-2 py-2">
                <span>{e.kind === 'removed' ? '🗑️' : e.severity === 'high' ? '🟠' : e.severity === 'medium' ? '🟡' : '🆕'}</span>
                <span className="min-w-0 flex-1 break-words">
                  {t(SYS_WHAT[e.section] ?? e.section)}: {e.section === 'setting' ? t(e.name) : e.name}
                  <span className="block text-xs text-muted">{e.kind === 'removed' ? t('Removed') : e.section === 'cert' ? t(STORE_LABEL[e.value] ?? e.value) : e.section === 'firewall' ? e.value : t('Turned on')}</span>
                </span>
                <span className="whitespace-nowrap text-xs text-muted">{ago(e.at)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

/** Extensions in every Chromium browser on the PC, what changed lately, and open findings about them. */
function ExtensionsCard({ l, events, findings, go }: { l: Latest; events: ExtEvent[]; findings: Resp['findings']; go: (p: string) => void }) {
  const list = [...(l.extensions?.list ?? [])].sort((a, b) => (SEV_ORDER[a.severity] ?? 3) - (SEV_ORDER[b.severity] ?? 3) || a.name.localeCompare(b.name));
  return (
    <Card title={`🧩 ${t('Browser extensions')}`}>
      <p className="mb-3 text-xs text-muted">
        {l.extensions
          ? t('{n} extensions in Chrome, Brave, Edge, Vivaldi and Opera are watched. A new one, or an update that adds powers, is checked: not from the Web Store → high; access to every site or risky permissions → medium; anything else → low (no message).', { n: l.extensions.count })
          : t('Browser extensions have not been read yet.')}
        {l.extensions?.baselineAt && ` ${t('Baseline taken {when}.', { when: ago(l.extensions.baselineAt) })}`}
      </p>
      <FindingList findings={findings} go={go} />
      {list.length > 0 && (
        <ul className="mb-3 divide-y divide-line text-sm">
          {list.map((e) => (
            <li key={`${e.browser}|${e.profile}|${e.id}`} className="flex items-start gap-2 py-2">
              <span>{e.severity === 'high' ? '🟠' : e.severity === 'medium' ? '🟡' : '🧩'}</span>
              <span className="min-w-0 flex-1">
                <span className="break-words">{e.name}</span>
                <span className="block text-xs text-muted">
                  {[`${e.browser}${e.profile !== 'Default' ? ` · ${e.profile}` : ''}`, t(EXT_REASON[e.reason] ?? e.reason), e.powers.length ? powers(e.powers) : null].filter(Boolean).join(' · ')}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
      {events.length > 0 && (
        <>
          <p className="mb-1 text-xs font-medium text-muted">{t('Last 30 days')}</p>
          <ul className="divide-y divide-line text-sm">
            {events.map((e, i) => (
              <li key={i} className="flex items-start gap-2 py-2">
                <span>{e.kind === 'removed' ? '🗑️' : e.severity === 'high' ? '🟠' : e.severity === 'medium' ? '🟡' : '🆕'}</span>
                <span className="min-w-0 flex-1">
                  <span className="break-words">{e.name}</span>
                  <span className="block text-xs text-muted">
                    {[e.browser, e.kind === 'removed' ? t('Removed') : t(EXT_REASON[e.reason ?? ''] ?? e.reason ?? ''), e.kind !== 'removed' && e.powers?.length ? powers(e.powers) : null].filter(Boolean).join(' · ')}
                  </span>
                </span>
                <span className="whitespace-nowrap text-xs text-muted">{ago(e.at)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {!list.length && !events.length && <Empty>{t('No browser extensions found.')}</Empty>}
    </Card>
  );
}

/** Programs installed or removed lately (30 days), and open findings about them. */
function ProgramsCard({ l, events, findings, go }: { l: Latest; events: ProgramEvent[]; findings: Resp['findings']; go: (p: string) => void }) {
  return (
    <Card title={`📦 ${t('Installed programs')}`}>
      <p className="mb-3 text-xs text-muted">
        {l.programs
          ? t('{n} programs are watched. A new one is checked: signed → low (no message), unsigned → medium, modified after signing or a crack name → high.', { n: l.programs.count })
          : t('The program list has not been read yet.')}
        {l.programs?.baselineAt && ` ${t('Baseline taken {when}.', { when: ago(l.programs.baselineAt) })}`}
      </p>
      <FindingList findings={findings} go={go} />
      {!events.length ? (
        <Empty>{t('No programs installed or removed in the last 30 days.')}</Empty>
      ) : (
        <ul className="divide-y divide-line text-sm">
          {events.map((e, i) => (
            <li key={i} className="flex items-start gap-2 py-2">
              <span>{e.kind === 'removed' ? '🗑️' : e.severity === 'high' ? '🟠' : e.severity === 'medium' ? '🟡' : '🆕'}</span>
              <span className="min-w-0 flex-1">
                <span className="break-words">{e.name}{e.version && !e.name.includes(e.version) ? ` ${e.version}` : ''}</span>
                <span className="block text-xs text-muted">
                  {e.kind === 'removed' ? t('Uninstalled') : [e.publisher, e.reason ? t(REASON[e.reason] ?? e.reason, { who: e.signer ?? '?' }) : null].filter(Boolean).join(' · ')}
                </span>
              </span>
              <span className="whitespace-nowrap text-xs text-muted">{ago(e.at)}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export default function DevicePage({ go }: { go: (p: string) => void }) {
  useTick();
  const { data, error, reload } = useApi(() => api.get<Resp>('/device-health'), [], ['device', 'findings']);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const l = data?.latest;
  const order = { bad: 0, warn: 1, unknown: 2, ok: 3 } as const;
  const checks = [...(l?.checks ?? [])].sort((a, b) => order[a.status] - order[b.status]);
  const ok = checks.filter((c) => c.status === 'ok').length;
  const known = checks.filter((c) => c.status !== 'unknown').length;
  const worst = checks[0]?.status ?? 'unknown';
  const autostart = (data?.findings ?? []).filter((f) => !['program_installed', 'browser_extension', 'network_changed', 'system_changed', 'device_connected'].includes(f.ruleId));
  const netFindings = (data?.findings ?? []).filter((f) => f.ruleId === 'network_changed');
  const sysFindings = (data?.findings ?? []).filter((f) => f.ruleId === 'system_changed');
  const perFindings = (data?.findings ?? []).filter((f) => f.ruleId === 'device_connected');
  const extFindings = (data?.findings ?? []).filter((f) => f.ruleId === 'browser_extension');
  const programFindings = (data?.findings ?? []).filter((f) => f.ruleId === 'program_installed');

  return (
    <>
      <PageHeader
        title={t('Device health')}
        subtitle={t('Is this PC\'s protection actually working, and did anything new set itself to start automatically? Checks only read; a virus scan starts only when you ask for one.')}
        actions={
          <Button
            disabled={busy || data?.running}
            onClick={async () => {
              setBusy(true);
              setErr(null);
              try {
                await api.post('/device-health/refresh');
                reload();
              } catch (e) {
                setErr(e instanceof Error ? e.message : String(e));
              }
              setBusy(false);
            }}
          >
            {busy || data?.running ? t('Checking… (about 15 s)') : t('Check now')}
          </Button>
        }
      />
      <ErrorNote error={error ?? err} />

      {!data ? (
        <Empty>{t('Loading…')}</Empty>
      ) : !l ? (
        <Card>
          <Empty>{t('No check has run yet. It runs every 30 minutes, or press "Check now".')}</Empty>
        </Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-3">
          <div className="space-y-4 xl:col-span-2">
            <ScanCard
              quickScanAgeDays={l.checks.find((c) => c.id === 'defender_scan')?.vars?.q as number | undefined}
              fullScanAgeDays={l.checks.find((c) => c.id === 'defender_scan')?.vars?.f as number | undefined}
            />
            <ThreatCard />
            <Card
              title={t('Protection & hardware')}
              right={<span className="text-xs text-muted">{t('Checked {when}', { when: ago(l.at) })}</span>}
            >
              <div className={`mb-2 flex items-baseline gap-3 rounded-xl px-4 py-3 ${worst === 'bad' ? 'bg-bad/10' : worst === 'warn' ? 'bg-warn/10' : 'bg-ok/10'}`}>
                <span className={`text-3xl font-semibold ${TONE[worst].text}`}>
                  {ok}/{known}
                </span>
                <span className="text-sm">{t('checks passed')}</span>
              </div>
              {!l.isAdmin && <p className="mb-2 text-xs text-warn">{t('SENTINEL is not running as administrator, so some checks cannot be read.')}</p>}
              <ul className="divide-y divide-line">
                {checks.map((c) => (
                  <CheckRow key={c.id} c={c} label={data.labels[c.id] ?? c.id} />
                ))}
              </ul>
            </Card>

            <Card title={t('Auto-start programs & scheduled tasks')}>
              <p className="mb-3 text-xs text-muted">
                {t('{s} auto-start entries and {n} scheduled tasks are watched. Anything new is checked: signed → low, unsigned or missing file → high, named like a Windows system file → critical.', { s: l.persistence.startup, n: l.persistence.tasks })}
                {l.persistence.baselineAt && ` ${t('Baseline taken {when}.', { when: ago(l.persistence.baselineAt) })}`}
              </p>
              {!autostart.length ? (
                <Empty>{t('Nothing suspicious found.')}</Empty>
              ) : (
                <ul className="divide-y divide-line">
                  {autostart.map((f) => (
                    <li key={f.id}>
                      <button type="button" className="flex w-full items-start gap-3 py-2.5 text-left hover:bg-panel-2/60" onClick={() => go(`security/${f.id}`)}>
                        <SevBadge sev={f.severity} />
                        <span className="min-w-0 flex-1">
                          <span className="block text-sm">{findingText(f, getLang()).title}</span>
                          <span className="block truncate text-xs text-muted">{findingText(f, getLang()).summary}</span>
                        </span>
                        <span className="whitespace-nowrap text-xs text-muted">{ago(f.lastSeen)}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <ProgramsCard l={l} events={data.recentPrograms ?? []} findings={programFindings} go={go} />
            <ExtensionsCard l={l} events={data.recentExtensions ?? []} findings={extFindings} go={go} />
            <NetworkCard l={l} events={data.recentNetwork ?? []} findings={netFindings} go={go} />
            <SystemCard l={l} events={data.recentSystem ?? []} findings={sysFindings} go={go} />
            <PeripheralsCard l={l} events={data.recentPeripherals ?? []} findings={perFindings} go={go} />
          </div>

          <div className="space-y-4">
            <Card title={t('Devices on your Tailscale network')}>
              {l.devices == null ? (
                <Empty>{t('Tailscale is not available on this PC.')}</Empty>
              ) : (
                <ul className="space-y-2 text-sm">
                  {l.devices.map((d) => (
                    <li key={d.name + d.os} className="flex items-center gap-2">
                      <span className={`size-2 rounded-full ${d.online ? 'bg-ok' : 'bg-muted'}`} />
                      <span className="flex-1">
                        {d.name} <span className="text-xs text-muted">({d.os}{d.self ? ` · ${t('this PC')}` : ''})</span>
                      </span>
                      <span className="text-xs text-muted">{d.online ? t('online') : d.lastSeen ? ago(Date.parse(d.lastSeen)) : t('offline')}</span>
                    </li>
                  ))}
                  {!l.devices.some((d) => d.os === 'android') && (
                    <li className="rounded-lg bg-warn/10 px-3 py-2 text-xs text-warn">
                      {t('Your Android phone is not on this Tailscale network yet. Install Tailscale from the Play Store and sign in with the same account to see it here and open SENTINEL from the phone.')}
                    </li>
                  )}
                </ul>
              )}
            </Card>

            <Card title={t('Android phone checklist')}>
              <p className="mb-2 text-xs text-muted">{t('Android does not let other apps inspect the phone, so SENTINEL cannot scan it. These built-in protections are what actually works:')}</p>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm">
                {ANDROID_TIPS.map((x) => (
                  <li key={x}>{t(x)}</li>
                ))}
              </ol>
            </Card>

            <Card title={t('iPhone / iPad checklist')}>
              <p className="mb-2 text-xs text-muted">{t('Apple does not let other apps inspect an iPhone or iPad either. These built-in protections are what actually works:')}</p>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm">
                {IOS_TIPS.map((x) => (
                  <li key={x}>{t(x)}</li>
                ))}
              </ol>
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
