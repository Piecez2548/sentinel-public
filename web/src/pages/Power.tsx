import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Icon } from '../components/icons';
import { Button, Card, ErrorNote, Field, FormModal, Input, PageHeader, Select, StatusBanner, Toggle } from '../components/ui';
import { api, ApiError } from '../lib/api';
import { duration } from '../lib/format';
import { t } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';

type Action = 'lock' | 'sleep' | 'hibernate' | 'restart' | 'shutdown';
type Pending = { action: Action; at: number; requestedAt: number; device: string };
type State = { pending: Pending | null; dryRun: boolean };
type Unlock = { until: number | null; mfa: boolean };

const ACTIONS: { id: Action; icon: () => ReactNode; label: string; desc: string; tone: 'calm' | 'warn' | 'danger'; delays: boolean }[] = [
  { id: 'lock', icon: Icon.lock, label: 'Lock screen', desc: 'Back to the sign-in screen. Everything keeps running.', tone: 'calm', delays: false },
  { id: 'sleep', icon: Icon.moon, label: 'Sleep', desc: 'Screen off and low power, like pressing the power button. Wakes in a second.', tone: 'calm', delays: true },
  { id: 'hibernate', icon: Icon.hibernate, label: 'Hibernate', desc: 'Saves open work to disk and powers off. Opens where you left off.', tone: 'warn', delays: true },
  { id: 'restart', icon: Icon.restart, label: 'Restart', desc: 'Restarts Windows. A 60-second countdown shows on screen first.', tone: 'warn', delays: true },
  { id: 'shutdown', icon: Icon.powerLg, label: 'Shut down', desc: 'Turns the PC off. It cannot be turned back on from the phone.', tone: 'danger', delays: true },
];

const TONE = {
  calm: 'hover:border-accent/60 hover:shadow-accent/10',
  warn: 'hover:border-warn/60 hover:shadow-warn/10',
  danger: 'hover:border-bad/60 hover:shadow-bad/10',
};

const DELAYS = [0, 15, 30, 60, 120, 240];

/** Runs a protected request; a 423 means the unlock ran out, so the page goes back to the code screen. */
function guarded<T>(p: Promise<T>, onLocked: () => void): Promise<T> {
  return p.catch((e) => {
    if (e instanceof ApiError && e.status === 423) onLocked();
    throw e;
  });
}

const mmss = (ms: number) => {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};

/* ---------- unlock once ---------- */

function UnlockGate({ mfa, onUnlocked }: { mfa: boolean; onUnlocked: () => void }) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/auth/unlock', { code });
      onUnlocked();
    } catch (err) {
      setError(err instanceof Error ? t(err.message) : String(err));
      setCode('');
      setBusy(false);
    }
  }

  if (!mfa) return <StatusBanner tone="warn" title={t('Turn on two-factor authentication in Settings first')} detail={t('Power control needs the 6-digit code from your authenticator app.')} />;

  return (
    <form onSubmit={submit} className="pop-in mx-auto max-w-sm rounded-2xl border border-line bg-gradient-to-b from-panel to-panel/80 p-6 text-center shadow-lg shadow-black/20">
      <span className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-accent/10 text-accent">
        <Icon.lock />
      </span>
      <h2 className="mt-4 text-lg font-semibold text-white">{t('Unlock power control')}</h2>
      <p className="mt-1 text-sm text-muted">{t('Enter your 6-digit code once. Everything on this page then works with a confirm tap for {n} minutes.', { n: 15 })}</p>
      <Input
        inputMode="numeric"
        autoComplete="one-time-code"
        autoFocus
        maxLength={6}
        placeholder="••••••"
        aria-label={t('6-digit code from your authenticator app')}
        value={code}
        onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
        className="mt-5 text-center text-2xl tracking-[0.6em]"
      />
      {error && <div className="mt-3 rounded-lg bg-bad/10 px-3 py-2 text-sm text-bad">{error}</div>}
      <Button variant="primary" disabled={busy || code.length !== 6} className="mt-4 w-full py-2.5">
        {busy ? t('Working…') : `🔓 ${t('Unlock')}`}
      </Button>
    </form>
  );
}

/* ---------- confirm dialogs (no code once unlocked) ---------- */

function ActionForm({ action, onClose, onLocked }: { action: (typeof ACTIONS)[number]; onClose: () => void; onLocked: () => void }) {
  const [delayMin, setDelayMin] = useState(0);
  return (
    <FormModal
      title={t('Confirm: {action}', { action: t(action.label) })}
      submitLabel={`✓ ${delayMin ? t('Schedule') : t(action.label)}`}
      danger={action.tone !== 'calm'}
      onClose={onClose}
      onSubmit={() => guarded(api.post('/power/action', { action: action.id, delayMin }), onLocked)}
    >
      <p className="text-sm text-muted">{t(action.desc)}</p>
      {action.delays && (
        <Field label={t('When')}>
          <Select value={delayMin} onChange={(e) => setDelayMin(Number(e.target.value))}>
            {DELAYS.map((m) => (
              <option key={m} value={m}>
                {m === 0 ? t('Now') : m < 60 ? t('In {n} minutes', { n: m }) : t('In {n} hour(s)', { n: m / 60 })}
              </option>
            ))}
          </Select>
        </Field>
      )}
    </FormModal>
  );
}

type Group = { name: string; label: string; title: string | null; company: string | null; path: string | null; cpu: number; memMB: number; count: number; protected: boolean; isGame: boolean };
type Procs = { at: number | null; groups: Group[]; gameMode: { enabled: boolean; processes: string[] }; gameRunning: { name: string; title: string | null } | null; dryRun: boolean };

const mem = (mb: number) => (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`);

function KillForm({ g, onClose, onLocked }: { g: Group; onClose: () => void; onLocked: () => void }) {
  return (
    <FormModal
      title={t('Close {name}', { name: g.title || g.label })}
      submitLabel={`✓ ${t('Close program')}`}
      danger
      onClose={onClose}
      onSubmit={() => guarded(api.post('/processes/kill', { name: g.name }), onLocked)}
    >
      <p className="text-sm text-muted">{t('Unsaved work in this program will be lost. Closes all {n} of its process(es).', { n: g.count })}</p>
      {g.path && <p className="break-all rounded-lg bg-panel-2 px-3 py-2 font-mono text-[11px] text-muted">{g.path}</p>}
    </FormModal>
  );
}

function Meter({ label, value, pct, tone }: { label: string; value: string; pct: number; tone: 'ok' | 'warn' | 'bad' }) {
  const bar = tone === 'bad' ? 'bg-bad' : tone === 'warn' ? 'bg-warn' : 'bg-accent';
  return (
    <div className="min-w-0">
      <div className="flex items-baseline justify-between gap-2 text-[11px]">
        <span className="text-muted">{label}</span>
        <span className={`tabular font-medium ${tone === 'bad' ? 'text-bad' : tone === 'warn' ? 'text-warn' : 'text-white'}`}>{value}</span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-panel-2">
        <div className={`h-full rounded-full ${bar} transition-all duration-500`} style={{ width: `${Math.max(2, Math.min(100, pct))}%` }} />
      </div>
    </div>
  );
}

/** Heaviest programs right now, with "close" and "this is a game" actions. */
function Programs({ onLocked }: { onLocked: () => void }) {
  const { data, error, loading, reload } = useApi(() => api.get<Procs>('/processes'), [], ['power'], 0);
  const [kill, setKill] = useState<Group | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const mode = data?.gameMode;
  const maxMem = Math.max(1, ...(data?.groups ?? []).map((g) => g.memMB));

  async function saveGames(processes: string[], enabled = mode?.enabled ?? true) {
    setErr(null);
    try {
      await api.put('/processes/game-mode', { enabled, processes });
      reload();
    } catch (e) {
      setErr(e instanceof Error ? t(e.message) : String(e));
    }
  }

  return (
    <>
      <Card
        className="mt-4"
        pad={false}
        title={t('Programs using this PC the most')}
        icon={<Icon.server />}
        right={
          <Button variant="ghost" disabled={loading} onClick={() => reload()}>
            {loading ? t('Working…') : `↻ ${t('Refresh')}`}
          </Button>
        }
      >
        <ErrorNote error={error ?? err} />
        {!data ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="skeleton h-16 rounded-xl border border-line" />
            ))}
          </div>
        ) : (
          <ul className="divide-y divide-line">
            {data.groups.map((g) => (
              <li key={g.name} className={`grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 px-4 py-3 ${g.protected ? 'opacity-75' : ''}`}>
                <div className="min-w-0">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-sm font-medium text-white">{g.title || g.label}</span>
                    {g.isGame && <span className="shrink-0 rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-semibold text-accent">🎮 {t('Game')}</span>}
                  </div>
                  <div className="truncate text-[11px] text-muted">
                    {g.label}.exe{g.count > 1 ? ` · ${t('{n} processes', { n: g.count })}` : ''}
                    {g.company ? ` · ${g.company}` : ''}
                  </div>
                </div>
                <div className="flex w-[7.25rem] items-center justify-end gap-1.5">
                  {g.protected ? (
                    <span className="inline-flex h-8 w-full items-center justify-center gap-1 rounded-lg border border-line/70 px-2 text-[11px] text-muted" title={t('Part of Windows, security software or SENTINEL — cannot be closed from here')}>
                      🛡 {t('System')}
                    </span>
                  ) : (
                    <>
                      {mode && (
                        <button
                          type="button"
                          title={g.isGame ? t('Remove from game list') : t('Mark as a game')}
                          aria-label={g.isGame ? t('Remove from game list') : t('Mark as a game')}
                          aria-pressed={g.isGame}
                          onClick={() => void saveGames(g.isGame ? mode.processes.filter((p) => p !== g.name) : [...mode.processes, g.name])}
                          className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg border text-sm transition ${g.isGame ? 'border-accent/60 bg-accent/15' : 'border-line grayscale hover:border-accent/50 hover:grayscale-0'}`}
                        >
                          🎮
                        </button>
                      )}
                      <Button variant="danger" className="h-8 flex-1" onClick={() => setKill(g)}>
                        {t('Close')}
                      </Button>
                    </>
                  )}
                </div>
                <div className="col-span-2 mt-2.5 grid grid-cols-2 gap-5 sm:max-w-md">
                  <Meter label="CPU" value={`${Math.round(g.cpu)}%`} pct={g.cpu} tone={g.cpu >= 50 ? 'bad' : g.cpu >= 20 ? 'warn' : 'ok'} />
                  <Meter label="RAM" value={mem(g.memMB)} pct={(g.memMB / maxMem) * 100} tone={g.memMB >= 2048 ? 'warn' : 'ok'} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="mt-4" title={`🎮 ${t('Game mode')}`}>
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1 text-sm text-muted">
            {t('While one of these programs is open, SENTINEL does not raise CPU or memory alerts. Security alerts still work as usual.')}
            {data?.gameRunning && <div className="mt-2 font-medium text-ok">● {t('{name} is open — CPU/memory alerts are paused', { name: data.gameRunning.title || data.gameRunning.name })}</div>}
          </div>
          {mode && <Toggle checked={mode.enabled} onChange={(v) => void saveGames(mode.processes, v)} />}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {mode?.processes.length ? (
            mode.processes.map((p) => (
              <span key={p} className="inline-flex items-center gap-1.5 rounded-full border border-line bg-panel-2 px-3 py-1 text-xs">
                {data?.groups.find((g) => g.name === p)?.title || p}
                <button type="button" aria-label={t('Remove')} className="text-muted hover:text-bad" onClick={() => void saveGames(mode.processes.filter((x) => x !== p))}>
                  ✕
                </button>
              </span>
            ))
          ) : (
            <span className="text-xs text-muted">{t('No games yet — press 🎮 next to a program above.')}</span>
          )}
        </div>
      </Card>

      {kill && (
        <KillForm
          g={kill}
          onLocked={onLocked}
          onClose={() => {
            setKill(null);
            reload();
          }}
        />
      )}
    </>
  );
}

/* ---------- open an app ---------- */

type LaunchApp = { id: string; name: string; folder: string | null };
type Launcher = { apps: LaunchApp[]; favourites: string[]; dryRun: boolean };

const TILE_COLORS = ['from-violet-500/30 to-indigo-500/20 text-violet-200', 'from-sky-500/30 to-cyan-500/20 text-sky-200', 'from-emerald-500/30 to-teal-500/20 text-emerald-200', 'from-amber-500/30 to-orange-500/20 text-amber-200', 'from-rose-500/30 to-pink-500/20 text-rose-200'];
const tileColor = (name: string) => TILE_COLORS[[...name].reduce((n, c) => n + c.charCodeAt(0), 0) % TILE_COLORS.length];

function OpenForm({ app, onClose, onLocked }: { app: LaunchApp; onClose: () => void; onLocked: () => void }) {
  return (
    <FormModal title={t('Open {name}', { name: app.name })} submitLabel={`▶ ${t('Open')}`} onClose={onClose} onSubmit={() => guarded(api.post('/launcher/open', { id: app.id }), onLocked)}>
      <p className="text-sm text-muted">{t('Opens on the PC screen as if you clicked it there. If the PC is locked, it opens behind the lock screen.')}</p>
    </FormModal>
  );
}

function EditApps({ data, onClose, onSaved }: { data: Launcher; onClose: () => void; onSaved: () => void }) {
  const [picked, setPicked] = useState<string[]>(data.favourites);
  const [q, setQ] = useState('');
  // Chosen apps first (in the order they were opened with the dialog), then the rest A–Z.
  const [first] = useState(data.favourites);
  const list = data.apps
    .filter((a) => !q || a.name.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => Number(first.includes(b.id)) - Number(first.includes(a.id)));
  const squash = (x: string) => x.toLowerCase().replace(/[^a-z0-9ก-๙]/g, '');
  const showFolder = (a: LaunchApp) => !!a.folder && !squash(a.folder).startsWith(squash(a.name).slice(0, 5));
  const toggle = (id: string) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : p.length >= 24 ? p : [...p, id]));
  return (
    <FormModal
      title={t('Choose apps')}
      submitLabel={t('Save')}
      onClose={onClose}
      onSubmit={async () => {
        await api.put('/launcher/favourites', { ids: picked });
        onSaved();
      }}
    >
      <p className="text-xs text-muted">{t('Apps from the Start menu and desktop of this PC. System tools are not listed. {n}/24 chosen.', { n: picked.length })}</p>
      <Input placeholder={t('Search apps…')} value={q} onChange={(e) => setQ(e.target.value)} />
      <ul className="-mx-1 max-h-[50vh] divide-y divide-line overflow-y-auto">
        {list.map((a) => (
          <li key={a.id}>
            <label className="flex cursor-pointer items-center gap-3 rounded-lg px-1 py-2 hover:bg-panel-2">
              <input type="checkbox" checked={picked.includes(a.id)} onChange={() => toggle(a.id)} className="h-4 w-4" />
              <span className="min-w-0 flex-1 truncate text-sm text-white">{a.name}</span>
              {showFolder(a) && <span className="max-w-[40%] truncate text-[11px] text-muted">{a.folder}</span>}
            </label>
          </li>
        ))}
      </ul>
    </FormModal>
  );
}

function OpenApps({ onLocked }: { onLocked: () => void }) {
  const { data, error, reload } = useApi(() => api.get<Launcher>('/launcher'), [], [], 0);
  const [openApp, setOpenApp] = useState<LaunchApp | null>(null);
  const [editing, setEditing] = useState(false);
  const favs = (data?.favourites ?? []).map((id) => data!.apps.find((a) => a.id === id)).filter((a): a is LaunchApp => !!a);

  return (
    <>
      <Card
        className="mt-4"
        title={t('Open an app')}
        icon={<span aria-hidden>▶</span>}
        right={
          <Button variant="ghost" disabled={!data} onClick={() => setEditing(true)}>
            ✎ {t('Edit')}
          </Button>
        }
      >
        <ErrorNote error={error} />
        {!data ? (
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-4 lg:grid-cols-6">
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="skeleton h-20 rounded-xl border border-line" />
            ))}
          </div>
        ) : favs.length ? (
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-4 lg:grid-cols-6">
            {favs.map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => setOpenApp(a)}
                className="group flex flex-col items-center gap-2 rounded-xl border border-line bg-panel-2/40 px-2 py-3 text-center transition hover:-translate-y-0.5 hover:border-accent/60"
              >
                <span className={`grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br text-base font-bold transition group-hover:scale-105 ${tileColor(a.name)}`}>{[...a.name][0]?.toUpperCase()}</span>
                <span className="line-clamp-2 w-full break-words text-[11px] leading-tight text-white">{a.name}</span>
              </button>
            ))}
          </div>
        ) : (
          <button type="button" onClick={() => setEditing(true)} className="w-full rounded-xl border border-dashed border-line/80 px-4 py-6 text-sm text-muted hover:border-accent/60">
            {t('No apps yet — tap to choose from this PC')}
          </button>
        )}
      </Card>
      {openApp && <OpenForm app={openApp} onLocked={onLocked} onClose={() => setOpenApp(null)} />}
      {editing && data && <EditApps data={data} onClose={() => setEditing(false)} onSaved={reload} />}
    </>
  );
}

type RemoteScreen = { target: string | null; installed: boolean; running: boolean; listening: boolean };

/** True on the PC itself: opening RustDesk there would connect the PC to itself. */
const onThisPc = () => ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);

/** Screen control: hands off to the RustDesk app on the phone, aimed at this PC's Tailscale IP. RustDesk asks for its own password and 2FA. */
function RemoteScreenBar() {
  const { data } = useApi(() => api.get<RemoteScreen>('/launcher/remote'), [], [], 60_000);
  if (!data) return <div className="skeleton mb-4 h-20 rounded-2xl border border-line" />;
  const ready = !!data.target && data.running && data.listening;
  const problem = !data.installed
    ? t('RustDesk is not installed on this PC')
    : !data.running
      ? t('RustDesk is not running on this PC')
      : !data.listening
        ? t('RustDesk direct IP access is off — turn it on in RustDesk → Settings → Security')
        : !data.target
          ? t('Tailscale has no IP — is Tailscale running on this PC?')
          : null;
  const href = data.target ? `rustdesk://connection/new/${data.target}` : undefined;
  const local = onThisPc();
  return (
    <section className="mb-4 flex flex-wrap items-center gap-4 rounded-2xl border border-accent/30 bg-gradient-to-r from-accent/15 via-panel to-panel p-4">
      <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-accent/15 text-2xl">🖥️</span>
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-2 font-semibold text-white">
          {t('Control the screen')}
          <span className={`inline-flex items-center gap-1.5 text-xs font-normal ${ready ? 'text-ok' : 'text-warn'}`}>
            <span className={`size-2 rounded-full ${ready ? 'bg-ok' : 'bg-warn'}`} />
            {ready ? t('Ready') : t('Not ready')}
          </span>
        </span>
        <span className="mt-0.5 block text-xs text-muted">
          {problem ?? (local ? t('Use this from your phone — it opens the RustDesk app connected to this PC.') : t('Opens RustDesk connected to this PC ({ip}). RustDesk asks for its own password and code.', { ip: data.target ?? '' }))}
        </span>
      </span>
      {href && ready && !local && (
        <a href={href} className="inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-accent to-indigo-500 px-5 font-semibold text-white shadow-md shadow-accent/20 hover:brightness-110 active:brightness-95 sm:w-auto">
          {t('Open RustDesk')}
        </a>
      )}
    </section>
  );
}

export default function PowerPage() {
  useTick(1000);
  const { data, error, reload } = useApi(() => api.get<State>('/power'), [], ['power'], 15_000);
  const unlock = useApi(() => api.get<Unlock>('/auth/unlock'), [], [], 0);
  const [open, setOpen] = useState<(typeof ACTIONS)[number] | null>(null);
  const [cancelErr, setCancelErr] = useState<string | null>(null);
  const p = data?.pending;
  const label = (a: Action) => t(ACTIONS.find((x) => x.id === a)?.label ?? a);
  const until = unlock.data?.until ?? null;
  const left = until ? until - Date.now() : 0;
  const isUnlocked = left > 0;

  // Close an open dialog when the unlock runs out.
  useEffect(() => {
    if (!isUnlocked) setOpen(null);
  }, [isUnlocked]);

  async function cancel() {
    setCancelErr(null);
    try {
      await api.post('/power/cancel');
      reload();
    } catch (e) {
      setCancelErr(e instanceof Error ? t(e.message) : String(e));
    }
  }

  async function lockNow() {
    await api.post('/auth/lock').catch(() => undefined);
    unlock.reload();
  }

  return (
    <>
      <PageHeader
        title={t('Power control')}
        subtitle={t('Lock, sleep, restart or shut down this PC from your phone. Unlock once with your 6-digit code; every command is announced on Telegram.')}
        actions={
          isUnlocked ? (
            <Button onClick={() => void lockNow()} title={t('Lock this page now')}>
              🔓 <span className="tabular">{mmss(left)}</span> · {t('Lock')}
            </Button>
          ) : undefined
        }
      />
      <ErrorNote error={error ?? cancelErr ?? unlock.error} />
      {data?.dryRun && <StatusBanner tone="warn" title={t('Test mode — commands are logged, not run')} />}

      {p && (
        <StatusBanner
          tone="warn"
          title={t('{action} in {time}', { action: label(p.action), time: duration(Math.max(0, p.at - Date.now())) })}
          detail={t('Requested from {device}', { device: p.device })}
          actions={
            <Button variant="danger" onClick={() => void cancel()}>
              ✋ {t('Cancel')}
            </Button>
          }
        />
      )}

      {!unlock.data ? (
        <div className="skeleton mx-auto h-72 max-w-sm rounded-2xl border border-line" />
      ) : !isUnlocked ? (
        <UnlockGate mfa={unlock.data.mfa} onUnlocked={() => unlock.reload()} />
      ) : (
        <div className="page-in">
          {/* Shown only once the page is unlocked (owner's choice): the server also refuses /launcher/remote before that. */}
          <RemoteScreenBar />
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {ACTIONS.map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => setOpen(a)}
                className={`group flex items-start gap-4 rounded-2xl border border-line bg-gradient-to-b from-panel to-panel/80 p-4 text-left transition duration-200 hover:-translate-y-0.5 hover:shadow-lg ${TONE[a.tone]}`}
              >
                <span className={`grid h-12 w-12 shrink-0 place-items-center rounded-xl transition group-hover:scale-105 ${a.tone === 'danger' ? 'bg-bad/10 text-bad' : a.tone === 'warn' ? 'bg-warn/10 text-warn' : 'bg-accent/10 text-accent'}`}>
                  <a.icon />
                </span>
                <span className="min-w-0">
                  <span className={`block font-semibold ${a.tone === 'danger' ? 'text-bad' : 'text-white'}`}>{t(a.label)}</span>
                  <span className="mt-0.5 block text-xs text-muted">{t(a.desc)}</span>
                </span>
              </button>
            ))}
          </div>

          <OpenApps onLocked={() => unlock.reload()} />
          <Programs onLocked={() => unlock.reload()} />
        </div>
      )}

      <Card className="mt-4" title={t('Good to know')}>
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
          <li>{t('Once the PC sleeps or is off, SENTINEL is off too — it cannot wake or start the PC again.')}</li>
          <li>{t('Restart and shut down show a countdown on the PC screen; you can cancel here until it ends.')}</li>
          <li>{t('The page locks itself after 15 minutes, when you sign out, or when SENTINEL restarts.')}</li>
          <li>{t('Cancelling never needs a code.')}</li>
        </ul>
      </Card>

      {open && isUnlocked && (
        <ActionForm
          action={open}
          onLocked={() => unlock.reload()}
          onClose={() => {
            setOpen(null);
            reload();
          }}
        />
      )}
    </>
  );
}
