import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Icon } from './components/icons';
import { PinScreen } from './components/PinScreen';
import { StepUpPrompt } from './components/StepUpPrompt';
import { Button, Input, PageSkeleton } from './components/ui';
import { api, type ComponentHealth } from './lib/api';
import { setLang, t, useLang } from './lib/i18n';
import { LiveBus, LiveContext, useApi, useRoute } from './lib/hooks';
// Each page (and ECharts, used by several) loads on first visit instead of in one large bundle.
const AlertsPage = lazy(() => import('./pages/Alerts'));
const ApplicationsPage = lazy(() => import('./pages/Applications'));
const AssetsPage = lazy(() => import('./pages/Assets'));
const DevicePage = lazy(() => import('./pages/Device'));
const IncidentsPage = lazy(() => import('./pages/Incidents'));
const InfrastructurePage = lazy(() => import('./pages/Infrastructure'));
const LogsPage = lazy(() => import('./pages/Logs'));
const OverviewPage = lazy(() => import('./pages/Overview'));
const PowerPage = lazy(() => import('./pages/Power'));
const ReportsPage = lazy(() => import('./pages/Reports'));
const SecurityPage = lazy(() => import('./pages/Security'));
const SettingsPage = lazy(() => import('./pages/Settings'));

type AuthState = { setupRequired: boolean; setupAllowed: boolean; authenticated: boolean; mfaPending: boolean; mfaEnabled: boolean; pinEnabled?: boolean; pinLocked?: boolean };

/* ---------- auth screens ---------- */

function AuthCard({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-2xl border border-line bg-panel p-6">
        <div className="mb-5 flex items-center gap-3">
          <Icon.logo />
          <div>
            <div className="text-lg font-bold tracking-[0.2em]">SENTINEL</div>
            <div className="text-xs text-muted">{subtitle}</div>
          </div>
        </div>
        <div className="mb-3 flex items-center justify-between">
          <h1 className="font-semibold">{title}</h1>
          <LangToggle />
        </div>
        {children}
      </div>
    </div>
  );
}

function LangToggle() {
  const lang = useLang();
  return (
    <div className="flex overflow-hidden rounded-md border border-line text-[11px]" role="group" aria-label="Language / ภาษา">
      {(['th', 'en'] as const).map((l) => (
        <button key={l} type="button" onClick={() => setLang(l)} className={`px-2 py-0.5 ${lang === l ? 'bg-accent text-white' : 'text-muted hover:text-white'}`}>
          {l === 'th' ? 'ไทย' : 'EN'}
        </button>
      ))}
    </div>
  );
}

function AuthGate({ state, onDone }: { state: AuthState; onDone: () => void }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [mfa, setMfa] = useState(state.mfaPending);

  async function run(e: FormEvent, fn: () => Promise<void>) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? t(err.message) : t('Failed'));
    } finally {
      setBusy(false);
    }
  }

  if (state.setupRequired) {
    if (!state.setupAllowed) {
      return (
        <AuthCard title={t('Setup required')} subtitle={t('Security monitoring')}>
          <p className="text-sm text-muted">{t('Open SENTINEL in a browser on the computer where it runs (http://127.0.0.1:3001) to create the admin password.')}</p>
        </AuthCard>
      );
    }
    return (
      <AuthCard title={t('Create admin password')} subtitle={t('First-time setup')}>
        <form
          className="space-y-3"
          onSubmit={(e) =>
            run(e, async () => {
              if (password !== confirm) throw new Error(t('Passwords do not match'));
              await api.post('/auth/setup', { password });
              onDone();
            })
          }
        >
          <Input type="password" autoFocus placeholder={t('Password (min. 12 characters)')} value={password} onChange={(e) => setPassword(e.target.value)} />
          <Input type="password" placeholder={t('Repeat password')} value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          <p className="text-xs text-muted">{t('Use a long passphrase. You can turn on two-factor authentication (MFA) in Settings afterwards.')}</p>
          {error && <div className="text-sm text-bad">{error}</div>}
          <Button variant="primary" className="w-full py-2" disabled={busy || password.length < 12}>
            {t('Create & sign in')}
          </Button>
        </form>
      </AuthCard>
    );
  }

  if (mfa) {
    return (
      <AuthCard title={t('Two-factor code')} subtitle={t('Enter the 6-digit code from your authenticator app')}>
        <form
          className="space-y-3"
          onSubmit={(e) =>
            run(e, async () => {
              await api.post('/auth/mfa', { code });
              onDone();
            })
          }
        >
          <Input inputMode="numeric" autoComplete="one-time-code" autoFocus maxLength={6} placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} className="text-center text-lg tracking-[0.5em]" />
          {error && <div className="text-sm text-bad">{error}</div>}
          <Button variant="primary" className="w-full py-2" disabled={busy || code.length !== 6}>
            {t('Verify')}
          </Button>
          <button type="button" className="w-full text-xs text-muted hover:text-white" onClick={() => setMfa(false)}>
            {t('Back to password')}
          </button>
        </form>
      </AuthCard>
    );
  }

  return (
    <AuthCard title={t('Sign in')} subtitle={t('Security monitoring')}>
      <form
        className="space-y-3"
        onSubmit={(e) =>
          run(e, async () => {
            const r = await api.post<{ ok?: boolean; mfaRequired?: boolean }>('/auth/login', { password });
            if (r.mfaRequired) setMfa(true);
            else onDone();
          })
        }
      >
        <Input type="password" autoFocus placeholder={t('Admin password')} value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <div className="text-sm text-bad">{error}</div>}
        <Button variant="primary" className="w-full py-2" disabled={busy || !password}>
          {t('Sign in')}
        </Button>
      </form>
    </AuthCard>
  );
}

/* ---------- shell ---------- */

const NAV = [
  { path: 'overview', label: 'Overview', icon: Icon.overview },
  { path: 'infrastructure', label: 'Infrastructure', icon: Icon.server },
  { path: 'device', label: 'Device health', icon: Icon.heart },
  { path: 'power', label: 'Power control', icon: Icon.power },
  { path: 'applications', label: 'Applications', icon: Icon.globe },
  { path: 'security', label: 'Security Center', icon: Icon.shield },
  { path: 'logs', label: 'Log Explorer', icon: Icon.logs },
  { path: 'incidents', label: 'Incidents', icon: Icon.incident },
  { path: 'alerts', label: 'Alert Manager', icon: Icon.bell },
  { path: 'assets', label: 'Assets', icon: Icon.box },
  { path: 'reports', label: 'Reports', icon: Icon.chart },
  { path: 'settings', label: 'Settings', icon: Icon.settings },
] as const;

type Badges = { alerts: number; findings: number; incidents: number; down: number; unhealthy: ComponentHealth[] };

function Shell({ onLogout }: { onLogout: () => void }) {
  const [route, go] = useRoute();
  const live = useMemo(() => new LiveBus(), []);
  const [connected, setConnected] = useState(true);
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    live.onStatus = setConnected;
    live.start();
    return () => live.stop();
  }, [live]);

  return (
    <LiveContext.Provider value={live}>
      <ShellInner route={route} go={go} connected={connected} onLogout={onLogout} navOpen={navOpen} setNavOpen={setNavOpen} />
    </LiveContext.Provider>
  );
}

function ShellInner({ route, go, connected, onLogout, navOpen, setNavOpen }: { route: string[]; go: (p: string) => void; connected: boolean; onLogout: () => void; navOpen: boolean; setNavOpen: (v: boolean) => void }) {
  const { data: b } = useApi<Badges>(
    async () => {
      const o = await api.get<{ alerts: { active: unknown[] }; findings: { openBySeverity: Record<string, number> }; incidents: { open: number }; assets: { down: number }; health: ComponentHealth[] }>('/overview');
      return {
        alerts: o.alerts.active.length,
        findings: Object.values(o.findings.openBySeverity).reduce((s, n) => s + n, 0),
        incidents: o.incidents.open,
        down: o.assets.down,
        unhealthy: o.health.filter((h) => !h.ok),
      };
    },
    [],
    ['alerts', 'findings', 'incidents', 'assets', 'health'],
    30_000,
  );

  useEffect(() => {
    const n = (b?.alerts ?? 0) + (b?.down ?? 0);
    document.title = n ? `🔴 (${n}) SENTINEL` : 'SENTINEL';
  }, [b]);

  const page = route[0] ?? 'overview';
  const badge: Record<string, number> = { alerts: b?.alerts ?? 0, security: b?.findings ?? 0, incidents: b?.incidents ?? 0 };

  const content = (() => {
    switch (page) {
      case 'infrastructure':
        return <InfrastructurePage />;
      case 'device':
        return <DevicePage go={go} />;
      case 'power':
        return <PowerPage />;
      case 'applications':
        return <ApplicationsPage selectedId={route[1] ? Number(route[1]) : null} go={go} />;
      case 'security':
        return <SecurityPage selectedId={route[1] ? Number(route[1]) : null} go={go} />;
      case 'logs':
        return <LogsPage />;
      case 'incidents':
        return <IncidentsPage selectedId={route[1] ? Number(route[1]) : null} go={go} />;
      case 'alerts':
        return <AlertsPage go={go} />;
      case 'assets':
        return <AssetsPage go={go} />;
      case 'reports':
        return <ReportsPage />;
      case 'settings':
        return <SettingsPage onLogout={onLogout} />;
      default:
        return <OverviewPage go={go} />;
    }
  })();

  const nav = (
    <nav className="flex flex-col gap-0.5">
      {NAV.map((n) => {
        const active = page === n.path;
        const count = badge[n.path] ?? 0;
        return (
          <a
            key={n.path}
            href={`#/${n.path}`}
            onClick={() => setNavOpen(false)}
            aria-current={active ? 'page' : undefined}
            className={`relative flex items-center gap-3 rounded-xl px-3 py-2 text-sm transition ${active ? 'bg-gradient-to-r from-accent/25 to-accent/5 font-medium text-white ring-1 ring-accent/30' : 'text-muted hover:bg-panel-2 hover:text-white'}`}
          >
            {active && <span className="absolute -left-4 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r-full bg-accent shadow-[0_0_10px] shadow-accent" />}
            <span className={active ? 'text-accent' : ''}>
              <n.icon />
            </span>
            <span className="flex-1">{t(n.label)}</span>
            {count > 0 && <span className="tabular min-w-5 rounded-full bg-bad/90 px-1.5 text-center text-[11px] font-semibold text-white shadow-sm shadow-bad/40">{count}</span>}
          </a>
        );
      })}
    </nav>
  );

  return (
    <div className="flex min-h-full">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-panel/60 p-4 backdrop-blur lg:flex">
        <a href="#/overview" className="mb-6 flex items-center gap-2.5 px-1">
          <Icon.logo />
          <span className="bg-gradient-to-r from-white to-violet-200 bg-clip-text text-lg font-bold tracking-[0.2em] text-transparent">SENTINEL</span>
        </a>
        {nav}
        <div className="mt-auto space-y-2 pt-4 text-xs text-muted">
          <div className="flex items-center gap-2 px-1">
            <span className={`h-2 w-2 rounded-full ${connected ? 'bg-ok shadow-[0_0_6px] shadow-ok' : 'animate-pulse bg-warn'}`} />
            {connected ? t('Live') : t('Reconnecting…')}
            <span className="ml-auto">
              <LangToggle />
            </span>
          </div>
          <button
            onClick={async () => {
              await api.post('/auth/logout').catch(() => {});
              onLogout();
            }}
            className="flex w-full items-center gap-2 rounded-lg px-1 py-1 transition hover:bg-panel-2 hover:text-white"
          >
            <Icon.logout /> {t('Sign out')}
          </button>
        </div>
      </aside>

      {navOpen && (
        <div className="fade-in fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden" onClick={() => setNavOpen(false)}>
          <div className="h-full w-64 overflow-y-auto border-r border-line bg-panel p-4 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="mb-5 flex items-center gap-2.5">
              <Icon.logo />
              <span className="flex-1 font-bold tracking-[0.2em]">SENTINEL</span>
              <LangToggle />
            </div>
            {nav}
          </div>
        </div>
      )}

      <main className="min-w-0 flex-1">
        <div className="sticky top-0 z-20 flex items-center justify-between border-b border-line bg-bg/80 px-4 py-3 backdrop-blur lg:hidden">
          <button onClick={() => setNavOpen(true)} aria-label={t('Menu')} className="rounded-lg border border-line px-2.5 py-1 text-sm transition hover:border-accent/60">
            ☰
          </button>
          <span className="font-bold tracking-[0.2em]">SENTINEL</span>
          <span title={connected ? t('Live') : t('Reconnecting…')} className={`h-2 w-2 rounded-full ${connected ? 'bg-ok shadow-[0_0_6px] shadow-ok' : 'animate-pulse bg-warn'}`} />
        </div>
        <div className="mx-auto max-w-[1400px] p-4 sm:p-6">
          {b && b.unhealthy.length > 0 && (
            <a href="#/settings" className="mb-4 block rounded-xl border border-warn/40 bg-warn/10 px-4 py-2.5 text-sm text-warn hover:bg-warn/15">
              ⚠ {t('Monitoring problem')}: {b.unhealthy.map((h) => `${t(h.label)} — ${t(h.message)}`).join(' · ')}
            </a>
          )}
          <Suspense fallback={<PageSkeleton />}>
            <div key={page} className="page-in">{content}</div>
          </Suspense>
        </div>
      </main>
    </div>
  );
}

/* ---------- root ---------- */

export default function App() {
  const [state, setState] = useState<AuthState | null>(null);
  // Bumped after the PIN is entered so every page loads its data again.
  const [round, setRound] = useState(0);
  const refresh = useCallback(() => {
    api.get<AuthState>('/auth/state').then(setState).catch(() => setState({ setupRequired: false, setupAllowed: false, authenticated: false, mfaPending: false, mfaEnabled: false }));
  }, []);

  useEffect(() => {
    refresh();
    const on = () => refresh();
    const pin = () => setState((s) => (s ? { ...s, pinLocked: true } : s));
    window.addEventListener('sentinel:unauthorized', on);
    window.addEventListener('sentinel:pin', pin);
    return () => {
      window.removeEventListener('sentinel:unauthorized', on);
      window.removeEventListener('sentinel:pin', pin);
    };
  }, [refresh]);

  // App PIN: tell the server when the app goes to the background; on return, ask whether the PIN is needed.
  const pinOn = !!state?.authenticated && !!state.pinEnabled;
  useEffect(() => {
    if (!pinOn) return;
    // Each message carries the time it happened, so the server can drop a "left" that arrives after a newer "back".
    const onVis = () => {
      const seq = Date.now();
      if (document.visibilityState === 'hidden') {
        void fetch('/api/auth/pin/away', { method: 'POST', keepalive: true, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ seq }) }).catch(() => undefined);
      } else {
        api
          .post<{ locked: boolean }>('/auth/pin/back', { seq })
          .then((r) => r.locked && setState((s) => (s ? { ...s, pinLocked: true } : s)))
          .catch(() => undefined);
      }
    };
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, [pinOn]);

  // Re-mount on language change so every page re-renders its text, charts included.
  const lang = useLang();
  if (!state) return null;
  if (!state.authenticated) return <AuthGate key={lang} state={state} onDone={refresh} />;
  if (state.pinLocked)
    return (
      <PinScreen
        onUnlocked={() => {
          setState((s) => (s ? { ...s, pinLocked: false } : s));
          setRound((n) => n + 1);
        }}
        onSignedOut={refresh}
      />
    );
  return (
    <>
      <Shell key={`${lang}:${round}`} onLogout={refresh} />
      <StepUpPrompt />
    </>
  );
}
