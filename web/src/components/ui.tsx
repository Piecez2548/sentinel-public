import { useEffect, useState, type ButtonHTMLAttributes, type FormEvent, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react';
import { sevLabel, SEV_STYLE, stateLabel, STATUS_DOT, statusLabel } from '../lib/format';
import { t } from '../lib/i18n';

export function Card({ title, icon, right, children, className = '', pad = true }: { title?: ReactNode; icon?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`rounded-2xl border border-line bg-gradient-to-b from-panel to-panel/80 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] transition-colors hover:border-[#36354a] ${pad ? 'p-4' : ''} ${className}`}>
      {(title || right) && (
        <div className={`mb-3 flex min-h-7 flex-wrap items-center justify-between gap-2 ${pad ? '' : 'px-4 pt-4'}`}>
          <h2 className="flex items-center gap-2 text-sm font-semibold tracking-wide text-slate-200">
            {icon && <span className="grid h-7 w-7 place-items-center rounded-lg bg-accent/10 text-accent">{icon}</span>}
            {title}
          </h2>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-white sm:text-2xl">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

const TONE = {
  ok: { text: 'text-ok', chip: 'bg-ok/10 text-ok', bar: 'from-ok/70' },
  bad: { text: 'text-bad', chip: 'bg-bad/10 text-bad', bar: 'from-bad/80' },
  warn: { text: 'text-warn', chip: 'bg-warn/10 text-warn', bar: 'from-warn/70' },
  none: { text: 'text-white', chip: 'bg-accent/10 text-accent', bar: 'from-accent/50' },
};

export function Kpi({ label, value, sub, tone, icon, onClick }: { label: string; value: ReactNode; sub?: ReactNode; tone?: 'ok' | 'bad' | 'warn'; icon?: ReactNode; onClick?: () => void }) {
  const c = TONE[tone ?? 'none'];
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag
      onClick={onClick}
      className={`group relative overflow-hidden rounded-2xl border border-line bg-gradient-to-b from-panel to-panel/80 px-4 py-3 text-left ${onClick ? 'cursor-pointer transition duration-200 hover:-translate-y-0.5 hover:border-accent/50 hover:shadow-lg hover:shadow-accent/10' : ''}`}
    >
      {/* thin colour strip on top shows the state at a glance */}
      <span className={`absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r ${c.bar} to-transparent`} />
      <div className="flex items-start justify-between gap-2">
        <div className="text-xs text-muted">{label}</div>
        {icon && <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-lg ${c.chip}`}>{icon}</span>}
      </div>
      <div className={`tabular mt-1 text-2xl font-semibold ${c.text}`}>{value}</div>
      <div className="flex min-h-4 items-center justify-between text-xs text-muted">
        <span className="truncate">{sub}</span>
        {onClick && <span className="text-muted/0 transition group-hover:text-muted">→</span>}
      </div>
    </Tag>
  );
}

/** One-line verdict at the top of a page: is everything fine, or what needs a look. */
export function StatusBanner({ tone, title, detail, actions }: { tone: 'ok' | 'warn' | 'bad'; title: ReactNode; detail?: ReactNode; actions?: ReactNode }) {
  const s = {
    ok: 'border-ok/30 from-ok/10 text-ok',
    warn: 'border-warn/30 from-warn/10 text-warn',
    bad: 'border-bad/40 from-bad/15 text-bad',
  }[tone];
  return (
    <div className={`mb-4 flex flex-wrap items-center gap-3 rounded-2xl border bg-gradient-to-r to-transparent px-4 py-3 ${s}`}>
      <span className="relative flex h-3 w-3 shrink-0">
        {tone !== 'ok' && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-50" />}
        <span className="relative inline-flex h-3 w-3 rounded-full bg-current" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="font-semibold">{title}</div>
        {detail && <div className="text-xs text-muted">{detail}</div>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

/** Placeholder blocks shown while a page loads. */
export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton rounded-2xl border border-line ${className}`} />;
}
export function PageSkeleton() {
  return (
    <div className="fade-in" aria-busy="true" aria-label={t('Loading…')}>
      <Skeleton className="mb-2 h-7 w-48" />
      <Skeleton className="mb-5 h-4 w-72 border-0" />
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[92px]" />)}
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
    </div>
  );
}

export function SevBadge({ sev }: { sev: string }) {
  return <span className={`inline-flex rounded-md px-1.5 py-0.5 text-[11px] font-semibold uppercase ring-1 ${SEV_STYLE[sev] ?? 'bg-line text-muted ring-line'}`}>{sevLabel(sev)}</span>;
}

const STATE_STYLE: Record<string, string> = {
  firing: 'bg-bad/15 text-bad',
  open: 'bg-bad/15 text-bad',
  acknowledged: 'bg-warn/15 text-warn',
  investigating: 'bg-accent/20 text-violet-300',
  resolved: 'bg-ok/15 text-ok',
  closed: 'bg-line text-muted',
  false_positive: 'bg-line text-muted',
  sent: 'bg-ok/15 text-ok',
  pending: 'bg-warn/15 text-warn',
  failed: 'bg-bad/15 text-bad',
};
export function StateBadge({ state }: { state: string }) {
  return <span className={`inline-flex rounded-md px-1.5 py-0.5 text-[11px] font-medium ${STATE_STYLE[state] ?? 'bg-line text-muted'}`}>{stateLabel(state)}</span>;
}

export function StatusDot({ status }: { status: string }) {
  return <span className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${STATUS_DOT[status] ?? 'bg-muted'}`} title={statusLabel(status)} />;
}

export function Button({ variant = 'default', className = '', ...p }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'default' | 'primary' | 'danger' | 'ghost' }) {
  const v = {
    default: 'border border-line bg-panel-2 hover:border-accent/70 hover:bg-[#232233] active:bg-panel-2',
    primary: 'bg-gradient-to-r from-accent to-indigo-500 text-white shadow-md shadow-accent/20 hover:brightness-110 active:brightness-95',
    danger: 'border border-bad/40 bg-bad/10 text-bad hover:bg-bad/20',
    ghost: 'text-muted hover:text-white hover:bg-panel-2',
  }[variant];
  return <button {...p} className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${v} ${className}`} />;
}

export const inputCls = 'w-full rounded-lg border border-line bg-panel-2 px-3 py-2 text-sm outline-none transition hover:border-[#3a3950] focus:border-accent focus:ring-2 focus:ring-accent/20';

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block text-xs text-muted">
      {label}
      <div className="mt-1">{children}</div>
      {hint && <div className="mt-1 text-[11px] text-muted/80">{hint}</div>}
    </label>
  );
}
export const Input = (p: InputHTMLAttributes<HTMLInputElement>) => <input {...p} className={`${inputCls} ${p.className ?? ''}`} />;
export const Select = (p: SelectHTMLAttributes<HTMLSelectElement>) => <select {...p} className={`${inputCls} ${p.className ?? ''}`} />;
export const Textarea = (p: TextareaHTMLAttributes<HTMLTextAreaElement>) => <textarea {...p} className={`${inputCls} ${p.className ?? ''}`} />;

export function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-9 shrink-0 rounded-full transition disabled:opacity-50 ${checked ? 'bg-accent' : 'bg-line'}`}
    >
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition ${checked ? 'left-4.5' : 'left-0.5'}`} />
    </button>
  );
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-30 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-[10vh] backdrop-blur-sm fade-in" onMouseDown={onClose}>
      <div onMouseDown={(e) => e.stopPropagation()} className={`w-full ${wide ? 'max-w-3xl' : 'max-w-md'} pop-in rounded-2xl border border-line bg-panel p-5 shadow-2xl shadow-black/50`}>
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold">{title}</h3>
          <button onClick={onClose} className="grid h-8 w-8 place-items-center rounded-lg text-muted transition hover:bg-panel-2 hover:text-white" aria-label={t('Close')}>
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

/** A modal form with submit handling, busy state and error display. */
export function FormModal({ title, submitLabel, onClose, onSubmit, children, wide, danger }: { title: string; submitLabel?: string; onClose: () => void; onSubmit: () => Promise<unknown>; children: ReactNode; wide?: boolean; danger?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await onSubmit();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? t(err.message) : t('Failed'));
      setBusy(false);
    }
  }
  return (
    <Modal title={title} onClose={onClose} wide={wide}>
      <form onSubmit={submit} className="space-y-3">
        {children}
        {error && <div className="rounded-lg bg-bad/10 px-3 py-2 text-sm text-bad">{error}</div>}
        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" onClick={onClose}>
            {t('Cancel')}
          </Button>
          <Button variant={danger ? 'danger' : 'primary'} disabled={busy}>
            {busy ? t('Working…') : (submitLabel ?? t('Save'))}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-xl border border-dashed border-line/80 bg-panel-2/30 px-4 py-8 text-center text-sm text-muted">{children}</div>;
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="mb-4 rounded-xl border border-bad/40 bg-bad/10 px-4 py-2.5 text-sm text-bad">{error}</div>;
}

export function Tabs<T extends string>({ value, onChange, tabs }: { value: T; onChange: (v: T) => void; tabs: { value: T; label: ReactNode }[] }) {
  return (
    <div className="mb-4 inline-flex max-w-full flex-wrap gap-1 rounded-xl border border-line bg-panel/70 p-1">
      {tabs.map((t) => (
        <button
          key={t.value}
          onClick={() => onChange(t.value)}
          className={`rounded-lg px-3 py-1.5 text-sm transition ${value === t.value ? 'bg-accent text-white shadow-md shadow-accent/25' : 'text-muted hover:bg-panel-2 hover:text-white'}`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string | number>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[] }) {
  return (
    <div className="flex gap-1">
      {options.map((o) => (
        <button
          key={String(o.value)}
          onClick={() => onChange(o.value)}
          className={`rounded-md px-2 py-0.5 text-xs transition ${value === o.value ? 'bg-accent text-white' : 'text-muted hover:bg-panel-2 hover:text-white'}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Meter({ value, warn = 75, bad = 90 }: { value: number | null; warn?: number; bad?: number }) {
  const v = value ?? 0;
  const color = v >= bad ? 'bg-bad' : v >= warn ? 'bg-warn' : 'bg-ok';
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-line">
      <div className={`h-full rounded-full transition-[width] duration-500 ${color}`} style={{ width: `${Math.min(100, Math.max(0, v))}%` }} />
    </div>
  );
}

export function Th({ children, className = '' }: { children?: ReactNode; className?: string }) {
  return <th className={`whitespace-nowrap px-3 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted ${className}`}>{children}</th>;
}
export function Td({ children, className = '' }: { children?: ReactNode; className?: string }) {
  return <td className={`px-3 py-2 align-top ${className}`}>{children}</td>;
}

export function Json({ value }: { value: unknown }) {
  return <pre className="max-h-80 overflow-auto rounded-lg bg-black/40 p-3 text-xs leading-relaxed text-slate-300">{JSON.stringify(value, null, 2)}</pre>;
}
