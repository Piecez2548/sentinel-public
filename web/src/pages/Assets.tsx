import { useState } from 'react';
import { Button, Card, Empty, ErrorNote, Field, FormModal, Input, PageHeader, Select, StatusDot, Td, Th, Toggle } from '../components/ui';
import { api, type Asset } from '../lib/api';
import { ago, statusLabel } from '../lib/format';
import { t } from '../lib/i18n';
import { useApi } from '../lib/hooks';

export function WebsiteForm({ site, onClose, onSaved }: { site: Asset | null; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(site?.name ?? '');
  const [url, setUrl] = useState(site?.target ?? 'https://');
  const [interval, setIntervalSec] = useState(site?.website?.intervalSec ?? 60);
  const [keyword, setKeyword] = useState(site?.website?.keyword ?? '');
  const [expected, setExpected] = useState(site?.website?.expectedStatus ?? '');
  const [env, setEnv] = useState(site?.environment ?? 'production');
  const [slo, setSlo] = useState(String(site?.sloTarget ?? 99.5));
  const [tags, setTags] = useState((site?.tags ?? []).join(', '));
  return (
    <FormModal
      title={site ? t('Edit {name}', { name: site.name }) : t('Add website / API')}
      submitLabel={site ? t('Save') : t('Add & check now')}
      onClose={onClose}
      onSubmit={async () => {
        const b = { type: 'website', name, url, intervalSec: interval, keyword, expectedStatus: expected, environment: env, sloTarget: Number(slo), tags };
        if (site) await api.put(`/assets/${site.id}`, b);
        else await api.post('/assets', b);
        onSaved();
      }}
    >
      <Field label={t('Name')}>
        <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} autoFocus />
      </Field>
      <Field label="URL" hint={t('Private/LAN addresses are blocked (SSRF protection).')}>
        <Input value={url} onChange={(e) => setUrl(e.target.value)} />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label={t('Check every')}>
          <Select value={interval} onChange={(e) => setIntervalSec(Number(e.target.value))}>
            {[30, 60, 120, 300, 600, 1800, 3600].map((s) => (
              <option key={s} value={s}>
                {s < 60 ? t('{n} seconds', { n: s }) : t('{n} minutes', { n: s / 60 })}
              </option>
            ))}
          </Select>
        </Field>
        <Field label={t('SLO target (%)')} hint={t('Used in Reports (error budget).')}>
          <Input type="number" step="0.1" min={50} max={100} value={slo} onChange={(e) => setSlo(e.target.value)} />
        </Field>
      </div>
      <Field label={t('Must contain text (optional)')} hint={t('Catches pages that return 200 but show an error.')}>
        <Input value={keyword} onChange={(e) => setKeyword(e.target.value)} maxLength={200} />
      </Field>
      <Field label={t('Expected HTTP status (optional)')} hint={t('For APIs/backends, e.g. 401 means "reachable but needs a key". Leave empty for normal websites (any 2xx/3xx is up).')}>
        <Input value={expected} onChange={(e) => setExpected(e.target.value)} maxLength={60} placeholder="200-299,401" />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label={t('Environment')}>
          <Select value={env} onChange={(e) => setEnv(e.target.value)}>
            {['production', 'staging', 'development', 'lab'].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </Select>
        </Field>
        <Field label={t('Tags (comma separated)')}>
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="vercel, frontend" />
        </Field>
      </div>
    </FormModal>
  );
}

export default function AssetsPage({ go }: { go: (p: string) => void }) {
  const { data, error, reload } = useApi(() => api.get<{ assets: Asset[] }>('/assets'), [], ['assets']);
  const [modal, setModal] = useState<{ site: Asset | null } | null>(null);
  const [del, setDel] = useState<Asset | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function toggle(a: Asset) {
    setActionError(null);
    try {
      await api.put(`/assets/${a.id}`, { enabled: !a.enabled });
      reload();
    } catch (e) {
      setActionError(e instanceof Error ? t(e.message) : t('Failed'));
    }
  }

  return (
    <>
      <PageHeader title={t('Asset Inventory')} subtitle={t('Everything SENTINEL watches. This PC is registered automatically by the built-in collector.')} actions={<Button variant="primary" onClick={() => setModal({ site: null })}>{t('+ Add website')}</Button>} />
      <ErrorNote error={error ?? actionError} />
      <Card pad={false}>
        {!data?.assets.length ? (
          <Empty>{t('No assets.')}</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line">
                <tr>
                  <Th>{t('Status')}</Th>
                  <Th>{t('Name')}</Th>
                  <Th>{t('Type')}</Th>
                  <Th>{t('Target')}</Th>
                  <Th>{t('Env / tags')}</Th>
                  <Th>SLO</Th>
                  <Th>{t('Signals')}</Th>
                  <Th>{t('Monitoring')}</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.assets.map((a) => (
                  <tr key={a.id} className="hover:bg-panel-2/50">
                    <Td>
                      <span className="flex items-center gap-2 text-xs">
                        <StatusDot status={a.status} /> {statusLabel(a.status)}
                      </span>
                    </Td>
                    <Td>
                      <button className="text-left hover:underline" onClick={() => go(a.type === 'host' ? 'infrastructure' : `applications/${a.id}`)}>
                        {a.name}
                      </button>
                      <div className="text-xs text-muted">{t('added {ago}', { ago: ago(a.createdAt) })}</div>
                    </Td>
                    <Td className="text-xs capitalize">{t(a.type)}</Td>
                    <Td className="max-w-64 truncate text-xs text-muted">{a.type === 'host' ? `${a.host?.os ?? ''} (${t('local collector')})` : a.target}</Td>
                    <Td className="text-xs">
                      <span className="text-muted">{a.environment}</span>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {a.tags.map((tag) => (
                          <span key={tag} className="rounded bg-line px-1.5 py-0.5 text-[11px]">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </Td>
                    <Td className="text-xs">{a.sloTarget}%</Td>
                    <Td className="text-xs">
                      <span className={a.activeAlerts ? 'text-bad' : 'text-muted'}>{t('{n} alerts', { n: a.activeAlerts })}</span>
                      <br />
                      <span className={a.openFindings ? 'text-warn' : 'text-muted'}>{t('{n} findings', { n: a.openFindings })}</span>
                    </Td>
                    <Td>
                      <Toggle checked={a.enabled} onChange={() => toggle(a)} />
                    </Td>
                    <Td className="whitespace-nowrap text-right">
                      {a.type === 'website' && (
                        <>
                          <Button variant="ghost" onClick={() => setModal({ site: a })}>
                            {t('Edit')}
                          </Button>
                          <Button variant="ghost" className="text-bad" onClick={() => setDel(a)}>
                            {t('Delete')}
                          </Button>
                        </>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {modal && <WebsiteForm site={modal.site} onClose={() => setModal(null)} onSaved={reload} />}
      {del && (
        <FormModal
          title={t('Delete {name}?', { name: del.name })}
          submitLabel={t('Delete permanently')}
          danger
          onClose={() => setDel(null)}
          onSubmit={async () => {
            await api.del(`/assets/${del.id}`);
            reload();
          }}
        >
          <p className="text-sm text-muted">{t('This removes the asset and its check history, alerts and findings. It cannot be undone. Pausing keeps the history instead.')}</p>
        </FormModal>
      )}
    </>
  );
}
