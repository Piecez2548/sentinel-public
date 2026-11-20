import { useState } from 'react';
import { Button, Card, Empty, ErrorNote, Field, FormModal, Input, PageHeader, Select, SevBadge, StateBadge, Tabs, Td, Th, Toggle } from '../components/ui';
import { api, type AlertEvent, type Asset } from '../lib/api';
import { ago, duration, sevLabel, stamp } from '../lib/format';
import { t, tk } from '../lib/i18n';
import { useApi, useTick } from '../lib/hooks';

type RuleType = { type: string; label: string; params: Record<string, number>; usesFor: boolean; assetType: 'host' | 'website' | null };
type Rule = { id: number; name: string; type: string; typeLabel: string; assetId: number | null; assetName: string | null; params: Record<string, number>; severity: string; forSec: number; cooldownSec: number; enabled: boolean; builtin: boolean; active: number };
type Channel = { id: number; type: string; name: string; enabled: boolean; chatId: string | null; tokenHint: string; createdAt: number };
type Delivery = { id: number; kind: string; channel: string; preview: string; status: string; attempts: number; lastError: string | null; createdAt: number; sentAt: number | null; nextAttemptAt: number | null };

const PARAM_LABEL: Record<string, string> = { threshold: 'Threshold (%)', thresholdMs: 'Threshold (ms)', samples: 'Checks to average', minutes: 'Minutes', days: 'Days before expiry' };
const paramLabel = (k: string) => t(PARAM_LABEL[k] ?? k);
const typeLabel = (type: string, label: string) => tk(`alertType.${type}`, label);

function describeRule(r: Rule) {
  const p = Object.entries(r.params).map(([k, v]) => `${paramLabel(k)}: ${v}`);
  if (r.forSec) p.push(t('for {d}', { d: duration(r.forSec * 1000) }));
  return p.join(' · ') || '—';
}

function RuleForm({ rule, types, onClose, onSaved }: { rule: Rule | null; types: RuleType[]; onClose: () => void; onSaved: () => void }) {
  const [type, setType] = useState(rule?.type ?? types[0]?.type ?? 'host_cpu');
  const info = types.find((x) => x.type === type)!;
  const [name, setName] = useState(rule?.name ?? '');
  const [severity, setSeverity] = useState(rule?.severity ?? 'high');
  const [forMin, setForMin] = useState(String((rule?.forSec ?? 300) / 60));
  const [cooldownMin, setCooldownMin] = useState(String((rule?.cooldownSec ?? 3600) / 60));
  const [assetId, setAssetId] = useState(rule?.assetId ? String(rule.assetId) : '');
  const [params, setParams] = useState<Record<string, string>>(Object.fromEntries(Object.entries(rule?.params ?? info?.params ?? {}).map(([k, v]) => [k, String(v)])));
  const { data: assets } = useApi(() => api.get<{ assets: Asset[] }>('/assets'), []);

  return (
    <FormModal
      title={rule ? t('Edit rule: {name}', { name: rule.name }) : t('New alert rule')}
      onClose={onClose}
      onSubmit={async () => {
        const b = {
          name: name || typeLabel(info.type, info.label),
          type,
          severity,
          forSec: info.usesFor ? Math.round(Number(forMin) * 60) : 0,
          cooldownSec: Math.round(Number(cooldownMin) * 60),
          assetId: assetId ? Number(assetId) : null,
          params: Object.fromEntries(Object.entries(params).map(([k, v]) => [k, Number(v)])),
        };
        if (rule) await api.put(`/alerts/rules/${rule.id}`, b);
        else await api.post('/alerts/rules', b);
        onSaved();
      }}
    >
      {!rule && (
        <Field label={t('Condition')}>
          <Select
            value={type}
            onChange={(e) => {
              setType(e.target.value);
              const sel = types.find((x) => x.type === e.target.value)!;
              setParams(Object.fromEntries(Object.entries(sel.params).map(([k, v]) => [k, String(v)])));
            }}
          >
            {types.map((x) => (
              <option key={x.type} value={x.type}>
                {typeLabel(x.type, x.label)}
              </option>
            ))}
          </Select>
        </Field>
      )}
      <Field label={t('Name')}>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={info ? typeLabel(info.type, info.label) : ''} />
      </Field>
      {info?.assetType && (
        <Field label={t('Applies to')}>
          <Select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
            <option value="">{info.assetType === 'host' ? t('All hosts') : t('All websites')}</option>
            {assets?.assets
              .filter((a) => a.type === info.assetType)
              .map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
          </Select>
        </Field>
      )}
      <div className="grid grid-cols-2 gap-3">
        {Object.keys(info?.params ?? {}).map((k) => (
          <Field key={k} label={paramLabel(k)}>
            <Input type="number" min={1} value={params[k] ?? ''} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />
          </Field>
        ))}
        {info?.usesFor && (
          <Field label={t('Sustained for (minutes)')} hint={t('Average over this window must exceed the threshold.')}>
            <Input type="number" min={1} value={forMin} onChange={(e) => setForMin(e.target.value)} />
          </Field>
        )}
        <Field label={t('Severity')}>
          <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {['low', 'medium', 'high', 'critical'].map((s) => (
              <option key={s} value={s}>{sevLabel(s)}</option>
            ))}
          </Select>
        </Field>
        <Field label={t('Remind every (minutes)')} hint={t('While still firing and not acknowledged. Prevents alert spam.')}>
          <Input type="number" min={5} value={cooldownMin} onChange={(e) => setCooldownMin(e.target.value)} />
        </Field>
      </div>
    </FormModal>
  );
}

function ChannelForm({ channel, onClose, onSaved }: { channel: Channel | null; onClose: () => void; onSaved: () => void }) {
  const [botToken, setToken] = useState('');
  const [chatId, setChat] = useState(channel?.chatId ?? '');
  return (
    <FormModal
      title={channel ? t('Edit Telegram channel') : t('Connect Telegram')}
      onClose={onClose}
      onSubmit={async () => {
        const b: Record<string, string> = { chatId };
        if (botToken) b.botToken = botToken;
        if (channel) await api.put(`/notifications/channels/${channel.id}`, b);
        else await api.post('/notifications/channels', { ...b, name: 'Telegram' });
        onSaved();
      }}
    >
      <ol className="list-decimal space-y-1 pl-5 text-xs text-muted">
        <li>{t('In Telegram, talk to @BotFather → /newbot → copy the token.')}</li>
        <li>{t('Open your new bot, press Start and send it any message.')}</li>
        <li>
          {t('Open')} <code className="text-slate-300">https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</code> {t('and copy')} <code className="text-slate-300">chat.id</code>. {t('(Or ask @userinfobot for your Id.) Close that tab afterwards — the URL contains your token.')}
        </li>
      </ol>
      <Field label={t('Bot token')} hint={channel ? t('Current: {hint}. Leave empty to keep it.', { hint: channel.tokenHint }) : t('Stored encrypted; never shown again in full.')}>
        <Input type="password" autoComplete="off" value={botToken} onChange={(e) => setToken(e.target.value)} placeholder="123456789:AA…" />
      </Field>
      <Field label="Chat ID">
        <Input value={chatId} onChange={(e) => setChat(e.target.value)} placeholder="123456789" />
      </Field>
    </FormModal>
  );
}

export default function AlertsPage({ go: _go }: { go: (p: string) => void }) {
  useTick();
  const [tab, setTab] = useState<'active' | 'history' | 'rules' | 'channels'>('active');
  const events = useApi(() => api.get<{ events: AlertEvent[] }>(`/alerts/events?status=${tab === 'history' ? 'all' : 'active'}&limit=200`), [tab], ['alerts']);
  const rules = useApi(() => api.get<{ types: RuleType[]; rules: Rule[] }>('/alerts/rules'), [], ['alerts']);
  const channels = useApi(() => api.get<{ channels: Channel[] }>('/notifications/channels'), [], ['notifications']);
  const deliveries = useApi(() => api.get<{ deliveries: Delivery[] }>('/notifications/deliveries?limit=50'), [], ['notifications']);
  const [ruleForm, setRuleForm] = useState<{ rule: Rule | null } | null>(null);
  const [channelForm, setChannelForm] = useState<{ channel: Channel | null } | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const active = (events.data?.events ?? []).filter((e) => e.status !== 'resolved');

  return (
    <>
      <PageHeader title={t('Alert Manager')} subtitle={t('Threshold rules, deduplicated alerts, reminders and Telegram delivery with retry')} />
      <ErrorNote error={events.error ?? rules.error} />
      {msg && <div className={`mb-4 rounded-xl px-4 py-2.5 text-sm ${msg.ok ? 'border border-ok/40 bg-ok/10 text-ok' : 'border border-bad/40 bg-bad/10 text-bad'}`}>{msg.text}</div>}
      <Tabs
        value={tab}
        onChange={(v) => {
          setTab(v);
          setMsg(null);
        }}
        tabs={[
          { value: 'active', label: t('Active ({n})', { n: active.length }) },
          { value: 'history', label: t('History') },
          { value: 'rules', label: t('Rules') },
          { value: 'channels', label: t('Notifications') },
        ]}
      />

      {(tab === 'active' || tab === 'history') && (
        <Card pad={false}>
          {!events.data?.events.length ? (
            <Empty>{tab === 'active' ? t('No active alerts ✓') : t('No alerts yet.')}</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-line">
                  <tr>
                    <Th>{t('Severity')}</Th>
                    <Th>{t('Alert')}</Th>
                    <Th>{t('Status')}</Th>
                    <Th>{t('Triggered')}</Th>
                    <Th>{t('Duration')}</Th>
                    <Th />
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {events.data.events.map((e) => (
                    <tr key={e.id}>
                      <Td>
                        <SevBadge sev={e.severity} />
                      </Td>
                      <Td>
                        <div>{e.title}</div>
                        <div className="text-xs text-muted">
                          {e.detail} · {t('rule')} “{e.ruleName ?? t('deleted')}”
                        </div>
                      </Td>
                      <Td>
                        <StateBadge state={e.status} />
                      </Td>
                      <Td className="whitespace-nowrap text-xs text-muted" >{stamp(e.triggeredAt)}</Td>
                      <Td className="whitespace-nowrap text-xs">{duration((e.resolvedAt ?? Date.now()) - e.triggeredAt)}</Td>
                      <Td className="text-right">
                        {e.status === 'firing' && (
                          <Button
                            onClick={async () => {
                              await api.post(`/alerts/events/${e.id}/ack`);
                              events.reload();
                            }}
                          >
                            {t('Acknowledge')}
                          </Button>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {tab === 'rules' && (
        <Card pad={false} title={t('Alert rules')} right={<Button variant="primary" onClick={() => setRuleForm({ rule: null })}>{t('+ New rule')}</Button>}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line">
                <tr>
                  <Th>{t('On')}</Th>
                  <Th>{t('Rule')}</Th>
                  <Th>{t('Applies to')}</Th>
                  <Th>{t('Condition')}</Th>
                  <Th>{t('Severity')}</Th>
                  <Th>{t('Reminder')}</Th>
                  <Th>{t('Firing')}</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rules.data?.rules.map((r) => (
                  <tr key={r.id}>
                    <Td>
                      <Toggle
                        checked={r.enabled}
                        onChange={async (v) => {
                          await api.put(`/alerts/rules/${r.id}`, { enabled: v });
                          rules.reload();
                        }}
                      />
                    </Td>
                    <Td>
                      <div>{r.builtin ? tk(`alertRule.${r.name}`, r.name) : r.name}</div>
                      <div className="text-xs text-muted">{typeLabel(r.type, r.typeLabel)}</div>
                    </Td>
                    <Td className="text-xs text-muted">{r.assetName ?? t('All')}</Td>
                    <Td className="text-xs">{describeRule(r)}</Td>
                    <Td>
                      <SevBadge sev={r.severity} />
                    </Td>
                    <Td className="text-xs text-muted">{t('every {d}', { d: duration(r.cooldownSec * 1000) })}</Td>
                    <Td className={`text-xs ${r.active ? 'text-bad' : 'text-muted'}`}>{r.active}</Td>
                    <Td className="whitespace-nowrap text-right">
                      <Button variant="ghost" onClick={() => setRuleForm({ rule: r })}>
                        {t('Edit')}
                      </Button>
                      {!r.builtin && (
                        <Button
                          variant="ghost"
                          className="text-bad"
                          onClick={async () => {
                            if (!confirm(t('Delete rule "{name}"?', { name: r.name }))) return;
                            await api.del(`/alerts/rules/${r.id}`);
                            rules.reload();
                          }}
                        >
                          {t('Delete')}
                        </Button>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {tab === 'channels' && (
        <div className="space-y-4">
          <Card title="Telegram" right={!channels.data?.channels.length && <Button variant="primary" onClick={() => setChannelForm({ channel: null })}>{t('Connect Telegram')}</Button>}>
            {!channels.data?.channels.length ? (
              <Empty>{t('Not connected. Alerts are shown in the dashboard only until you connect Telegram.')}</Empty>
            ) : (
              <ul className="space-y-2">
                {channels.data.channels.map((c) => (
                  <li key={c.id} className="flex flex-wrap items-center gap-3 rounded-lg bg-panel-2 px-3 py-2 text-sm">
                    <Toggle
                      checked={c.enabled}
                      onChange={async (v) => {
                        await api.put(`/notifications/channels/${c.id}`, { enabled: v });
                        channels.reload();
                      }}
                    />
                    <span className="flex-1">
                      {c.name} <span className="text-xs text-muted">· chat {c.chatId} · token {c.tokenHint}</span>
                    </span>
                    <Button
                      onClick={async () => {
                        setMsg(null);
                        try {
                          await api.post(`/notifications/channels/${c.id}/test`);
                          setMsg({ ok: true, text: t('Test message sent — check Telegram.') });
                        } catch (e) {
                          setMsg({ ok: false, text: e instanceof Error ? t(e.message) : t('Failed') });
                        }
                        deliveries.reload();
                      }}
                    >
                      {t('Send test')}
                    </Button>
                    <Button variant="ghost" onClick={() => setChannelForm({ channel: c })}>
                      {t('Edit')}
                    </Button>
                    <Button
                      variant="ghost"
                      className="text-bad"
                      onClick={async () => {
                        if (!confirm(t('Disconnect this Telegram channel?'))) return;
                        await api.del(`/notifications/channels/${c.id}`);
                        channels.reload();
                      }}
                    >
                      {t('Remove')}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title={t('Delivery history')} pad={false}>
            {!deliveries.data?.deliveries.length ? (
              <Empty>{t('No messages sent yet.')}</Empty>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="border-b border-line">
                    <tr>
                      <Th>{t('Time')}</Th>
                      <Th>{t('Kind')}</Th>
                      <Th>{t('Message')}</Th>
                      <Th>{t('Status')}</Th>
                      <Th>{t('Attempts')}</Th>
                      <Th />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {deliveries.data.deliveries.map((d) => (
                      <tr key={d.id}>
                        <Td className="whitespace-nowrap text-xs text-muted">{ago(d.createdAt)}</Td>
                        <Td className="text-xs">{tk(`kind.${d.kind}`, d.kind.replace('_', ' '))}</Td>
                        <Td className="max-w-md text-xs">
                          <div className="truncate">{d.preview}</div>
                          {d.lastError && <div className="text-bad">{d.lastError}</div>}
                          {d.nextAttemptAt && <div className="text-warn">{t('next retry in {d}', { d: duration(d.nextAttemptAt - Date.now()) })}</div>}
                        </Td>
                        <Td>
                          <StateBadge state={d.status} />
                        </Td>
                        <Td className="text-xs">{d.attempts}</Td>
                        <Td>
                          {d.status === 'failed' && (
                            <Button
                              variant="ghost"
                              onClick={async () => {
                                await api.post(`/notifications/deliveries/${d.id}/retry`);
                                deliveries.reload();
                              }}
                            >
                              {t('Retry')}
                            </Button>
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}

      {ruleForm && rules.data && <RuleForm rule={ruleForm.rule} types={rules.data.types} onClose={() => setRuleForm(null)} onSaved={rules.reload} />}
      {channelForm && <ChannelForm channel={channelForm.channel} onClose={() => setChannelForm(null)} onSaved={channels.reload} />}
    </>
  );
}
