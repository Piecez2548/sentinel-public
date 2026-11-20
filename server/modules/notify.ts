import { Router } from 'express';
import { all, get, getSetting, run, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/bus.js';
import { decrypt, encrypt } from '../lib/crypto.js';
import { L } from '../lib/i18n.js';
import { registerComponent, reportError, reportOk } from '../lib/health.js';
import { body, clientIp, HttpError, idParam, str } from '../lib/http.js';
import { escHtml } from '../lib/util.js';
import { deviceOf, stepUp } from './auth.js';

/**
 * Durable notification queue (ADR-004): every message is a row in
 * notification_deliveries, retried with backoff, survives restarts.
 */

type TelegramConfig = { botToken: string; chatId: string };
type Channel = { id: number; type: string; name: string; config_enc: string; enabled: number; created_at: number };

const BACKOFF_MS = [30_000, 120_000, 600_000, 1_800_000];
const MAX_ATTEMPTS = 5;

registerComponent('telegram', 'Telegram delivery');

export type NotifyKind =
  | 'alert_fired'
  | 'alert_resolved'
  | 'alert_reminder'
  | 'finding'
  | 'incident'
  | 'digest'
  | 'test'
  | 'system';

/** Queue a message (HTML) for every enabled channel. Returns number of deliveries created. */
/** "🔐 Security change: … from <device>" — sent for every change that weakens or redirects protection. */
export function securityNotice(en: string, th: string, req?: import('express').Request) {
  const from = req ? deviceOf(req) : null;
  const ip = req ? clientIp(req) : null;
  enqueue(
    'system',
    'security',
    `🔐 <b>${escHtml(L(`Security change: ${en}`, `มีการเปลี่ยนการตั้งค่าความปลอดภัย: ${th}`))}</b>` +
      (from ? `\n${escHtml(L(`From ${from} (${ip})`, `จาก ${from} (${ip})`))}` : '') +
      `\n\n${escHtml(L("If this wasn't you: SENTINEL → Settings → sign out all sessions, then change your password.", 'ถ้าไม่ใช่คุณ: SENTINEL → ตั้งค่า → ออกจากระบบทุกเครื่อง แล้วเปลี่ยนรหัสผ่าน'))}`,
  );
}

/** Sends right away on one channel (used to warn on a channel before it is changed or deleted). */
async function warnOn(c: Channel, en: string, th: string, req: import('express').Request) {
  try {
    await sendTelegram(channelConfig(c), `🔐 <b>${escHtml(L(`Security change: ${en}`, `มีการเปลี่ยนการตั้งค่าความปลอดภัย: ${th}`))}</b>\n${escHtml(L(`From ${deviceOf(req)} (${clientIp(req)})`, `จาก ${deviceOf(req)} (${clientIp(req)})`))}`);
  } catch {
    /* best effort */
  }
}

export function enqueue(kind: NotifyKind, ref: string | null, html: string): number {
  console.log(`[notify] ${kind}: ${html.replace(/<[^>]+>/g, '').replace(/\n/g, ' | ')}`);
  const channels = all<{ id: number }>('SELECT id FROM notification_channels WHERE enabled = 1');
  const now = Date.now();
  for (const c of channels) {
    run(
      'INSERT INTO notification_deliveries (channel_id, kind, ref, message, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      c.id, kind, ref, html, 'pending', now, now,
    );
  }
  if (channels.length) publish('notifications');
  return channels.length;
}

class PermanentError extends Error {}

async function sendTelegram(cfg: TelegramConfig, html: string): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`https://api.telegram.org/bot${cfg.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: cfg.chatId, text: html.slice(0, 4000), parse_mode: 'HTML', disable_web_page_preview: true }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch (e) {
    // Never let the token leak into error text.
    const msg = e instanceof Error ? ((e as Error & { cause?: { code?: string } }).cause?.code ?? e.message) : String(e);
    throw new Error(msg.split(cfg.botToken).join('***'));
  }
  if (res.ok) return;
  const data = (await res.json().catch(() => ({}))) as { description?: string };
  const msg = `HTTP ${res.status}${data.description ? `: ${data.description}` : ''}`;
  if (res.status >= 400 && res.status < 500 && res.status !== 429) throw new PermanentError(msg);
  throw new Error(msg);
}

function channelConfig(c: Channel): TelegramConfig {
  return JSON.parse(decrypt(c.config_enc)) as TelegramConfig;
}

/** Dispatcher tick: send due deliveries. */
export async function dispatch() {
  if (!get('SELECT id FROM notification_channels WHERE enabled = 1 LIMIT 1')) {
    reportOk('telegram', 'No channel configured — alerts are shown in the dashboard only');
    return;
  }
  const due = all<{ id: number; channel_id: number; message: string; attempts: number }>(
    `SELECT d.id, d.channel_id, d.message, d.attempts FROM notification_deliveries d
       JOIN notification_channels c ON c.id = d.channel_id
     WHERE d.status = 'pending' AND d.next_attempt_at <= ? AND c.enabled = 1
     ORDER BY d.id LIMIT 20`,
    Date.now(),
  );
  for (const d of due) {
    const ch = get<Channel>('SELECT * FROM notification_channels WHERE id = ?', d.channel_id);
    if (!ch) continue;
    const attempts = d.attempts + 1;
    try {
      await sendTelegram(channelConfig(ch), d.message);
      run("UPDATE notification_deliveries SET status = 'sent', attempts = ?, sent_at = ?, last_error = NULL WHERE id = ?", attempts, Date.now(), d.id);
      reportOk('telegram', 'Last message delivered');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const permanent = e instanceof PermanentError || attempts >= MAX_ATTEMPTS;
      run(
        'UPDATE notification_deliveries SET status = ?, attempts = ?, last_error = ?, next_attempt_at = ? WHERE id = ?',
        permanent ? 'failed' : 'pending', attempts, msg, Date.now() + BACKOFF_MS[Math.min(attempts - 1, BACKOFF_MS.length - 1)], d.id,
      );
      reportError('telegram', `Delivery failed: ${msg}${permanent ? '' : ' (will retry)'}`);
    }
    publish('notifications');
  }
}

/** Seed a Telegram channel from env vars (prototype compatibility). */
export function importEnvChannel() {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chat = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chat) return;
  if (get('SELECT id FROM notification_channels LIMIT 1')) return;
  run(
    'INSERT INTO notification_channels (type, name, config_enc, enabled, created_at) VALUES (?, ?, ?, 1, ?)',
    'telegram', 'Telegram', encrypt(JSON.stringify({ botToken: token, chatId: chat })), Date.now(),
  );
  console.log('[notify] imported Telegram channel from .env');
}

/* ---------- daily digest (also acts as dead-man's switch) ---------- */

export function maybeSendDigest(buildDigest: () => string) {
  if (getSetting('digest_enabled') === 'false') return;
  const hour = Number(getSetting('digest_hour') ?? 8);
  const now = new Date();
  const today = now.toDateString();
  if (now.getHours() < hour || getSetting('digest_last_day') === today) return;
  setSetting('digest_last_day', today);
  enqueue('digest', null, buildDigest());
}

/* ---------- API ---------- */

export const notifyRouter = Router();

function maskToken(t: string) {
  return t.length > 10 ? `${t.slice(0, 4)}…${t.slice(-4)}` : '••••';
}

notifyRouter.get('/channels', (_req, res) => {
  const rows = all<Channel>('SELECT * FROM notification_channels ORDER BY id');
  res.json({
    channels: rows.map((c) => {
      let cfg: TelegramConfig | null = null;
      try {
        cfg = channelConfig(c);
      } catch {
        /* undecryptable (master key changed) */
      }
      return {
        id: c.id,
        type: c.type,
        name: c.name,
        enabled: !!c.enabled,
        chatId: cfg?.chatId ?? null,
        tokenHint: cfg ? maskToken(cfg.botToken) : 'unreadable — re-enter token',
        createdAt: c.created_at,
      };
    }),
  });
});

function parseTelegram(b: Record<string, unknown>, existing?: TelegramConfig): TelegramConfig {
  const token = str(b.botToken, 'Bot token', { optional: !!existing, max: 200 }) ?? existing!.botToken;
  const chat = str(b.chatId, 'Chat ID', { optional: !!existing, max: 64 }) ?? existing!.chatId;
  if (!/^\d+:[A-Za-z0-9_-]{20,}$/.test(token)) throw new HttpError(400, 'Bot token format looks wrong (expected 123456:ABC…)');
  if (!/^-?\d+$|^@[A-Za-z0-9_]{4,}$/.test(chat)) throw new HttpError(400, 'Chat ID should be a number (or @channelname)');
  return { botToken: token, chatId: chat };
}

notifyRouter.post('/channels', stepUp, (req, res) => {
  const b = body(req);
  const cfg = parseTelegram(b);
  const name = str(b.name, 'Name', { optional: true, max: 60 }) ?? 'Telegram';
  const r = run(
    'INSERT INTO notification_channels (type, name, config_enc, enabled, created_at) VALUES (?, ?, ?, 1, ?)',
    'telegram', name, encrypt(JSON.stringify(cfg)), Date.now(),
  );
  audit('channel.created', { ip: clientIp(req), resourceType: 'channel', resourceId: Number(r.lastInsertRowid), detail: { name, chatId: cfg.chatId } });
  publish('notifications', 'health');
  res.status(201).json({ id: Number(r.lastInsertRowid) });
});

notifyRouter.put('/channels/:id', stepUp, async (req, res) => {
  const id = idParam(req);
  const ch = get<Channel>('SELECT * FROM notification_channels WHERE id = ?', id);
  if (!ch) throw new HttpError(404, 'Not found');
  await warnOn(ch, `Telegram channel "${ch.name}" is being changed`, `กำลังแก้ไขช่อง Telegram "${ch.name}"`, req);
  const b = body(req);
  let existing: TelegramConfig | undefined;
  try {
    existing = channelConfig(ch);
  } catch {
    existing = undefined;
  }
  const cfg = parseTelegram(b, existing);
  const enabled = b.enabled === undefined ? ch.enabled : b.enabled ? 1 : 0;
  run('UPDATE notification_channels SET config_enc = ?, enabled = ?, name = ? WHERE id = ?', encrypt(JSON.stringify(cfg)), enabled, str(b.name, 'Name', { optional: true, max: 60 }) ?? ch.name, id);
  audit('channel.updated', { ip: clientIp(req), resourceType: 'channel', resourceId: id, detail: { enabled: !!enabled, chatId: cfg.chatId } });
  publish('notifications');
  res.json({ ok: true });
});

notifyRouter.delete('/channels/:id', stepUp, async (req, res) => {
  const id = idParam(req);
  const ch = get<Channel>('SELECT * FROM notification_channels WHERE id = ?', id);
  if (ch) await warnOn(ch, `Telegram channel "${ch.name}" is being deleted`, `กำลังลบช่อง Telegram "${ch.name}"`, req);
  run('DELETE FROM notification_channels WHERE id = ?', id);
  audit('channel.deleted', { ip: clientIp(req), resourceType: 'channel', resourceId: id });
  publish('notifications');
  res.json({ ok: true });
});

notifyRouter.post('/channels/:id/test', async (req, res) => {
  const ch = get<Channel>('SELECT * FROM notification_channels WHERE id = ?', idParam(req));
  if (!ch) throw new HttpError(404, 'Not found');
  const msg = L('✅ <b>SENTINEL</b> test message — Telegram alerts are working.', '✅ <b>SENTINEL</b> ข้อความทดสอบ — การแจ้งเตือนทาง Telegram ใช้งานได้');
  try {
    await sendTelegram(channelConfig(ch), msg);
    run(
      "INSERT INTO notification_deliveries (channel_id, kind, message, status, attempts, next_attempt_at, created_at, sent_at) VALUES (?, 'test', ?, 'sent', 1, ?, ?, ?)",
      ch.id, msg, Date.now(), Date.now(), Date.now(),
    );
    reportOk('telegram', 'Test message delivered');
    publish('notifications', 'health');
    res.json({ ok: true });
  } catch (e) {
    const m = e instanceof Error ? e.message : String(e);
    run(
      "INSERT INTO notification_deliveries (channel_id, kind, message, status, attempts, next_attempt_at, created_at, last_error) VALUES (?, 'test', ?, 'failed', 1, ?, ?, ?)",
      ch.id, msg, Date.now(), Date.now(), m,
    );
    publish('notifications');
    throw new HttpError(502, `Telegram rejected the message: ${m}`);
  }
});

notifyRouter.get('/deliveries', (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const rows = all<{ id: number; kind: string; ref: string | null; message: string; status: string; attempts: number; last_error: string | null; created_at: number; sent_at: number | null; next_attempt_at: number; channel: string }>(
    `SELECT d.*, c.name AS channel FROM notification_deliveries d JOIN notification_channels c ON c.id = d.channel_id
     ORDER BY d.id DESC LIMIT ?`,
    limit,
  );
  res.json({
    deliveries: rows.map((d) => ({
      id: d.id,
      kind: d.kind,
      channel: d.channel,
      preview: d.message.replace(/<[^>]+>/g, '').slice(0, 160),
      status: d.status,
      attempts: d.attempts,
      lastError: d.last_error,
      createdAt: d.created_at,
      sentAt: d.sent_at,
      nextAttemptAt: d.status === 'pending' ? d.next_attempt_at : null,
    })),
  });
});

notifyRouter.post('/deliveries/:id/retry', (req, res) => {
  const id = idParam(req);
  run("UPDATE notification_deliveries SET status = 'pending', next_attempt_at = ? WHERE id = ? AND status = 'failed'", Date.now(), id);
  publish('notifications');
  res.json({ ok: true });
});

export const html = { esc: escHtml };
