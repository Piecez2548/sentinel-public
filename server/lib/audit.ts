import { all, get, run } from '../db.js';
import { sha256 } from './crypto.js';

const GENESIS = '0'.repeat(64);

type Row = {
  seq: number;
  ts: number;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  detail: string | null;
  ip: string | null;
  prev_hash: string;
  hash: string;
};

function rowHash(prev: string, seq: number, ts: number, action: string, rtype: string | null, rid: string | null, detail: string | null, ip: string | null) {
  return sha256([prev, seq, ts, action, rtype ?? '', rid ?? '', detail ?? '', ip ?? ''].join('|'));
}

/** Never put secrets in `detail`. */
export function audit(action: string, opts: { resourceType?: string; resourceId?: string | number; detail?: unknown; ip?: string } = {}) {
  const last = get<{ seq: number; hash: string }>('SELECT seq, hash FROM audit_logs ORDER BY seq DESC LIMIT 1');
  const prev = last?.hash ?? GENESIS;
  const seq = (last?.seq ?? 0) + 1;
  const ts = Date.now();
  const rtype = opts.resourceType ?? null;
  const rid = opts.resourceId != null ? String(opts.resourceId) : null;
  const detail = opts.detail !== undefined ? JSON.stringify(opts.detail) : null;
  const ip = opts.ip ?? null;
  run(
    'INSERT INTO audit_logs (seq, ts, action, resource_type, resource_id, detail, ip, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    seq, ts, action, rtype, rid, detail, ip, prev, rowHash(prev, seq, ts, action, rtype, rid, detail, ip),
  );
}

export function verifyAuditChain(): { ok: boolean; checked: number; brokenAt?: number; reason?: string } {
  const rows = all<Row>('SELECT * FROM audit_logs ORDER BY seq');
  let prev = GENESIS;
  let expectedSeq = rows[0]?.seq ?? 1;
  for (const r of rows) {
    if (r.seq !== expectedSeq) return { ok: false, checked: rows.length, brokenAt: r.seq, reason: 'gap in sequence (row deleted)' };
    if (r.prev_hash !== prev) return { ok: false, checked: rows.length, brokenAt: r.seq, reason: 'prev_hash mismatch' };
    const h = rowHash(r.prev_hash, r.seq, r.ts, r.action, r.resource_type, r.resource_id, r.detail, r.ip);
    if (h !== r.hash) return { ok: false, checked: rows.length, brokenAt: r.seq, reason: 'row content was modified' };
    prev = r.hash;
    expectedSeq++;
  }
  return { ok: true, checked: rows.length };
}
