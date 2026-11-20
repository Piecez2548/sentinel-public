import type { NextFunction, Request, Response } from 'express';

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}
export const badRequest = (m: string) => new HttpError(400, m);
export const notFound = (m = 'Not found') => new HttpError(404, m);

const socketIp = (req: Request) => (req.socket.remoteAddress ?? 'unknown').replace(/^::ffff:/, '');
const isLoopbackIp = (a: string) => a === '127.0.0.1' || a === '::1';

/** Address of the device behind `tailscale serve` (it connects from loopback and adds X-Forwarded-For). */
function forwardedIp(req: Request): string | null {
  if (!isLoopbackIp(socketIp(req))) return null; // only trust the header from the local proxy
  const xff = String(req.headers['x-forwarded-for'] ?? '').split(',').pop()?.trim();
  return xff && /^[0-9a-fA-F:.]{2,45}$/.test(xff) ? xff.replace(/^::ffff:/, '') : null;
}

/** The phone shows as its Tailscale address (100.x), not as 127.0.0.1. */
export function clientIp(req: Request): string {
  return forwardedIp(req) ?? socketIp(req);
}

/** A request typed on this PC itself — not one relayed by tailscale serve (which also arrives from loopback). */
export function isLoopback(req: Request): boolean {
  if (!isLoopbackIp(socketIp(req))) return false;
  return !req.headers['x-forwarded-for'] && !req.headers['tailscale-user-login'] && !req.headers['x-forwarded-host'];
}

type Body = Record<string, unknown>;
export const body = (req: Request): Body => (req.body && typeof req.body === 'object' ? (req.body as Body) : {});

export function str(v: unknown, name: string, opts: { min?: number; max?: number; optional?: boolean } = {}): string | undefined {
  if (v === undefined || v === null || v === '') {
    if (opts.optional) return undefined;
    throw badRequest(`${name} is required`);
  }
  if (typeof v !== 'string') throw badRequest(`${name} must be text`);
  const s = v.trim();
  if (opts.min != null && s.length < opts.min) throw badRequest(`${name} must be at least ${opts.min} characters`);
  if (opts.max != null && s.length > opts.max) throw badRequest(`${name} must be at most ${opts.max} characters`);
  return s;
}

export function num(v: unknown, name: string, opts: { min?: number; max?: number; optional?: boolean; int?: boolean } = {}): number | undefined {
  if (v === undefined || v === null || v === '') {
    if (opts.optional) return undefined;
    throw badRequest(`${name} is required`);
  }
  const n = Number(v);
  if (!Number.isFinite(n)) throw badRequest(`${name} must be a number`);
  if (opts.int && !Number.isInteger(n)) throw badRequest(`${name} must be a whole number`);
  if (opts.min != null && n < opts.min) throw badRequest(`${name} must be ≥ ${opts.min}`);
  if (opts.max != null && n > opts.max) throw badRequest(`${name} must be ≤ ${opts.max}`);
  return n;
}

export function oneOf<T extends string>(v: unknown, name: string, values: readonly T[], optional = false): T | undefined {
  if (v === undefined && optional) return undefined;
  if (typeof v !== 'string' || !values.includes(v as T)) throw badRequest(`${name} must be one of: ${values.join(', ')}`);
  return v as T;
}

export const idParam = (req: Request): number => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) throw notFound();
  return id;
};

export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  if (err instanceof SyntaxError && 'body' in (err as object)) {
    res.status(400).json({ error: 'Invalid JSON' });
    return;
  }
  console.error('[api] unhandled error:', err);
  res.status(500).json({ error: 'Internal error' });
}
