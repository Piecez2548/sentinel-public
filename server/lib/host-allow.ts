/**
 * Which Host header values SENTINEL answers (DNS-rebinding guard).
 * Allowed: IP literals (a rebinding page cannot own those), localhost, Tailscale `*.ts.net` names, and any
 * extra names in ALLOWED_HOSTS (comma separated, e.g. when serving on a LAN name).
 */
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function extra(): Set<string> {
  return new Set(
    String(process.env.ALLOWED_HOSTS ?? '')
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
  );
}

/** The name part of a Host header, lower-cased, without the port; null when it is malformed. */
export function hostName(header: string | undefined): string | null {
  const h = String(header ?? '').trim().toLowerCase();
  if (!h || h.length > 255) return null;
  const v6 = /^\[([0-9a-f:.]+)\](?::\d{1,5})?$/.exec(h);
  if (v6) return `[${v6[1]}]`;
  const m = /^([a-z0-9.-]+)(?::\d{1,5})?$/.exec(h);
  return m ? m[1].replace(/\.$/, '') : null;
}

export function hostAllowed(header: string | undefined): boolean {
  const name = hostName(header);
  if (!name) return false;
  if (name.startsWith('[') || IPV4.test(name)) return true;
  if (name === 'localhost' || name.endsWith('.localhost')) return true;
  if (/^[a-z0-9-]+\.[a-z0-9-]+\.ts\.net$/.test(name)) return true;
  return extra().has(name);
}
