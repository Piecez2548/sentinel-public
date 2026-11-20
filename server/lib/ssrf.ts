import dns from 'node:dns';
import net from 'node:net';

/**
 * SSRF guard. A URL field that the server fetches is an SSRF vector, so every
 * connection is validated against private / loopback / link-local ranges
 * (this also covers cloud metadata at 169.254.169.254).
 *
 * Set ALLOW_PRIVATE_TARGETS=true to monitor things on your own LAN / localhost.
 */

const blocked = new net.BlockList();
for (const [addr, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blocked.addSubnet(addr, prefix, 'ipv4');
}
for (const [addr, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  blocked.addSubnet(addr, prefix, 'ipv6');
}

export function allowPrivate(): boolean {
  return process.env.ALLOW_PRIVATE_TARGETS === 'true';
}

export function isBlockedAddress(ip: string): boolean {
  const family = net.isIPv6(ip) ? 'ipv6' : 'ipv4';
  return blocked.check(ip, family);
}

function bareHost(hostname: string): string {
  return hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
}

/** Synchronous checks on the URL itself (scheme, credentials, literal IPs, obvious local names). */
export function assertUrlAllowed(raw: string | URL): URL {
  const url = typeof raw === 'string' ? new URL(raw) : raw;
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http:// and https:// URLs are allowed');
  }
  if (url.username || url.password) {
    throw new Error('URLs with embedded credentials are not allowed');
  }
  if (!allowPrivate()) {
    const host = bareHost(url.hostname).toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) {
      throw new Error('Private/local targets are blocked');
    }
    if (net.isIP(host) && isBlockedAddress(host)) {
      throw new Error('Private/local targets are blocked');
    }
  }
  return url;
}

/**
 * DNS lookup used at connect time, so the address we validate is the address
 * we actually connect to (defeats DNS rebinding and redirect-to-internal tricks).
 */
export function safeLookup(
  hostname: string,
  options: dns.LookupOptions,
  cb: (err: Error | null, address?: string | dns.LookupAddress[], family?: number) => void,
) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return cb(err);
    const list = addresses as dns.LookupAddress[];
    if (!allowPrivate()) {
      const bad = list.find((a) => isBlockedAddress(a.address));
      if (bad) return cb(new Error(`Blocked address ${bad.address} (private/local target)`));
    }
    if (options.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}
