/**
 * WebAuthn relying party for the address SENTINEL was opened on. The phone uses
 * https://<pc>.<tailnet>.ts.net:8443 (tailscale serve), the PC uses http://localhost:3001.
 * WebAuthn needs a domain name: an IP address (http://127.0.0.1) cannot use fingerprints.
 * The browser signs the real origin into every fingerprint response, and the server checks it
 * against this one, so a forged Host header cannot make a response from another site count.
 */
export function relyingParty(host: string | undefined): { rpID: string; origin: string } | null {
  if (!host || !/^[a-z0-9.-]+(:\d{1,5})?$/i.test(host)) return null;
  const hostname = host.replace(/:\d+$/, '').toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || !hostname.includes('.') && hostname !== 'localhost') return null;
  const proto = hostname === 'localhost' ? 'http' : 'https';
  return { rpID: hostname, origin: `${proto}://${host.toLowerCase()}` };
}
