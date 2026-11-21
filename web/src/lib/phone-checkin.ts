import { api } from './api';

/**
 * When SENTINEL is opened on a phone or tablet, tell the PC what the browser knows about the device
 * (system version, model, battery, home-screen app). Nothing runs on a PC. At most once per 10 minutes.
 */
const ID_KEY = 'sentinel-phone-id';
const LAST_KEY = 'sentinel-phone-checkin';
const EVERY_MS = 10 * 60_000;

type UAData = { getHighEntropyValues?: (h: string[]) => Promise<{ platformVersion?: string; model?: string }> };
type BatteryNav = { getBattery?: () => Promise<{ level: number; charging: boolean }> };

const store = {
  get: (k: string) => {
    try {
      return localStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set: (k: string, v: string) => {
    try {
      localStorage.setItem(k, v);
    } catch {
      /* private mode: a new id next time is fine */
    }
  },
};

export function isPhoneOrTablet(): boolean {
  const ua = navigator.userAgent;
  return /Android|iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
}

function deviceId(): string {
  let id = store.get(ID_KEY);
  if (!id || !/^[a-z0-9-]{8,64}$/i.test(id)) {
    id = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `p-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    store.set(ID_KEY, id);
  }
  return id;
}

export async function phoneCheckin(force = false): Promise<void> {
  if (!isPhoneOrTablet()) return;
  const last = Number(store.get(LAST_KEY)) || 0;
  if (!force && Date.now() - last < EVERY_MS) return;
  store.set(LAST_KEY, String(Date.now()));
  const hints: Record<string, unknown> = { touch: navigator.maxTouchPoints > 1 };
  try {
    const ch = await (navigator as Navigator & { userAgentData?: UAData }).userAgentData?.getHighEntropyValues?.(['platformVersion', 'model']);
    if (ch) Object.assign(hints, { platformVersion: ch.platformVersion, model: ch.model });
  } catch {
    /* not offered (Safari, Firefox) */
  }
  try {
    const b = await (navigator as Navigator & BatteryNav).getBattery?.();
    if (b) hints.battery = { level: b.level, charging: b.charging };
  } catch {
    /* iPhone / iPad do not share the battery */
  }
  hints.standalone = matchMedia('(display-mode: standalone)').matches || (navigator as Navigator & { standalone?: boolean }).standalone === true;
  try {
    await api.post('/device-health/phone-checkin', { id: deviceId(), hints });
  } catch {
    /* best effort: never bother the user */
  }
}
