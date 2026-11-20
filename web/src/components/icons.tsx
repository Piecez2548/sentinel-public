import type { ReactNode } from 'react';

const I = ({ children, size = 18 }: { children: ReactNode; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    {children}
  </svg>
);

export const Icon = {
  overview: () => (
    <I>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </I>
  ),
  server: () => (
    <I>
      <rect x="3" y="4" width="18" height="7" rx="1.5" />
      <rect x="3" y="13" width="18" height="7" rx="1.5" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </I>
  ),
  heart: () => (
    <I>
      <path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10Z" />
      <path d="M8 12h2l1-2 2 4 1-2h2" />
    </I>
  ),
  globe: () => (
    <I>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
    </I>
  ),
  shield: () => (
    <I>
      <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3Z" />
      <path d="m9 12 2 2 4-4" />
    </I>
  ),
  logs: () => (
    <I>
      <path d="M4 6h16M4 10h16M4 14h10M4 18h7" />
    </I>
  ),
  incident: () => (
    <I>
      <path d="M12 3 2 20h20L12 3Z" />
      <path d="M12 10v4M12 17h.01" />
    </I>
  ),
  bell: () => (
    <I>
      <path d="M6 8a6 6 0 1 1 12 0c0 7 3 8 3 8H3s3-1 3-8" />
      <path d="M10 20a2 2 0 0 0 4 0" />
    </I>
  ),
  box: () => (
    <I>
      <path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z" />
      <path d="m4 7.5 8 4.5 8-4.5M12 12v9" />
    </I>
  ),
  chart: () => (
    <I>
      <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />
    </I>
  ),
  settings: () => (
    <I>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" />
    </I>
  ),
  power: () => (
    <I>
      <path d="M12 3v9M18.4 6.6a9 9 0 1 1-12.8 0" />
    </I>
  ),
  lock: () => (
    <I size={22}>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </I>
  ),
  moon: () => (
    <I size={22}>
      <path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5Z" />
    </I>
  ),
  hibernate: () => (
    <I size={22}>
      <path d="M12 3v12M7 10l5 5 5-5M4 19h16" />
    </I>
  ),
  restart: () => (
    <I size={22}>
      <path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v4h-4" />
    </I>
  ),
  powerLg: () => (
    <I size={22}>
      <path d="M12 3v9M18.4 6.6a9 9 0 1 1-12.8 0" />
    </I>
  ),
  logout: () => (
    <I size={16}>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
    </I>
  ),
  logo: () => (
    <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden>
      <defs>
        <linearGradient id="lg" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stopColor="#a78bfa" />
          <stop offset="1" stopColor="#38bdf8" />
        </linearGradient>
      </defs>
      <path d="M16 2 4 7v8c0 7 5 12.5 12 15 7-2.5 12-8 12-15V7L16 2Z" fill="url(#lg)" opacity=".9" />
      <circle cx="16" cy="15" r="4.5" fill="#0b0a10" />
      <circle cx="16" cy="15" r="2" fill="#a78bfa" />
    </svg>
  ),
};
