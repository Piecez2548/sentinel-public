import express from 'express';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { migrate } from './db.js';
import { HttpError, errorHandler } from './lib/http.js';
import { HOUR, MIN, every } from './lib/util.js';
import { adminExists, authRouter, purgeSessions, requireAuth } from './modules/auth.js';
import { alertsRouter, evaluateAlerts, seedAlertRules } from './modules/alerts.js';
import { assetsRouter } from './modules/assets.js';
import { backupRouter, maybeRestoreDrill, maybeScheduledBackup } from './modules/backup.js';
import { detectionRouter, regradeServiceFindings, runDetection, seedDetectionRules } from './modules/detection.js';
import { seedKnownLogins } from './modules/login-watch.js';
import { collectEventLog } from './modules/eventlog.js';
import { collectHost, ensureLocalHost, markStaleHosts } from './modules/host-collector.js';
import { deviceRouter, DEVICE_HEALTH_EVERY_MS, runDeviceHealth } from './modules/device-health.js';
import { heartbeatConfigured, HEARTBEAT_EVERY_MS, sendHeartbeat } from './modules/heartbeat.js';
import { httpTick } from './modules/http-monitor.js';
import { aiRouter } from './modules/ai.js';
import { autoResolveRecovered, correlate, incidentsRouter } from './modules/incidents.js';
import { dispatch, importEnvChannel, maybeSendDigest, notifyRouter } from './modules/notify.js';
import { reportsRouter, runRollups } from './modules/reports.js';
import { launcherRouter } from './modules/launcher.js';
import { passkeyRouter } from './modules/passkey.js';
import { powerRouter } from './modules/power.js';
import { processesRouter, refreshIfBusy } from './modules/processes.js';
import { scanRouter } from './modules/scan.js';
import { buildDigest, runRetention, systemRouter } from './modules/system.js';
import { maybeAutoScan, withWeekly } from './modules/weekly.js';

const PORT = Number(process.env.PORT ?? 3001);
const HOST = process.env.HOST ?? '127.0.0.1';

migrate();
seedDetectionRules();
seedAlertRules();
importEnvChannel();
ensureLocalHost();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', false);
app.use(express.json({ limit: '64kb' }));

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  );
  next();
});

// Reject cross-site state-changing requests (defence in depth on top of SameSite=Strict cookies).
app.use('/api', (req, _res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.headers.origin;
  if (origin) {
    let host: string | null = null;
    try {
      host = new URL(origin).host;
    } catch {
      /* invalid */
    }
    if (host !== req.headers.host) return next(new HttpError(403, 'Cross-origin request blocked'));
  }
  if (req.headers['content-type'] && !String(req.headers['content-type']).startsWith('application/json')) {
    return next(new HttpError(415, 'Use application/json'));
  }
  next();
});

// Fingerprint unlock must work while the app PIN is still needed: mounted before the auth router's gate.
app.use('/api/auth/passkey', passkeyRouter);
app.use('/api/auth', authRouter);
app.use('/api', requireAuth);
app.use('/api/assets', assetsRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/security', detectionRouter);
app.use('/api', aiRouter);
app.use('/api/incidents', incidentsRouter);
app.use('/api/notifications', notifyRouter);
app.use('/api/reports', reportsRouter);
app.use('/api/backups', backupRouter);
app.use('/api/device-health/scan', scanRouter);
app.use('/api/device-health', deviceRouter);
app.use('/api/power', powerRouter);
app.use('/api/processes', processesRouter);
app.use('/api/launcher', launcherRouter);
app.use('/api', systemRouter);
app.use('/api', (_req, _res, next) => next(new HttpError(404, 'Not found')));
app.use(errorHandler);

const dist = resolve('web/dist');
if (existsSync(dist)) {
  app.use(express.static(dist, { index: false }));
  app.use((req, res, next) => (req.method === 'GET' ? res.sendFile(resolve(dist, 'index.html')) : next()));
} else {
  app.get('/', (_req, res) => {
    res.type('text').send('Frontend not built yet. Run `npm run build` (or use `npm run dev`).');
  });
}

function startJobs() {
  every(5_000, 'http', httpTick);
  every(60_000, 'host', async () => {
    await collectHost();
    refreshIfBusy();
  });
  every(30_000, 'eventlog', async () => {
    const n = await collectEventLog();
    if (n) await runDetection();
  });
  every(60_000, 'detection', runDetection, false);
  every(30_000, 'alerts', () => {
    markStaleHosts();
    evaluateAlerts();
  });
  every(5_000, 'dispatch', dispatch);
  every(60_000, 'correlation', () => {
    correlate();
    autoResolveRecovered();
  });
  every(HOUR, 'rollups', runRollups);
  every(HOUR, 'retention', () => {
    runRetention();
    purgeSessions();
  });
  every(5 * MIN, 'digest', () => maybeSendDigest(() => withWeekly(buildDigest())));
  every(5 * MIN, 'auto_scan', maybeAutoScan, false);
  every(10 * MIN, 'backup', maybeScheduledBackup);
  every(HOUR, 'restore_drill', maybeRestoreDrill); // monthly; the first one runs at start-up
  if (heartbeatConfigured()) every(HEARTBEAT_EVERY_MS, 'heartbeat', sendHeartbeat);
  every(DEVICE_HEALTH_EVERY_MS, 'device_health', runDeviceHealth);
}

app.listen(PORT, HOST, () => {
  console.log(`SENTINEL running on http://${HOST}:${PORT}`);
  if (!adminExists()) console.log('First run: open the URL above in a browser on this PC to create the admin password.');
  startJobs();
  seedKnownLogins();
  regradeServiceFindings()
    .then((n) => n && console.log(`Re-graded ${n} new-service finding(s) by signature`))
    .catch((e) => console.error('Re-grading service findings failed:', e));
});
