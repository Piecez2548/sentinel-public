# Database Schema Specification (SQLite, Revision B)

ปรับจาก Blueprint §5: ลบ `users`, `memberships`, `workspaces`, `workspace_id`; ใช้ SQLite (ADR-002) จึงเก็บ metrics/logs ไว้ในฐานเดียวกันพร้อม retention
ข้อกำหนด: PK เป็น INTEGER (SQLite rowid), เวลาเป็น epoch ms (UTC), FK เปิด, JSON เก็บเป็น TEXT, schema version ใน `PRAGMA user_version`

## ERD (ย่อ)

```text
admin_account 1 ── * sessions
assets 1 ── 0..1 http_checks 1 ── * check_results
assets 1 ── 0..1 host_info,  assets 1 ── * host_metrics
assets 1 ── * log_events
assets 1 ── * alert_events * ── 1 alert_rules
assets 1 ── * security_findings * ── 1 detection_rules
incidents 1 ── * incident_events,  incidents 1 ── * incident_links (alert | finding)
notification_channels 1 ── * notification_deliveries
assets 1 ── * daily_stats
audit_logs (append-only, hash chain)
```

## ตาราง

| Table | คอลัมน์สำคัญ | Constraint / Index |
|---|---|---|
| `admin_account` | password_hash (Argon2id), totp_secret_enc, totp_enabled, totp_last_step, failed_attempts, locked_until | CHECK(id = 1) |
| `sessions` | token_hash, mfa_pending, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent | unique(token_hash) |
| `assets` | name, type (host/website), environment, target, tags, enabled, status, status_since, slo_target | idx(type) |
| `http_checks` | asset_id, interval_sec, keyword, consecutive_failures, last_*, tls_expires_at, headers | PK(asset_id) |
| `check_results` | asset_id, ts, ok, status_code, latency_ms, error | idx(asset_id, ts) |
| `host_info` | asset_id, hostname, os, cpu_model, cores, collector, last_seen_at | PK(asset_id) |
| `host_metrics` | asset_id, ts, cpu_pct, mem_pct, mem_used, mem_total, disks (JSON), net_rx_bps, net_tx_bps | idx(asset_id, ts) |
| `log_events` | asset_id, channel, event_id, record_id, ts, level, category, summary, fields (JSON) | unique(asset_id, channel, record_id); idx(ts); idx(event_id, ts) |
| `detection_rules` | id (slug), name, description, severity, enabled, params (JSON) | PK(id) |
| `security_findings` | rule_id, asset_id, severity, title, summary, fingerprint, status, first_seen, last_seen, count, evidence (JSON) | idx(status, last_seen); idx(fingerprint) |
| `alert_rules` | name, type, asset_id?, params, severity, for_sec, cooldown_sec, enabled | |
| `alert_events` | rule_id, asset_id, fingerprint, status (firing/acknowledged/resolved), severity, title, detail, value, triggered_at, acknowledged_at, resolved_at, last_notified_at | **unique(fingerprint) WHERE status != 'resolved'** = dedup |
| `incidents` | title, severity, status, summary, assignee, source, opened_at, acknowledged_at, resolved_at, closed_at, resolution | idx(status) |
| `incident_events` | incident_id, type, from_status, to_status, message, ts | idx(incident_id, ts) |
| `incident_links` | incident_id, kind (alert/finding), ref_id, reason | PK(incident_id, kind, ref_id) |
| `notification_channels` | type (telegram), name, config_enc, enabled | |
| `notification_deliveries` | channel_id, kind, ref, message, status (pending/sent/failed), attempts, next_attempt_at, last_error, sent_at | idx(status, next_attempt_at) |
| `daily_stats` | asset_id, day, checks_total, checks_ok, latency_avg, latency_p95, host_samples, cpu_avg, cpu_max, mem_avg | PK(asset_id, day) |
| `audit_logs` | seq, ts, action, resource_type, resource_id, detail, ip, prev_hash, hash | trigger ห้าม UPDATE/DELETE |
| `settings` | key, value | PK(key) |

## Audit hash chain
`hash = sha256(prev_hash | seq | ts | action | resource_type | resource_id | detail | ip)` — ตรวจด้วย `GET /api/audit/verify`

## Retention (job รายชั่วโมง)

| ข้อมูล | อายุ |
|---|---|
| `host_metrics`, `check_results` | 15 วัน |
| `log_events` | 14 วัน (evidence ที่ผูกกับ finding ถูกเก็บสรุปไว้ใน finding) |
| `alert_events`, `security_findings`, `notification_deliveries` | 90 วัน |
| `incidents`, `daily_stats`, `audit_logs` | 1 ปี+ (audit ไม่ลบ) |

## Migration
Schema version 2. ถ้าพบตาราง `sites` ของ prototype (v1) จะย้ายเป็น `assets` + `http_checks` + `check_results` อัตโนมัติ แล้วลบตารางเก่า
