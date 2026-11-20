# Architecture Decision Records

รูปแบบ: บริบท → การตัดสินใจ → Trade-off · **Revision B (2026-11-12):** เจ้าของโปรเจกต์เลือกทาง B = ฟีเจอร์ครบตาม Blueprint แต่ใช้ชิ้นส่วนน้อย สำหรับแอดมินคนเดียว ADR ที่เกี่ยวกับ NestJS/Postgres/Redis/Prometheus/Loki/Docker ของ v1.0 ถูกแทนที่ด้วยฉบับนี้

## ADR-001 Single-process modular monolith
- **ตัดสินใจ:** Node.js + TypeScript (Express) โปรเซสเดียว แบ่ง module: auth, assets, collectors, detection, alerts, notify, incidents, reports, audit, backup
- **เหตุผล:** แอดมินคนเดียว + 1 PC + เว็บไม่กี่ตัว ไม่ต้องการ microservices หรือ worker แยก
- **Trade-off:** ถ้าขยายหลายสิบเครื่อง ต้องแยก ingestion ออก (ดู ADR-012)

## ADR-002 SQLite เป็นที่เก็บเดียว
- **ตัดสินใจ:** `node:sqlite` (WAL) เก็บทั้งข้อมูลธุรกิจ, host metrics, security logs, check results; มี daily rollup สำหรับรายงานระยะยาว
- **แทน:** PostgreSQL + Prometheus + Loki ใน Blueprint
- **เหตุผล:** ปริมาณข้อมูลจริง ~1,500 metrics + หลักพัน events ต่อวัน; SQLite รองรับสบาย, ไม่ต้องติดตั้งอะไรเพิ่ม, backup เป็นไฟล์เดียว
- **Trade-off:** ไม่มี PromQL/LogQL; query ทำใน SQL ที่ออกแบบไว้แล้ว

## ADR-003 Single-admin authentication
- **ตัดสินใจ:** `admin_account` (แถวเดียว) + `sessions`; Argon2id, TOTP MFA (RFC 6238), session token เก็บเป็น hash, rotation หลังล็อกอิน/MFA, logout all, lockout 5 ครั้ง/15 นาที เก็บใน DB
- **First-run setup:** ตั้งรหัสผ่านผ่านหน้าเว็บได้เฉพาะคำขอจาก localhost และเฉพาะตอนยังไม่มีแอดมิน
- **ตัดออก:** users, memberships, workspaces, roles

## ADR-004 Scheduler ภายในโปรเซส
- **ตัดสินใจ:** timer ภายในแอปแทน Redis/BullMQ; คิว notification เก็บใน `notification_deliveries` (ทนต่อ restart, retry + backoff)
- **Trade-off:** สถานะ "เงื่อนไขค้างอยู่กี่นาที" ของ alert rule อยู่ในหน่วยความจำ — หลัง restart นับใหม่ (ยอมรับได้)

## ADR-005 การเก็บข้อมูลจาก PC Windows
- **ตัดสินใจ:** local collector ในแอป
  - Host metrics: `os` (CPU/RAM), `fs.statfs` (disk ทุกไดรฟ์), `netstat -e` (network) ทุก 60 วินาที
  - Event Log: `wevtutil` + XPath กรองเฉพาะ Event ID ที่ใช้ตรวจจับ, cursor ด้วย EventRecordID (ไม่อ่านซ้ำ ไม่พลาด)
- **Channels/Event IDs:** Security 4624 (เฉพาะ logon type 2/7/10/11), 4625, 4648, 4720, 4722, 4724, 4728/4732/4756, 4740, 1102 · System 104, 6005, 6006, 6008, 7045 · Defender 1116, 1117, 5001
- **สิทธิ์:** อ่าน Security log ต้องเป็น Administrators หรือสมาชิก **Event Log Readers** (แนะนำอย่างหลัง = least privilege); ถ้าอ่านไม่ได้ collector รายงานสถานะ error + วิธีแก้ (ไม่เงียบ)
- **ขยายในอนาคต:** รูปแบบข้อมูลเดียวกับ ingest API → เพิ่ม agent ระยะไกลพร้อม token ได้

## ADR-006 HTTP/TLS checks ในแอป
- โค้ดจาก prototype ที่ผ่านการทดสอบ: SSRF guard ตอน connect, ตรวจทุก redirect hop, keyword check, TLS expiry, ตรวจ security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)

## ADR-007 Detection เป็น rule-based ที่ตรวจสอบได้
- Built-in rules ในโค้ด + พารามิเตอร์ (threshold/window/เปิด-ปิด) ปรับได้จาก UI
- ผลลัพธ์ = `security_findings` พร้อม evidence (รายการ log event id จริง + ช่วงเวลา + เงื่อนไขที่ตรง) และ dedup ด้วย fingerprint
- **ห้าม:** block/ปิดระบบอัตโนมัติ, สรุปโดยไม่มีหลักฐาน

## ADR-008 Frontend & realtime
- React + TypeScript + Tailwind + ECharts; อัปเดตสดด้วย SSE; ธีม Dark Enterprise

## ADR-009 Self-monitoring (ห้ามล้มแบบเงียบ)
- ทุก collector/dispatcher รายงาน health; alert rule `pipeline` ยิงเมื่อ collector error/หยุดเกิน 5 นาที หรือส่ง Telegram ล้มเหลวต่อเนื่อง
- Daily digest ทาง Telegram = dead-man's switch (ถ้าไม่ได้รับ แปลว่า SENTINEL ไม่ทำงาน)

## ADR-010 Audit integrity
- `audit_logs` append-only: SQLite trigger ปฏิเสธ UPDATE/DELETE + hash chain; มีปุ่ม/endpoint ตรวจ chain

## ADR-011 Deployment
- `npm start` บน PC; ผูก 127.0.0.1 เป็นค่าเริ่มต้น; backup อัตโนมัติรายวันเก็บ 7 ชุด + restore CLI
- Secrets (Telegram token) เข้ารหัส AES-256-GCM ด้วย `data/master.key` (แยกจาก DB, รวมอยู่ใน backup)

## ADR-012 เส้นทางขยาย (เมื่อมีหลายผู้ใช้/หลายเครื่อง)
- หลายเครื่อง: เพิ่ม agent + ingest API; ถ้าเกิน ~20 hosts พิจารณา Prometheus/Loki ตาม Blueprint เดิม
- หลายผู้ใช้: เพิ่ม users/roles และ migrate `admin_account`
