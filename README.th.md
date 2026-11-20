# SENTINEL

[English](README.md) · **ภาษาไทย**

แพลตฟอร์ม **Security Monitoring + Observability** สำหรับแอดมินคนเดียว ตาม SENTINEL Blueprint v1.0 (ทาง B: ฟีเจอร์ครบ ใช้ชิ้นส่วนน้อย) — ดูเอกสารใน [`docs/`](docs)

เฝ้าดู **PC Windows เครื่องนี้** และ **เว็บไซต์/API ของคุณ** ตรวจจับเหตุผิดปกติด้วยกฎที่ตรวจสอบได้ แจ้งเตือนทาง Telegram และบันทึก Incident พร้อมหลักฐาน

## ทำอะไรได้

| ด้าน | รายละเอียด |
|---|---|
| Infrastructure | CPU, RAM, ดิสก์ทุกไดรฟ์, network, แบตเตอรี่ (โน๊ตบุ๊ค) ของ PC ทุก 1 นาที |
| Applications | HTTP status, latency, keyword, TLS หมดอายุ, security headers (SSRF-guarded) |
| Security | อ่าน Windows Event Log: login สำเร็จ/ล้มเหลว, สร้างบัญชี, เพิ่มเข้า Administrators, ล้าง log, ติดตั้ง service, Defender เจอมัลแวร์/ถูกปิด, RDP |
| Device health | ทุก 30 นาที: Defender เปิด/อัปเดต/**ข้อยกเว้นอันตราย**, ไฟร์วอลล์, Windows Update, BitLocker, สุขภาพ SSD, แบตเสื่อม, **โปรแกรมเริ่มอัตโนมัติ + Scheduled Task ใหม่** (ตรวจลายเซ็น, จับชื่อปลอมเช่น svchost.exe นอก Windows) และอุปกรณ์ใน Tailscale — อ่านอย่างเดียว |
| Detection | 19 กฎ (เช่น เดารหัสผ่านทั้งแบบเร็วและแบบช้า 24 ชม., มีคนเดารหัสเข้า SENTINEL เอง/รหัสผ่านถูกแต่รหัส 6 หลักผิด/เข้าจากอุปกรณ์ใหม่, login สำเร็จหลังล้มเหลวหลายครั้ง, service ใหม่ตรวจลายเซ็นดิจิทัล) ปรับ threshold ได้ ทุก finding มีหลักฐาน log จริง ปิดหลายรายการพร้อมกันได้ |
| Alerting | กฎ threshold 9 แบบ (รวมแบตใกล้หมด), dedup, เตือนซ้ำตามรอบ, acknowledge, auto-resolve, Telegram + retry + ประวัติการส่ง |
| Incidents | Open → Acknowledged → Investigating → Resolved → Closed, Reopen, timeline, note, ผูกหลักฐาน, correlation อัตโนมัติ |
| Reports | Availability, SLO/error budget, MTTA/MTTR, แนวโน้มความปลอดภัย (7/30/90 วัน) |
| Admin | รหัสผ่าน Argon2id + MFA (TOTP), จัดการ session, audit log แบบ hash chain, backup อัตโนมัติ + restore |

## เริ่มใช้งาน

ต้องมี Node.js 22.13+ บน Windows

```bash
npm install
npm run build
npm start
```

เปิด http://127.0.0.1:3001 บนเครื่องนี้ ครั้งแรกจะให้ตั้งรหัสผ่านแอดมิน (อย่างน้อย 12 ตัว) แล้วแนะนำให้เปิด MFA ที่ **Settings → Account & MFA**

> **อ่าน Security log ได้ต้องมีสิทธิ์:** รัน SENTINEL ใน terminal แบบ Administrator หรือเพิ่มบัญชีของคุณเข้ากลุ่ม *Event Log Readers* ครั้งเดียว (แนะนำ) แล้ว sign out/in:
> `net localgroup "Event Log Readers" "%USERNAME%" /add` (รันใน terminal แบบ Administrator)
> ถ้าไม่มีสิทธิ์ ระบบจะขึ้นแถบเตือนบนหน้าเว็บ ไม่เงียบ

### รันเบื้องหลังอัตโนมัติ (ไม่ต้อง `npm start` เอง)

รันครั้งเดียวใน terminal แบบ **Run as administrator**:

```bash
npm run service:install
```

SENTINEL จะเริ่มเองแบบไม่มีหน้าต่างทุกครั้งที่ sign in เข้า Windows ถ้าโปรแกรมหยุด ตัวรันจะเริ่มใหม่ให้เอง (รอ 20 วินาที–5 นาที) และอ่าน Security log ได้เพราะ task รันด้วยสิทธิ์สูงสุด เปิดหน้าเว็บได้จาก shortcut **SENTINEL** บน Desktop

| คำสั่ง | ทำอะไร |
|---|---|
| `npm run service:status` | ดูว่ารันอยู่ไหม และ log ล่าสุด |
| `npm run service:stop` / `service:start` | หยุด / เริ่มตอนนี้ |
| `npm run service:uninstall` | เอาการเริ่มอัตโนมัติออก |

Log อยู่ที่ `data/logs/sentinel.log` (หมุนไฟล์ที่ 10 MB) หลังแก้โค้ดให้รัน `npm run build` แล้ว `npm run service:stop` และ `npm run service:start`

### เปิดจากมือถือ / นอกบ้าน
ผ่าน Tailscale (เครือข่ายส่วนตัว ไม่เปิด port ออกอินเทอร์เน็ต): `tailscale serve --bg --https=8443 http://127.0.0.1:3001`

### แจ้งเตือนเมื่อ SENTINEL เองหยุดทำงาน (dead man's switch)
SENTINEL บอกไม่ได้ว่าตัวเองตาย (ปิดเครื่อง/แบตหมด/ค้าง) จึงส่งสัญญาณไปบริการภายนอกทุก 5 นาที ถ้าสัญญาณหายไป บริการนั้นจะแจ้งเตือนคุณ
1. สมัคร https://healthchecks.io (ฟรี) → **Add Check** → Period **5 นาที**, Grace **15 นาที** (หรือ 30 ถ้าไม่อยากโดนเตือนตอนรีสตาร์ท)
2. **Integrations** → เพิ่ม **Telegram** (กดตามขั้นตอนของเขา) เพื่อให้แจ้งเข้ามือถือ
3. คัดลอก Ping URL (`https://hc-ping.com/...`) ใส่ใน `.env` เป็น `HEARTBEAT_URL=...` แล้ว `npm run service:stop` / `service:start`

ถ้าส่วนใดของ SENTINEL ผิดปกติ จะส่งไปที่ `<url>/fail` พร้อมชื่อส่วนที่เสีย ให้ healthchecks แจ้งเตือนด้วย URL นี้เป็นความลับ ไม่ถูกเขียนลง log หรือแสดงบนหน้าเว็บ
> ข้อควรรู้: ปิดโน๊ตบุ๊คเองก็จะถูกแจ้งเตือนเหมือนกัน (เพราะแยกไม่ได้ว่าตั้งใจปิดหรือไม่) — กด **Pause** ใน healthchecks ก่อนปิดเครื่องนานๆ ได้

### สำเนา backup นอกดิสก์
ตั้ง `BACKUP_COPY_DIR` ใน `.env` เป็นโฟลเดอร์ที่ sync ขึ้น cloud (เช่น `C:\Users\<you>\OneDrive\SENTINEL-backups`) — ทุก backup ถูกคัดลอกไปที่นั่นด้วย (เก็บ 7 ชุดเหมือนกัน) ถ้าคัดลอกไม่ได้ ระบบลองใหม่ทุก 10 นาทีและขึ้นเตือนในหน้าสุขภาพระบบ backup มี `master.key` อยู่ด้วย จึงควรเปิด MFA ของบัญชี cloud นั้น

### AI สรุปเหตุการณ์ (ไม่บังคับ)
ใส่ `ANTHROPIC_API_KEY=...` ใน `.env` แล้วรีสตาร์ท จะมีปุ่ม **ให้ AI สรุป** ในหน้าเหตุการณ์ Claude อ่านเฉพาะหลักฐานของเหตุการณ์นั้น ตอบเป็นภาษาไทยพร้อมอ้างอิงหลักฐานทุกข้อ (การอ้างอิงที่ไม่มีอยู่จริงจะถูกตัดออก) ผลถูกเก็บในไทม์ไลน์ ไม่มีการเปลี่ยนแปลงอะไรอัตโนมัติ — มีค่าใช้จ่ายต่อครั้งตามการใช้ Claude API และข้อความหลักฐานถูกส่งไปที่ Anthropic

### Telegram
**Alert Manager → Notifications → Connect Telegram** แล้วทำตามขั้นตอนบนหน้าจอ (token ถูกเข้ารหัสด้วย `data/master.key`) แล้วกด **Send test**

## การตั้งค่า (`.env`, ไม่บังคับ)

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `PORT` / `HOST` | 3001 / 127.0.0.1 | เข้าได้เฉพาะเครื่องนี้ |
| `DATA_DIR` | `data` | ที่เก็บฐานข้อมูล, key, backups |
| `ALLOW_PRIVATE_TARGETS` | false | `true` เพื่อเช็ก localhost/LAN (ปกติบล็อกกัน SSRF) |
| `COOKIE_SECURE` | false | `true` เมื่อเปิดผ่าน HTTPS |

## ข้อมูล, backup, restore

- ทุกอย่างอยู่ใน `data/` — `sentinel.db` (SQLite) และ `master.key`
- Backup อัตโนมัติวันละครั้ง (ตั้งเวลาได้) เก็บ 7 ชุดใน `data/backups/` หรือกด **Settings → Backups → Back up now** แล้ว **คัดลอกไปไว้ที่อื่น** (อีกดิสก์/คลาวด์)
- Restore: หยุด SENTINEL แล้วรัน `npm run restore -- data/backups/<ชื่อ backup>` (ข้อมูลเดิมถูกย้ายไป `data/pre-restore-*` ไม่ถูกลบ)
- Retention: metrics/check 15 วัน, security log 14 วัน, alert/finding 90 วัน, incident/audit 1 ปี+

## ทดสอบ

```bash
npm test                 # unit (SSRF guard, health, signature, checker, heartbeat)
npm run test:acceptance  # acceptance + alerting บนเซิร์ฟเวอร์จริง (~3 นาที)
npm run test:eval        # ความแม่นยำ detection/correlation (21 สถานการณ์)
npm run typecheck
```


## ข้อจำกัดที่ควรรู้

- ตรวจจับจาก log/metrics ที่เก็บได้เท่านั้น ไม่ใช่แอนติไวรัส ไม่บล็อกอะไรอัตโนมัติ
- เว็บบน Vercel ตรวจได้จากภายนอก (HTTP/TLS/headers) เท่านั้น
- Correlation บอกว่า "เกิดใกล้กันบน asset เดียวกัน" ไม่ได้พิสูจน์สาเหตุ
- ความพร้อมใช้งานของ PC เครื่องนี้ในรายงานคือ "ช่วงเวลาที่ถูกมอนิเตอร์" (ปิดเครื่อง = ไม่มีข้อมูล ซึ่งเป็นเรื่องปกติ)
- ใช้คนเดียว — ถ้าต้องการหลายผู้ใช้ ดู ADR-012

## โครงสร้าง

```text
server/
  db.ts                 schema + migration
  lib/                  ssrf, checker, crypto, totp, audit, health, bus
  modules/              auth, assets, http-monitor, host-collector, eventlog,
                        detection, alerts, notify, incidents, reports, backup, system
web/src/                React + Tailwind + ECharts (10 หน้า)
scripts/restore.ts      กู้คืน backup
tests/                  acceptance tests
docs/                   SRS, ADR, Schema, Test Plan, ผลทดสอบ
```
