# SENTINEL — System Requirements Specification (v1.1, single-admin, Revision B)

อ้างอิง: SENTINEL_Project_Blueprint.md v1.0 · **ส่วนที่ต่างจาก Blueprint:** ตัดการใช้งานหลายคนออก (users, memberships, workspaces, RBAC 3 บทบาท) เหลือ **แอดมินคนเดียว**

## 1. ผู้ใช้และ Lab

| รายการ | ค่า |
|---|---|
| ผู้ใช้ | แอดมินคนเดียว (เจ้าของระบบ) |
| Lab asset 1 | **PC Windows เครื่องนี้**: host metrics (windows_exporter) + Windows Event Log (Security/System) |
| Lab asset 2 | **เว็บของคุณบน Vercel**: HTTP, TLS, latency, headers (ติดตั้ง exporter ไม่ได้) |
| การจำลองเหตุ | สคริปต์ทดสอบที่สร้างเหตุจริงแบบควบคุมได้ (CPU สูง, login ผิดหลายครั้ง, เว็บทดสอบล่ม) |
| เป้าหมายขนาด | 10–50 assets (เป็นเป้าหมาย ไม่ใช่ผลทดสอบ) |

## 2. Functional Requirements

ระยะ = Phase ใน Blueprint (P1 MVP, P2 Security, P3 Incident, P4 Advanced)

| ID | ความต้องการ | ระยะ |
|---|---|---|
| FR-01 | แอดมินล็อกอินด้วยรหัสผ่าน (Argon2id) และ MFA แบบ TOTP; session หมุนเวียนได้, logout ทุก session ได้ | P1 |
| FR-02 | จัดการ Asset (server/website/api): เพิ่ม แก้ พัก ลบ, tag, environment | P1 |
| FR-03 | HTTP check: status, latency, TLS expiry, ตรวจข้อความในหน้า; จำกัดปลายทางกัน SSRF | P1 |
| FR-04 | Host metrics CPU/RAM/Disk/Network และสถานะ online จาก Prometheus | P1 |
| FR-05 | Dashboard: health, active alerts, online/offline, latency, timeline | P1 |
| FR-06 | Alert rule: threshold (CPU, RAM, Disk, down, latency, TLS) + severity | P1 |
| FR-07 | Alert event: dedup, cooldown, acknowledge, auto-resolve | P1 |
| FR-08 | Telegram notification + retry + delivery status | P1 |
| FR-09 | Audit log ของทุกการเปลี่ยนแปลงโดยแอดมิน | P1 |
| FR-10 | Log ingestion จาก Windows Event Log → ฐานข้อมูล, Log Explorer พร้อม query limit | P2 |
| FR-11 | Detection rules: failed login burst, login นอกเวลา, service ถูกหยุด, error 5xx พุ่ง | P2 |
| FR-12 | Security Finding พร้อม evidence reference (query + ช่วงเวลา) | P2 |
| FR-13 | Incident: Open → Acknowledged → Investigating → Resolved → Closed, Reopen, เหตุผลการเปลี่ยนสถานะ | P3 |
| FR-14 | Correlation: จัดกลุ่ม alert/finding ด้วย asset เดียวกัน + ช่วงเวลาใกล้กัน + dependency; ไม่สรุปเหตุ-ผลจากความสัมพันธ์อย่างเดียว | P3 |
| FR-15 | Incident timeline + evidence + ผู้รับผิดชอบ/บันทึกการแก้ไข | P3 |
| FR-16 | Reports: availability, SLO, MTTR, performance, security trends | P4 |
| FR-17 | Tracing (OpenTelemetry + Tempo) และ AI-assisted investigation (ต้องอ้างหลักฐาน) | P4 |

**นอกขอบเขต:** หลายผู้ใช้/RBAC, EDR/Antivirus, Firewall, vulnerability scan เชิงรุก, auto-block IP, multi-tenant, AI ตัดสินโดยไม่มีหลักฐาน

## 3. Non-functional Requirements

| ID | ด้าน | ข้อกำหนด |
|---|---|---|
| NFR-01 | ความถูกต้อง | Collector/การส่งแจ้งเตือนล้มเหลว ต้องไม่เงียบ — มี self-monitoring, pipeline alert และ daily digest |
| NFR-02 | ความปลอดภัย | ไม่มี credential/token/cookie ใน logs; secrets เข้ารหัส; SSRF guard; rate limit ล็อกอิน |
| NFR-03 | ความทนทาน | Restart แล้วข้อมูลธุรกิจและประวัติไม่หาย; Backup/Restore ทดสอบได้จริง |
| NFR-04 | ประสิทธิภาพ | Dashboard โหลด < 2 วินาทีที่ 50 assets (ต้องวัดจริงใน P4) |
| NFR-05 | Retention | Metrics 15 วัน, Logs 7–14 วัน, Findings/Alerts 90 วัน, Incidents/Audit 1 ปี |
| NFR-06 | ทรัพยากร | รันเป็นโปรเซสเดียว ไม่ต้องใช้ Docker; RAM เป้าหมาย < 300 MB |
| NFR-07 | การตรวจสอบย้อนหลัง | Audit log ป้องกันการแก้ไข (hash chain) |

## 4. User stories (แอดมิน)

- ในฐานะแอดมิน ฉันอยากเห็นสถานะรวมของทุก asset ในหน้าเดียว เพื่อรู้ว่ามีอะไรผิดปกติ
- ฉันอยากได้แจ้งเตือนทาง Telegram เมื่อ CPU สูง/เว็บล่ม/TLS ใกล้หมด โดยไม่โดนแจ้งซ้ำรัว ๆ
- ฉันอยากรู้ว่ามีคนพยายามเดารหัส Windows ของฉันหรือไม่ พร้อมหลักฐาน (log) ที่ตรวจสอบได้
- เมื่อเกิดเหตุ ฉันอยากเปิด Incident รวม alert/finding ที่เกี่ยวข้อง เห็น timeline และบันทึกการแก้ไข
- ฉันอยากได้รายงาน availability/MTTR รายเดือน
- ฉันอยากมั่นใจว่าข้อมูลกู้คืนได้ถ้าเครื่องมีปัญหา
