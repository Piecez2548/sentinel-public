# MVP Acceptance Test Plan (v0.1, single-admin)

ปรับจาก Blueprint §8/§10: เปลี่ยนเคส "Viewer แก้ Asset ได้ 403" เป็นเคสควบคุมการเข้าถึงของแอดมินคนเดียว ใช้ **Lab จริง** (PC นี้ + เว็บของคุณ + เว็บทดสอบในเครื่อง) ไม่ใช้ mock อย่างเดียว · Revision B: ไม่มี Docker/Prometheus/Loki/Redis

## Test cases

| ID | Scenario | ขั้นตอนโดยสรุป | ผลที่ต้องได้ | ชนิด |
|---|---|---|---|---|
| AT-01 | เพิ่ม server | เปิดแอปบน PC นี้ (local collector) | asset ขึ้น Online และเห็น CPU/RAM/Disk ภายใน 2 นาที | E2E |
| AT-02 | CPU สูง | ลด threshold ชั่วคราว หรือรันสคริปต์โหลด CPU ให้เกิน threshold ตาม `for_sec` | เกิด alert ตามเวลา และส่ง Telegram | E2E |
| AT-03 | API/เว็บล่ม | ชี้ check ไปปลายทางที่หยุดตอบ | สถานะ Down + แจ้งเตือน; เมื่อกลับมา auto-resolve + แจ้ง recovered | E2E |
| AT-04 | Alert ซ้ำ | คงเงื่อนไขผิดปกติไว้หลายรอบ | alert_event เดียว (dedup) ไม่แจ้งรัวภายใน cooldown | Integration |
| AT-05 | ไม่ล็อกอิน | เรียก API ทุก endpoint ที่ป้องกันโดยไม่มี session | 401 ทุกตัว | Security |
| AT-06 | ล็อกอินผิด | ผิดรหัส 5 ครั้งติด | rate limit/lockout; บันทึก audit; รหัสถูกก็ยังเข้าไม่ได้ช่วง lockout | Security |
| AT-07 | MFA | เปิด TOTP แล้วล็อกอิน | ต้องใส่รหัส TOTP; รหัสผิด/ซ้ำถูกปฏิเสธ | Security |
| AT-08 | SSRF | เพิ่ม check ไป 127.0.0.1, 169.254.169.254, redirect ไป internal, DNS rebinding | ถูกบล็อกทุกกรณี และบันทึก audit | Security |
| AT-09 | Restart | หยุดและเริ่มแอปใหม่ | assets, rules, alerts, ประวัติ ไม่หาย; checks ทำงานต่อเอง | Reliability |
| AT-10 | Telegram ล้มเหลว | ใส่ token ผิด/ตัดเน็ต | retry ตาม backoff, delivery status = failed พร้อมเหตุผล, ไม่หยุด alert อื่น | Integration |
| AT-11 | Collector ล่ม | ทำให้ Event Log collector อ่านไม่ได้ / เครือข่ายออก Telegram ไม่ได้ | เกิด pipeline alert และขึ้นสถานะบนหน้าเว็บ ไม่เงียบ | Reliability |
| AT-12 | Backup/Restore | `backup` แล้ว restore ลง environment ใหม่ | ข้อมูลทดสอบกู้คืนครบ ตรวจ hash chain ผ่าน | Recovery |
| AT-13 | ไม่มี credential ใน log | สร้างเหตุการณ์ล็อกอิน/ตั้ง token แล้ว grep logs ทุก service | ไม่พบ password/token/cookie | Security |
| AT-14 | Audit integrity | แก้/ลบแถว audit ตรง ๆ | DB ปฏิเสธ; ถ้า chain ถูกแก้ ตัวตรวจต้องรายงาน | Security |

### Phase 2 (Security) — เพิ่มเมื่อถึง Phase
| ID | Scenario | ผลที่ต้องได้ |
|---|---|---|
| AT-21 | Login ล้มเหลวบน Windows ≥ N ครั้ง/นาที (สร้างจริง) | เกิด Finding พร้อม evidence_ref ที่เปิดดู log จริงได้ |
| AT-22 | Query ใน Log Explorer เกิน limit | ถูกจำกัด/ปฏิเสธตาม query limit |
| AT-23 | Detection precision/recall | วัดบนชุดเหตุการณ์ที่รู้คำตอบ (ground truth) |

### Phase 3 (Incident)
| ID | Scenario | ผลที่ต้องได้ |
|---|---|---|
| AT-31 | CPU สูง + latency สูง + login fail พร้อมกันบน asset เดียว | Correlation เสนอ incident เดียวพร้อมหลักฐานแต่ละชิ้น |
| AT-32 | เปลี่ยนสถานะ incident | มี incident_event + เหตุผล + audit ทุกครั้ง; Reopen ได้ |
| AT-33 | Correlation accuracy | วัด Precision/Recall กับ ground truth (Quality Gate Phase 3) |

## Quality Gates (ต้องผ่านก่อนเริ่ม Phase ถัดไป)
1. ไม่มี Critical security finding ที่ยังไม่แก้
2. Core E2E (AT-01–AT-04, AT-09) ผ่านทั้งหมด
3. AT-13: ไม่มี credential รั่วใน logs
4. AT-05–AT-08: การควบคุมการเข้าถึงและ SSRF ผ่าน
5. AT-12: Backup/Restore ผ่านจริง
6. AT-11: collector/การแจ้งเตือนล่มแล้วไม่เงียบ
7. Phase 3: วัด Precision/Recall ของ Correlation ด้วย ground truth

## หลักการรายงานผล
บันทึกผลจริงของแต่ละเคส (ผ่าน/ไม่ผ่าน, วันที่, หลักฐาน) ใน `docs/test-results/` ห้ามบันทึกว่าผ่านถ้ายังไม่ได้รันจริง
