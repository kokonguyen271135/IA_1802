# 3 Kịch bản Demo — Từ Basic tới Nâng cao trong Doanh nghiệp

> Slide này trả lời feedback của thầy: **"Demo thì chia theo ngữ cảnh tình huống: từ basic tới nâng cao trong doanh nghiệp"**.
>
> Mỗi kịch bản có: tình huống thực tế → input → output → kết luận.

---

## KỊCH BẢN 1 — BASIC: Lập trình viên cá nhân

### Tình huống
> Sinh viên A vừa viết một module Python xử lý đăng nhập. Em muốn check xem có lỗ hổng bảo mật không trước khi push lên GitHub.

### Input
- 1 file Python ngắn (~30 dòng)
- File mẫu: `tests/demo_basic_login.py`

```python
# Vulnerable login example
import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE name='{username}' AND pass='{password}'"
    cursor.execute(query)
    return cursor.fetchone() is not None

def render_profile(user_input):
    # XSS vulnerability
    return f"<h1>Welcome {user_input}</h1>"
```

### Demo flow
1. Mở web UI, upload file
2. Click "Scan"
3. Đợi 2–3 giây
4. Xem kết quả

### Output mong đợi
```
═══════════════════════════════════════════════════════
  SCAN RESULT — demo_basic_login.py
═══════════════════════════════════════════════════════

  Found 2 vulnerabilities:

  [HIGH]    CWE-89  SQL Injection
            Line 7:  query = f"SELECT * FROM users WHERE..."
            Confidence: 94.2%
            Fix: Use parameterized queries (cursor.execute(sql, params))

  [MEDIUM]  CWE-79  Cross-Site Scripting (XSS)
            Line 11: return f"<h1>Welcome {user_input}</h1>"
            Confidence: 87.5%
            Fix: Escape HTML using html.escape() or template engine

  Total scan time: 2.34s
═══════════════════════════════════════════════════════
```

### Điểm nhấn khi trình bày
- Đơn giản, ai cũng dùng được
- Static analyzer phát hiện theo pattern (regex + AST)
- Không cần AI cho ca dễ → tiết kiệm tài nguyên

---

## KỊCH BẢN 2 — TRUNG CẤP: Đội ngũ DevOps SME

### Tình huống
> Công ty SME (50 nhân viên) đang chạy 1 web app Django bằng container Docker. Đội DevOps muốn audit các thư viện đang dùng có CVE chưa được patch không.

### Input
- File `requirements.txt` của project
- File mẫu: `tests/demo_intermediate_requirements.txt`

```
# requirements.txt — vulnerable versions on purpose
Django==2.0.1
requests==2.18.0
PyYAML==3.13
Pillow==5.0.0
urllib3==1.22
flask==0.12.2
```

### Demo flow
1. Upload `requirements.txt`
2. Click "Scan dependencies"
3. Chờ NVD API + cache (~5–10s lần đầu)
4. Xem báo cáo CVE list

### Output mong đợi

| Package | Version | CVEs | Highest Severity | Patch Version |
|---------|---------|------|------------------|---------------|
| Django | 2.0.1 | **CVE-2019-19844** (Account Takeover), CVE-2019-12781, CVE-2018-7536 | **CRITICAL** (9.8) | 2.2.28+ |
| PyYAML | 3.13 | **CVE-2020-14343** (Arbitrary Code Exec), CVE-2017-18342 | **CRITICAL** (9.8) | 5.4+ |
| Pillow | 5.0.0 | CVE-2020-5310, CVE-2019-16865 (DoS), CVE-2019-19911 | HIGH (8.8) | 8.1.1+ |
| requests | 2.18.0 | CVE-2018-18074 (auth header leak) | HIGH (8.1) | 2.20+ |
| urllib3 | 1.22 | CVE-2019-11324, CVE-2020-26137 | HIGH (7.5) | 1.25.10+ |
| flask | 0.12.2 | CVE-2018-1000656 (DoS) | MEDIUM (5.3) | 0.12.3+ |

```
═══════════════════════════════════════════════════════
  SUMMARY
  Total CVEs found: 13
  CRITICAL: 2 │ HIGH: 6 │ MEDIUM: 5 │ LOW: 0
  Recommended action: PATCH IMMEDIATELY (2 critical)

  Estimated patching effort: ~3 hours (auto-fix available)
═══════════════════════════════════════════════════════
```

### Điểm nhấn khi trình bày
- **CPE matcher** ánh xạ `Django==2.0.1` → `cpe:2.3:a:djangoproject:django:2.0.1:*:*:*:*:*:*:*`
- **NVD API v2** trả về toàn bộ CVE liên quan
- **AI Severity** kiểm chứng lại CVSS từ NVD (đôi khi NVD chậm cập nhật, BERT bù đắp)
- **Cache layer** giảm round-trip API → demo lần 2 nhanh hơn 10x

---

## KỊCH BẢN 3 — NÂNG CAO: Doanh nghiệp lớn (Enterprise)

### Tình huống
> Công ty lớn (1,000+ nhân viên, 100+ servers) muốn quét toàn bộ hệ thống Windows server: 50 file PE binaries, 20 web app dependencies, kèm context "asset criticality" để biết patch cái nào trước.

### Input
- 1 thư mục chứa nhiều artifact:
  - 5 file `.exe` (PE binaries) — gồm 2 mẫu malware từ MalwareBazaar
  - 3 file `requirements.txt` (Python services)
  - 2 file `package.json` (Node.js services)
  - 1 file `pom.xml` (Java service)
- 1 file metadata: `assets.yaml`

```yaml
# assets.yaml — asset criticality config
services:
  - name: payment-api
    requirements: payment/requirements.txt
    criticality: CRITICAL  # Xử lý thanh toán
    public_facing: true
  - name: internal-dashboard
    package_json: dashboard/package.json
    criticality: MEDIUM
    public_facing: false
  - name: legacy-erp
    pom_xml: erp/pom.xml
    criticality: HIGH
    public_facing: false
binaries:
  - path: scanner.exe
    criticality: HIGH  # Chạy trên endpoint
  - path: updater.exe
    criticality: CRITICAL  # Có quyền admin
```

### Demo flow
1. Upload toàn bộ thư mục (zip)
2. Click "Enterprise scan"
3. Chờ ~30–60s (parallel scanning)
4. Xem dashboard tổng hợp
5. Click vào CVE để xem chi tiết + suggested patch

### Output mong đợi

#### Dashboard tổng quan
```
╔══════════════════════════════════════════════════════════╗
║  ENTERPRISE SECURITY DASHBOARD                            ║
║  Scan: 2026-05-05 10:15 │ Duration: 47s                  ║
╠══════════════════════════════════════════════════════════╣
║                                                            ║
║  [PE Binaries]  5 files scanned                            ║
║   ▸ 2 MALWARE detected (XGBoost confidence > 99%)          ║
║   ▸ 3 benign                                               ║
║                                                            ║
║  [Dependencies] 47 packages scanned                        ║
║   ▸ 23 CVEs found                                          ║
║   ▸ CRITICAL: 4 │ HIGH: 11 │ MEDIUM: 8 │ LOW: 0           ║
║                                                            ║
║  [Risk-Adjusted Priority]                                  ║
║   ▸ CRITICAL (patch trong 24h):  6 issues                  ║
║   ▸ HIGH     (patch trong 7d):  12 issues                  ║
║   ▸ MEDIUM   (patch trong 30d):  7 issues                  ║
║                                                            ║
╚══════════════════════════════════════════════════════════╝
```

#### Top 5 priority (sau khi nhân với asset criticality)

| # | CVE | Asset | CVSS | AI Score | Asset Crit | **Final Score** |
|---|-----|-------|------|----------|------------|------------------|
| 1 | Malware (updater.exe) | Endpoint binary | — | 99.8% | CRITICAL | **10.0** |
| 2 | CVE-2019-19844 (Django account takeover) | payment-api | 9.8 | 0.97 | CRITICAL | **9.94** |
| 3 | CVE-2020-14343 (PyYAML RCE) | payment-api | 9.8 | 0.96 | CRITICAL | **9.91** |
| 4 | Malware (scanner.exe) | Endpoint binary | — | 98.5% | HIGH | **9.34** |
| 5 | CVE-2021-44228 (Log4Shell) | legacy-erp | 10.0 | 0.99 | HIGH | **9.30** |

#### Báo cáo có thể export
- PDF executive summary (1 trang)
- CSV cho ticketing (Jira import)
- JSON cho SIEM ingestion (Splunk, ELK)

### Điểm nhấn khi trình bày
- **Toàn bộ pipeline** chạy: Static + AI Severity + AI CWE + Malware Detection + CPE matching + Contextual scoring
- **Contextual scorer** quan trọng: 1 CVE 9.8 trên server không public ≠ CVE 9.8 trên payment API
- **Parallel scanning**: dùng multiprocessing chạy song song các file
- **Cache + incremental scan**: lần sau chỉ scan file thay đổi
- **Output có thể tích hợp** vào Jira/Slack/SIEM → đúng chuẩn doanh nghiệp

---

## Bảng so sánh 3 kịch bản

| Tiêu chí | Basic | Trung cấp (SME) | Nâng cao (Enterprise) |
|----------|-------|------------------|------------------------|
| Số file input | 1 | 1–5 | 50+ |
| Loại artifact | Source code | Dependency manifest | Mixed (code + binary + dep) |
| Module sử dụng | Static analyzer | Static + NVD + AI | Toàn bộ pipeline |
| Thời gian scan | 2–3s | 5–10s | 30–60s |
| Output | Inline annotations | CVE list | Risk dashboard + export |
| User persona | Sinh viên / Dev | DevOps engineer | Security team / CISO |
| Tích hợp | Local IDE | CI/CD | SIEM + Ticketing |

## Checklist chuẩn bị demo

- [ ] Tạo file mẫu cho cả 3 kịch bản trong `tests/demo_*`
- [ ] Pre-warm NVD API cache (chạy 1 lần trước demo)
- [ ] Backup plan: video screen-record nếu mạng chậm
- [ ] Chuẩn bị 2 mẫu malware test (vô hại, từ EICAR test file hoặc MalwareBazaar test family)
- [ ] Tạo `assets.yaml` mẫu cho kịch bản 3
- [ ] Test trên máy demo trước hôm bảo vệ ít nhất 2 lần
- [ ] In sẵn báo cáo PDF mẫu để phát cho hội đồng

## Mỗi kịch bản nói gì (script ngắn)

> **Basic (1 phút)**: "Đây là user case đơn giản nhất — 1 dev cá nhân scan file của mình. Hệ thống phát hiện 2 lỗ hổng kinh điển bằng static analyzer, không cần AI cho ca này."
>
> **Trung cấp (2 phút)**: "Khi lên team DevOps SME, ta cần scan dependencies. Hệ thống dùng CPE matcher map package → CVE qua NVD, kèm AI Severity kiểm chứng. Đây là use case phổ biến nhất."
>
> **Nâng cao (3 phút)**: "Doanh nghiệp lớn cần dashboard risk-adjusted. Hệ thống chạy toàn pipeline: malware detection cho binary, CVE scan cho dependency, AI cho severity, contextual scorer nhân với asset criticality để ra priority list đúng nghĩa enterprise."
