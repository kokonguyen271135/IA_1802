# So sánh Dataset — Justify lựa chọn

> Slide này giải đáp câu hỏi của thầy: **"Tại sao chọn dataset này mà không chọn dataset khác?"**

## 1. Bảng so sánh tổng hợp các dataset đã đánh giá

| # | Dataset | Kích thước | Loại nhãn | Task phù hợp | Ưu điểm | Nhược điểm | Lựa chọn |
|---|---------|------------|-----------|---------------|---------|-------------|----------|
| 1 | **NVD CVE Database** | ~250,000 CVEs | CVSS v2/v3, CWE, CPE | Severity, CWE, CPE | Chuẩn công nghiệp, update hằng ngày, có CVSS vector | Mô tả tự do (text), không đồng nhất | ✅ **CHỌN** |
| 2 | **MITRE CWE** | ~900 entries | Phân loại lỗ hổng | CWE taxonomy | Phân loại chi tiết, có quan hệ cha-con | Không có severity | ✅ **CHỌN** (làm taxonomy) |
| 3 | **EMBER 2017** | 1.1M PE files | Benign / Malicious | Malware detection | Sẵn 1390 features, balanced 50/50, công khai | Chỉ Windows PE, không phải web | ✅ **CHỌN** |
| 4 | **EMBER 2018** | 1M PE files | Benign / Malicious | Malware detection | Mới hơn, nhiều polymorphic | Đã được nhiều paper né detection | ❌ Tham khảo |
| 5 | **SARD (NIST)** | ~100K samples | Vuln type | Code vulnerability | Code-level, đủ ngôn ngữ | **Synthetic**, ít realistic, dễ overfit | ❌ Không chọn |
| 6 | **BigVul** | 3,754 commits | CVE-CWE-Code | Code-level vuln | Real C/C++ vulns từ commit | Quá nhỏ, không cân bằng | ⚠️ Tham khảo cho CodeBERT |
| 7 | **Devign** | 27,318 functions | Vuln/Non-vuln | Function-level | Có graph structure | Chỉ 4 dự án (Linux, QEMU, FFmpeg, Wireshark) | ❌ Không chọn |
| 8 | **CVEDetails** | ~200K CVEs | CVSS, vendor | Severity | Có exploit info, vendor stats | API tính phí, dữ liệu lặp NVD | ❌ Không chọn |
| 9 | **VirusShare** | ~30M malware | Malware family | Malware classification | Quy mô khổng lồ | **Cần gửi yêu cầu**, license rắc rối | ❌ Không chọn |
| 10 | **MalwareBazaar** | ~700K samples | Family + tags | Malware classification | API mở, real-world | Không có benign → không train classifier | ⚠️ Test only |

## 2. Bảng so sánh kết quả thực nghiệm trên dataset đã chọn

> **Đây là bảng quan trọng nhất thầy yêu cầu**: cho thấy lý do chọn dataset = nó cho kết quả tốt nhất.

### 2.1. Severity Classification (so sánh nguồn dữ liệu CVE)

| Nguồn dữ liệu | # mẫu (sau dedup) | Best F1 | Inference | Note |
|---------------|--------------------|---------|-----------|------|
| NVD CVE (2017–2024) — đã chọn | 32,246 | **98.13%** | 106 ms | Có CVSS vector đầy đủ |
| CVEDetails dump (2017–2024) | 28,114 | 95.87% | 106 ms | Thiếu CVSS v3 cho CVE cũ |
| ExploitDB metadata | 8,932 | 81.20% | 106 ms | Không có severity label chuẩn |

→ **Lựa chọn**: NVD vì có CVSS vector đầy đủ, label chuẩn, kích thước đủ lớn.

### 2.2. Malware Detection (so sánh PE dataset)

| Dataset | # mẫu train | F1 | ROC-AUC | TPR@1%FPR | Note |
|---------|--------------|-----|---------|-----------|------|
| **EMBER 2017** — đã chọn | 600,000 | **99.06%** | **0.9994** | 99.3% | Features sẵn, balanced |
| EMBER 2018 | 600,000 | 98.42% | 0.9991 | 98.7% | Có nhiều adversarial samples |
| SOREL-20M | 8,000,000 | 98.91% | 0.9993 | 99.1% | **15 GB**, vượt khả năng RTX 3050 |
| BODMAS | 134,435 | 96.30% | 0.9982 | 95.4% | Quá nhỏ, không đủ generalize |

→ **Lựa chọn**: EMBER 2017 vì cân bằng giữa kích thước và tài nguyên (RTX 3050 train được).

### 2.3. CWE Classification (so sánh source nhãn CWE)

| Source | # CWE classes | # mẫu | Macro-F1 | Note |
|--------|----------------|--------|----------|------|
| NVD (đã chọn, lọc 15 PE-relevant CWEs) | 15 | 78,421 | **85.58%** | Cân bằng, đủ samples mỗi lớp |
| NVD (full 47 CWEs) | 47 | 95,318 | 71.24% | Long-tail nghiêm trọng |
| MITRE CAPEC mapping | 30 | 12,400 | 64.80% | Quá ít samples |

→ **Lựa chọn**: NVD lọc 15 CWE PE-relevant, loại bỏ:
- CWE-399 (Resource Mgmt — quá generic)
- CWE-20  (Input Validation — catch-all, F1 thấp 0.63)
- CWE-77  (Command Injection — overlap CWE-78, F1=0.64)
- CWE-415 (Double Free — overlap CWE-416)
- CWE-189 (Numeric Errors — overlap CWE-190)
- 9 CWE web/non-PE: CWE-79, CWE-89, CWE-22, CWE-352, CWE-862, CWE-74, CWE-284, CWE-120, CWE-434

## 3. Tiêu chí lựa chọn dataset (đưa vào slide)

```
TIÊU CHÍ                      │ TRỌNG SỐ │ LÝ DO
──────────────────────────────┼──────────┼────────────────────
1. Kích thước đủ lớn          │   25%    │ Tránh overfit
2. Nhãn chuẩn công nghiệp     │   25%    │ Reproducibility
3. Cân bằng các lớp           │   15%    │ Tránh bias
4. Cập nhật mới               │   15%    │ Bắt được lỗ hổng mới
5. Tài nguyên train phù hợp   │   10%    │ RTX 3050 chạy được
6. License mở                 │   10%    │ Có thể public code
                                  ─────
                                  100%
```

## 4. Slide kết luận

> **Combination chốt**:
> - **Severity** → NVD CVE (32K mẫu sau dedup) + CVSS vector
> - **CWE**      → NVD CVE lọc 15 PE-relevant CWEs (78K mẫu)
> - **Malware**  → EMBER 2017 (600K + 200K test)
> - **Knowledge base** → MITRE CWE taxonomy + CPE dictionary

## 5. Nguồn tải dataset (cho phần Q&A)

| Dataset | URL | Format | Size |
|---------|-----|--------|------|
| NVD CVE | https://nvd.nist.gov/vuln/data-feeds | JSON | ~3 GB |
| MITRE CWE | https://cwe.mitre.org/data/downloads.html | XML | ~5 MB |
| EMBER 2017 | https://github.com/elastic/ember | JSONL + features | ~9 GB |
| MITRE CAPEC | https://capec.mitre.org/data/downloads.html | XML | ~10 MB |
