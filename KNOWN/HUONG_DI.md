# Các Hướng Đi của Đồ Án

## Tổng Quan

Đồ án xây dựng công cụ đánh giá lỗ hổng phần mềm kết hợp AI và cơ sở dữ liệu CVE (NVD).
Hệ thống có 3 hướng xử lý chính (pipeline chính, fallback, và phân tích gói phụ thuộc).

---

## Hướng 1 — Phân Tích PE Binary (Hướng Chính)

**Mục tiêu:** Từ một file .exe / .dll / .sys → tìm CVE liên quan đến phần mềm đó.

**Luồng xử lý:**

```
Upload PE file
    │
    ▼
[Static Analysis]
  - Phân tích PE headers, import table, sections
  - Phân loại hành vi (Process Injection, Keylogging, v.v.)
  - Tính entropy từng section (phát hiện packing)
  - Quét chuỗi strings (URL, IP, Base64, lệnh hệ thống)
  - Nhận dạng component nhúng (OpenSSL, Python, libcurl...)
    │
    ▼
[CPE Resolution — 3 lớp fallback]
  Lớp 1: Rule-based — đọc PE VersionInfo + đối chiếu KNOWN_PATTERNS
  Lớp 2: Claude AI — gửi metadata → Claude trả về vendor/product
  Lớp 3: FAISS Semantic — vector search trong index CPE
    │
    ▼
[NVD API Query]
  Chính: search_by_cpe(cpe)
  Fallback: search_by_keyword(product + version) nếu CPE trả về 0 kết quả
    │
    ▼
[AI Enrichment]
  - Phân loại severity từng CVE (Ensemble BERT + XGBoost + TF-IDF)
  - Tính relevance score (SecBERT semantic similarity)
  - Tính AI Risk Score tổng hợp
  - Sinh narrative (Claude)
    │
    ▼
JSON Response → Frontend
```

**Ưu điểm:** Chính xác khi nhận dạng được CPE, kết quả sát với phần mềm thực tế.

---

## Hướng 2 — Phân Tích Gói Phụ Thuộc (Package Manifest)

**Mục tiêu:** Quét toàn bộ dependency của một project → phát hiện CVE trong từng thư viện.

**Hỗ trợ các ecosystem:**

| File | Ngôn ngữ |
|------|----------|
| requirements.txt, Pipfile, setup.cfg | Python |
| package.json, yarn.lock | Node.js |
| pom.xml, build.gradle | Java |
| composer.json | PHP |
| go.mod | Go |
| Cargo.toml | Rust |

**Luồng xử lý:**

```
Upload manifest file
    │
    ▼
PackageAnalyzer nhận diện ecosystem
    │
    ▼
Trích xuất danh sách (package_name, version)
    │
    ▼
Với mỗi package:
    ├─ Tìm CPE từ _KNOWN_CPE hints
    ├─ Fallback: Claude AI match
    ├─ Fallback: FAISS semantic match
    └─ Query NVD by CPE hoặc keyword
    │
    ▼
Enrich CVE (severity pipeline, relevance)
    │
    ▼
Tổng hợp toàn bộ CVE → thống kê global
```

**Ưu điểm:** Phù hợp với DevSecOps, quét nhanh toàn bộ supply chain trong một lần.

---

## Hướng 3 — Dự Đoán CWE từ Hành Vi PE (Fallback Thông Minh)

**Mục tiêu:** Khi không xác định được CPE, dùng hành vi thực tế của PE để dự đoán loại lỗ hổng (CWE) → tìm CVE theo CWE đó.

**Khi nào kích hoạt:**
- Không tìm được CPE từ cả 3 lớp (rule, AI, FAISS)
- Hoặc CPE trả về 0 CVE từ NVD

**Luồng xử lý:**

```
PE Analysis result (imports, strings, sections, entropy)
    │
    ▼
[CWE Prediction]
  Phương án 1: SecBERT ML model (nếu đã train)
    └─ Input: text mô tả hành vi PE (ngôn ngữ tự nhiên)
    └─ Output: Top-5 CWE + confidence score
  Phương án 2: Rule-based mapping
    └─ API categories → CWE (vd: Process Injection → CWE-94)
    └─ String patterns → CWE (vd: IP addr → CWE-918)
    └─ Entropy cao → CWE-506 (packed/encrypted code)
    │
    ▼
[Target Detection]
  Phân tích DLL imports, registry strings, file paths
  Nhận dạng phần mềm mục tiêu (Microsoft Office, Adobe, Firefox...)
    │
    ▼
[NVD Query by CWE]
  Với mỗi CWE dự đoán + target:
    └─ nvd_api.search_by_cwe(CWE-ID, keyword=target)
    │
    ▼
[Relevance Filtering]
  Lọc CVE phù hợp với hành vi Windows/native
  Loại bỏ CVE chỉ liên quan đến web (nếu PE không phải web)
  Sắp xếp theo relevance + CWE confidence + CVSS
```

**Ưu điểm:** Hệ thống không bao giờ trả về tay không — luôn có kết quả dựa trên hành vi thực tế.

---

## So Sánh 3 Hướng

| | Hướng 1 (PE+CPE) | Hướng 2 (Package) | Hướng 3 (CWE Behavior) |
|--|--|--|--|
| Input | PE binary | Manifest file | PE binary (fallback) |
| Điểm mạnh | Chính xác | Nhanh, rộng | Không cần CPE |
| Điểm yếu | Cần xác định CPE | Không phân tích binary | Kết quả gián tiếp |
| Khi dùng | Ưu tiên trước | Project audit | Khi CPE thất bại |

---

## Kiến Trúc Tổng Thể

```
Frontend (HTML/JS)
    │  HTTP
    ▼
Flask Backend (app.py)
    ├── static_analyzer.py       ← phân tích PE
    ├── package_analyzer.py      ← phân tích manifest
    ├── cpe_extractor.py         ← nhận dạng CPE
    ├── ai_analyzer.py           ← tích hợp Claude AI
    ├── cpe_semantic_matcher.py  ← FAISS CPE index
    ├── cwe_predictor.py         ← Hướng 3
    ├── nvd_api_v2.py            ← NVD API client
    └── ai/
        ├── severity_pipeline.py ← Ensemble severity
        └── relevance_scorer.py  ← SecBERT relevance
```
