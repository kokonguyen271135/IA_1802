# Hướng dẫn Thuyết trình Hệ thống — Hiểu Sâu & Trình Bày Tốt

---

## PHẦN 1 — HỆ THỐNG LÀM GÌ? (Nói 1 câu)

> **"Công cụ tự động phân tích file phần mềm → tìm lỗ hổng bảo mật (CVE) từ cơ sở dữ liệu NVD → dùng AI để đánh giá mức độ nguy hiểm và lọc kết quả liên quan."**

---

## PHẦN 2 — KIẾN TRÚC TỔNG QUAN

```
┌─────────────────────────────────────────────────────────────────┐
│                     NGƯỜI DÙNG (Browser)                        │
│              Upload file (.exe / .dll / requirements.txt)       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP POST /api/analyze
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FLASK BACKEND (app.py)                        │
│                                                                 │
│   ┌──────────────┐          ┌──────────────────────────────┐   │
│   │  PE Binary?  │──YES──▶  │     _analyze_pe()            │   │
│   │  .exe/.dll   │          │  Pipeline 5 bước             │   │
│   └──────┬───────┘          └──────────────────────────────┘   │
│          │ NO                                                    │
│   ┌──────▼───────┐          ┌──────────────────────────────┐   │
│   │  Package     │──YES──▶  │  _analyze_package_manifest() │   │
│   │  Manifest?   │          │  requirements.txt, pom.xml…  │   │
│   └──────────────┘          └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
              JSON response → Frontend hiển thị
```

---

## PHẦN 3 — PIPELINE PHÂN TÍCH PE FILE (Chi tiết từng bước)

Đây là luồng **quan trọng nhất** — khi upload file `.exe` hoặc `.dll`:

### BƯỚC 1 — Static Analysis (PE Parser)
```
File .exe/.dll
      ↓
PEStaticAnalyzer.analyze()
      ↓
Trích xuất:
  • PE Headers   → compile time, checksum, architecture (x86/x64)
  • Sections     → tên (.text, .data, .rsrc), entropy từng section
  • Import table → danh sách DLL và function được import
  • Strings      → URL, IP, registry key, command strings
  • Components   → thư viện nhúng (OpenSSL, zlib, libcurl...)
  • Risk score   → 0–100 dựa trên heuristic rule
```

**Entropy là gì?** Đo mức độ ngẫu nhiên của data trong section:
- Entropy > 7.0 → section bị **pack hoặc mã hóa** → dấu hiệu malware

---

### BƯỚC 2 — EMBER XGBoost (AI Malware Detection)
```
File .exe/.dll
      ↓
ember1390_encoder.py → trích xuất 1.390 features tĩnh
      ↓
XGBoost model (ember2017_xgb.json)
      ↓
Output: probability = 0.0 → 1.0

Phân ngưỡng:
  ≥ 0.80 → CRITICAL (MALWARE)
  ≥ 0.51 → HIGH     (MALWARE)
  ≥ 0.35 → MEDIUM   (SUSPICIOUS)
  ≥ 0.15 → LOW      (SUSPICIOUS)
  < 0.15 → CLEAN    (BENIGN)
```

**Model này làm gì?** Thay thế antivirus signature-based → dùng 1.390 đặc trưng
tĩnh của file để phân loại malware/benign mà không cần internet hay database virus.

**Số liệu:** AUC = 0.9994 | Accuracy = 98.99% | Train: 600K PE samples (EMBER 2017)

---

### BƯỚC 3 — CPE Extraction (Xác định phần mềm)
```
File .exe/.dll
      ↓
CPEExtractor.extract_from_file()
      ↓
Đọc PE VersionInfo resource:
  ProductName   = "WinRAR"
  CompanyName   = "win.rar GmbH"
  FileVersion   = "7.01"
      ↓
Khớp với KNOWN_PATTERNS (rule-based) → cpe:2.3:a:rarlab:winrar:7.01

  Nếu rule-based thất bại:
      ↓
  FAISS Semantic Matcher (AI)
      ↓
  SentenceTransformer encode tên phần mềm → vector
  → Tìm CPE gần nhất trong index (cosine similarity)
  → "WinRAR 7.01" → cpe:2.3:a:rarlab:winrar:7.01 (score: 0.92)
```

**Tại sao cần CPE?** NVD lưu CVE theo CPE (Common Platform Enumeration).
Không có CPE → không query được CVE.

---

### BƯỚC 4 — NVD API Query (Lấy danh sách CVE)
```
CPE: cpe:2.3:a:rarlab:winrar:7.01
      ↓
NVDAPIv2.search_by_cpe(cpe, version)
      ↓
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...
      ↓
Nhận về: danh sách CVE với
  - CVE ID, CVSS score, mô tả
  - Vector string (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
  - Affected version ranges
  - CWE type, KEV status

Rate limit: 50 req/30s (có API key) | 5 req/30s (không có)
```

---

### BƯỚC 5 — AI Enrichment (Làm giàu kết quả bằng AI)

Đây là phần AI phức tạp nhất, gồm 2 sub-pipeline song song:

#### 5A — Ensemble Severity Classification
```
CVE description + CVSS vector string
            ↓
┌───────────────────────────┐    weight=1.00
│  Fine-tuned SecBERT       │ ────────────────────────┐
│  (bert_severity/)         │                         ↓
│  Accuracy: 98.13%         │              Confidence-Weighted
└───────────────────────────┘              Voting Ensemble
                                                      ↓
┌───────────────────────────┐              score[label] +=
│  XGBoost + TF-IDF + CVSS │ ────────────── weight × conf
│  (xgboost_severity.pkl)   │    weight=0.85           ↓
│  Accuracy: 89.24%         │              Normalize → argmax
└───────────────────────────┘                         ↓
                                          Output:
                                          {
                                            predicted_severity: "CRITICAL",
                                            confidence: 0.94,
                                            source: "ensemble",
                                            models_used: ["bert", "xgboost"]
                                          }
```

**SecBERT hiểu gì?**
Input: `"Buffer overflow in OpenSSL allows remote code execution... AV:N/AC:L/PR:N"`
- Tokenizer tách thành subwords → 256 token tối đa
- Format: `[CLS] description [SEP] AV_N AC_L PR_N UI_N ...`
- 12 lớp Transformer → vector 768 chiều → Linear head → Softmax 4 class
- Output: `{CRITICAL: 0.94, HIGH: 0.05, MEDIUM: 0.01, LOW: 0.00}`

**XGBoost hiểu gì?**
Input: description + CVSS vector
- TF-IDF(description) → 5,000 features (unigram + bigram)
- CVSS encoding: AV:N=3, AV:A=2, AV:L=1, AV:P=0; AC:L=1, AC:H=0...
- Tổng: 5,008 features → XGBoost 200 cây → probabilities

**Tại sao cần Ensemble?**
- BERT giỏi hiểu ngữ nghĩa nhưng cần GPU, chậm (106ms/sample)
- XGBoost không cần GPU, cực nhanh (0.01ms/sample), backup khi BERT lỗi
- Ensemble giảm variance: 2 model đồng ý → tự tin hơn

---

#### 5B — SecBERT Relevance Scoring (Lọc CVE liên quan)
```
PE Analysis (behavior profile)
      ↓
build_profile_text() → văn bản tự nhiên mô tả hành vi PE:
  "This Windows executable imports APIs from Process Injection,
   Network Communication. Uses VirtualAllocEx, WriteProcessMemory,
   CreateRemoteThread. Has 2 high-entropy sections..."
      ↓
SecBERT encode → vector 768 chiều (profile_vec)
      ↓
Với mỗi CVE description:
  SecBERT encode → vector 768 chiều (cve_vec)
  similarity = cosine(profile_vec, cve_vec) → 0.0–1.0
      ↓
Mapping:
  ≥ 0.72 → CRITICAL relevance
  ≥ 0.55 → HIGH
  ≥ 0.50 → MEDIUM
  ≥ 0.30 → LOW
  < 0.30 → MINIMAL → BỊ LỌC BỎ

→ Chỉ giữ lại CVE thực sự liên quan đến hành vi của file
```

**Đây là điểm mới của đề tài:** Tool thông thường trả về TẤT CẢ CVE
của phần mềm đó. Hệ thống này chỉ giữ CVE liên quan đến hành vi
CỤ THỂ của file đang phân tích.

---

### BƯỚC 6 — CWE Prediction (Track 3 — Khi không tìm được CPE)
```
Không tìm được CPE/CVE?
      ↓
CWEPredictor.predict_and_fetch()
      ↓
Rule-based mapping: API imports → CWE
  VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    → CWE-94 (Code Injection, conf=0.95)
  ShellExecute + CreateProcess + network APIs
    → CWE-78 (OS Command Injection, conf=0.90)
  High-entropy sections
    → CWE-506 (Embedded Malicious Code, conf=0.70)
      ↓
Query NVD theo CWE (chỉ khi EMBER ≥ 50%)
      ↓
CVE suggestions (advisory-only, không phải confirmed match)
```

---

### BƯỚC 7 — Recommendations (Gợi ý khắc phục)
```
Danh sách CVE đã enriched
      ↓
_generate_recommendations() — pure rule-based logic
      ↓
Phân tích:
  • CRITICAL/HIGH CVEs + AV:Network + AC:Low
    → "Update ngay, không dùng trên production"
  • CVE về auth bypass
    → "Patch auth + bật MFA"
  • CVE về memory corruption
    → "Enable DEP/ASLR/stack canary"
  • fixed_version có sẵn
    → "Upgrade lên version X"
      ↓
Output: recommendations[], top_threats[], update_decision{}
```

---

## PHẦN 4 — PIPELINE PHÂN TÍCH PACKAGE MANIFEST

Khi upload `requirements.txt`, `package.json`, `pom.xml`...

```
requirements.txt:
  flask==2.3.0
  requests==2.28.0
  numpy==1.24.0
      ↓
PackageAnalyzer.analyze()
  → parse từng dependency → (name, version, ecosystem)
      ↓
Với mỗi package:
  NVD search by CPE (python:flask:2.3.0)
  → danh sách CVE
      ↓
Tổng hợp tất cả CVE → ai_enrich_severity() → recommendations()
```

---

## PHẦN 5 — CÁC MODEL AI — BẢNG TÓM TẮT

| Model | File | Nhiệm vụ | Accuracy | Input | Output |
|-------|------|----------|----------|-------|--------|
| **SecBERT Severity** | `models/bert_severity/` | Phân loại CVE severity | **98.13%** | CVE text + CVSS | CRITICAL/HIGH/MEDIUM/LOW |
| **XGBoost Severity** | `models/xgboost_severity.pkl` | Phân loại CVE severity (backup) | **89.24%** | TF-IDF + CVSS features | CRITICAL/HIGH/MEDIUM/LOW |
| **EMBER XGBoost** | `models/ember2017_xgb.json` | Phát hiện malware PE | **98.99%** | 1,390 static features | Probability 0–1 |
| **SecBERT Relevance** | HuggingFace (online) | Lọc CVE theo hành vi PE | — | PE text + CVE text | Cosine similarity 0–1 |
| **FAISS CPE** | `models/cpe_index.faiss` | Tìm CPE khi rule thất bại | — | Tên phần mềm | CPE string |

---

## PHẦN 6 — TẠI SAO DÙNG SecBERT THAY VÌ BERT THƯỜNG?

| | BERT gốc | SecBERT |
|--|---------|---------|
| Pre-train data | Wikipedia, sách | CVE database, exploit reports, security blogs |
| Hiểu "heap boundary" | Không | **Có** (tương đương "buffer overflow") |
| Hiểu "privilege escalation" | Yếu | **Mạnh** (gặp nhiều trong training) |
| Dùng cho | NLP chung | **Cybersecurity NLP** |

---

## PHẦN 7 — QUY TRÌNH CHẠY HỆ THỐNG THỰC TẾ

### Khởi động:
```bash
cd backend
python app.py
```

Khi khởi động, hệ thống in ra:
```
[+] NVD API v2 initialized
[+] SecBERT CWE classifier (15 classes)     ← ML model load
[+] EMBER Behavioral Scorer: ENABLED        ← XGBoost load
[+] Severity Pipeline: ENABLED (bert, xgboost)
[+] SecBERT Semantic Relevance: ENABLED
[+] Semantic CPE Matcher (FAISS): ENABLED
```

### Khi upload file WinRAR.exe:
```
[PE] Analyzing: WinRAR.exe
[PE] EMBER score: 3.2% → BENIGN (CLEAN)        ← bước 2
[CPE] Extracted: rarlab:winrar:7.01 (rule-based) ← bước 3
[NVD] Querying CPE: cpe:2.3:a:rarlab:winrar:7.01 ← bước 4
[NVD] Found 12 CVEs
[AI] Severity ensemble: bert + xgboost           ← bước 5A
[AI] SecBERT relevance scoring 12 CVEs...        ← bước 5B
[AI] Filtered: 8 relevant CVEs kept (4 removed)
```

---

## PHẦN 8 — CÂU HỎI HỘI ĐỒNG — TRẢ LỜI SẴN

**"Tại sao cần Ensemble, BERT 98% không đủ sao?"**
> XGBoost bổ sung thông tin cấu trúc CVSS numerical (AV, AC, PR...) — thứ
> BERT không xử lý tốt vì đó là số, không phải ngôn ngữ. Ensemble còn đảm bảo
> hệ thống hoạt động ngay cả khi GPU không có — XGBoost chạy CPU hoàn toàn.

**"EMBER 2017 có lỗi thời không?"**
> Feature tĩnh của PE file (headers, imports, entropy, sections) không thay đổi
> theo năm — chúng là đặc trưng cố định của định dạng file. Dataset EMBER vẫn
> là benchmark chuẩn công nghiệp. Hệ thống có script retrain tại
> `utils/retrain_xgboost.py` khi cần.

**"SecBERT relevance được validate chưa?"**
> Cosine similarity trong embedding space là metric NLP chuẩn. Threshold
> (0.72/0.55/0.50/0.30) chọn dựa trên thực nghiệm trên tập CVE thực từ NVD.

**"Nếu không xác định được phần mềm thì sao?"**
> Track 3 — CWE Prediction: phân tích API imports → dự đoán CWE →
> query NVD theo CWE → trả về CVE advisory-only (không phải confirmed match).
> Hệ thống minh bạch với người dùng rằng đây là gợi ý hành vi, không phải match chính xác.

**"Hệ thống xử lý file script/APK thế nào?"**
> Nhánh Package Manifest riêng — parse requirements.txt, package.json, pom.xml,
> go.mod, Gemfile... → query NVD theo ecosystem + tên package + version.
> Không dùng EMBER (chỉ dành cho PE binary).

**"Graceful degradation là gì?"**
> Mỗi model có thể tắt độc lập mà hệ thống vẫn chạy:
> - Không có GPU → chỉ XGBoost severity (0.01ms/sample)
> - Không có FAISS → chỉ rule-based CPE matching
> - Không có EMBER → fallback về CVSS score
> - Không có SecBERT → sort CVE theo CVSS score

---

## PHẦN 9 — ĐIỂM MẠNH SO VỚI TOOL TRUYỀN THỐNG

| Tính năng | Tool truyền thống | Hệ thống này |
|-----------|-------------------|-------------|
| Phát hiện malware | Signature (cần update) | ML 1,390 features (static, không cần internet) |
| Tìm CVE | Chỉ theo tên/version | **CPE chuẩn NVD + FAISS semantic fallback** |
| Lọc CVE liên quan | Không (trả hết) | **SecBERT cosine similarity** |
| Đánh giá severity | Chỉ CVSS score | **Fine-tuned BERT 98.13%** |
| File không rõ nguồn | Bỏ qua | **CWE prediction từ behavior** |
| Dependency scan | Tách biệt | **Tích hợp cùng pipeline** |

---

## PHẦN 10 — SƠ ĐỒ LUỒNG DỮ LIỆU ĐẦY ĐỦ

```
                    ┌─────────────┐
                    │  File Upload │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │                         │
         PE Binary                Package Manifest
    (.exe/.dll/.sys)        (requirements.txt, pom.xml...)
              │                         │
    ┌─────────▼──────────┐   ┌──────────▼──────────┐
    │ 1. PE Static Anal. │   │ Parse dependencies   │
    │    pefile library  │   │ per ecosystem        │
    │    1390 features   │   └──────────┬──────────┘
    └─────────┬──────────┘              │
              │                         │
    ┌─────────▼──────────┐   ┌──────────▼──────────┐
    │ 2. EMBER XGBoost   │   │ NVD query per pkg   │
    │    Malware score   │   │ by CPE string        │
    │    AUC=0.9994      │   └──────────┬──────────┘
    └─────────┬──────────┘              │
              │                    All CVEs
    ┌─────────▼──────────┐              │
    │ 3. CPE Extraction  │              │
    │  Rule-based →      │              │
    │  FAISS fallback    │              │
    └─────────┬──────────┘              │
              │                         │
    ┌─────────▼──────────┐              │
    │ 4. NVD API Query   │              │
    │  search_by_cpe()   │              │
    └─────────┬──────────┘              │
              │                         │
    ┌─────────▼──────────┐              │
    │ 5. AI Enrichment   │◄─────────────┘
    │                    │
    │  5A. Ensemble:     │
    │   SecBERT(98.13%)  │
    │   + XGBoost(89.24%)│
    │   → severity label │
    │                    │
    │  5B. SecBERT:      │
    │   cosine sim       │
    │   → filter LOW CVE │
    └─────────┬──────────┘
              │
    ┌─────────▼──────────┐
    │ 6. CWE Prediction  │  ← chỉ khi không có CPE/CVE
    │  (Track 3)         │
    │  behavior → CWE    │
    └─────────┬──────────┘
              │
    ┌─────────▼──────────┐
    │ 7. Recommendations │
    │  rule-based logic  │
    │  + update_decision │
    └─────────┬──────────┘
              │
    ┌─────────▼──────────┐
    │   JSON Response    │
    │   → Frontend UI    │
    └────────────────────┘
```
