# Thuyết Trình Luận Văn
## Nghiên cứu và Phát triển Công cụ Đánh giá Lỗ hổng Phần mềm kết hợp AI và Cơ sở Dữ liệu CVE

---

## MỤC LỤC

1. [Giới thiệu & Bài toán](#1-giới-thiệu--bài-toán)
2. [Cách cài đặt & Chạy hệ thống](#2-cách-cài-đặt--chạy-hệ-thống)
3. [Kiến trúc tổng thể](#3-kiến-trúc-tổng-thể)
4. [Luồng xử lý chi tiết](#4-luồng-xử-lý-chi-tiết)
5. [Các Model AI sử dụng](#5-các-model-ai-sử-dụng)
6. [Thuật toán cốt lõi](#6-thuật-toán-cốt-lõi)
7. [Kết quả & Đánh giá](#7-kết-quả--đánh-giá)
8. [Demo chức năng](#8-demo-chức-năng)

---

## 1. Giới thiệu & Bài toán

### 1.1 Đặt vấn đề

Trong bảo mật phần mềm, việc phát hiện và đánh giá lỗ hổng là công việc tốn thời gian và đòi hỏi chuyên môn sâu. Các công cụ hiện tại thường:

- Yêu cầu người dùng biết chính xác tên/phiên bản phần mềm (khó khi chỉ có file .exe)
- Không đánh giá được mức độ nguy hiểm trong ngữ cảnh cụ thể
- Không hỗ trợ phân tích hành vi khi không có CVE

### 1.2 Mục tiêu luận văn

> **Xây dựng công cụ tự động phân tích file phần mềm → xác định lỗ hổng CVE → đánh giá rủi ro bằng AI**

Ba đóng góp chính:

| # | Đóng góp | Kỹ thuật |
|---|----------|----------|
| 1 | Tự động định danh phần mềm từ file binary | 3-tier CPE Pipeline (Rule → FAISS → Claude AI) |
| 2 | Phân loại mức độ nghiêm trọng CVE bằng Ensemble ML | SecBERT + XGBoost + TF-IDF |
| 3 | Dự đoán lỗ hổng theo hành vi khi không có CPE | CWE Behavior Prediction (Hướng 3) |

### 1.3 Input / Output

```
INPUT  → File .exe / .dll / .sys         (PE Binary)
         hoặc requirements.txt / package.json  (Package Manifest)
         hoặc tên phần mềm + phiên bản   (Text search)

OUTPUT → Danh sách CVE với CVSS score + severity
         AI severity prediction (ensemble model)
         CVE relevance score với file đang phân tích
         Tóm tắt rủi ro bằng ngôn ngữ tự nhiên (Claude AI)
         Khuyến nghị xử lý cụ thể
```

---

## 2. Cách cài đặt & Chạy hệ thống

### 2.1 Yêu cầu hệ thống

| Thành phần | Phiên bản |
|-----------|----------|
| Python | 3.10+ |
| RAM | Tối thiểu 4GB (8GB nếu dùng BERT) |
| GPU | Không bắt buộc (BERT chạy được trên CPU) |
| OS | Windows / Linux / macOS |

### 2.2 Cài đặt

**Bước 1: Clone project & tạo môi trường**
```bash
git clone https://github.com/kokonguyen271135/IA_1802.git
cd IA_1802
python -m venv venv
source venv/bin/activate    # Linux/macOS
# hoặc: venv\Scripts\activate  (Windows)
```

**Bước 2: Cài thư viện**
```bash
pip install -r requirements.txt
```

> **Lưu ý:** Nếu máy không có GPU, PyTorch vẫn chạy trên CPU được.
> Nếu muốn cài nhanh hơn (bỏ deep learning):
> ```bash
> pip install flask flask-cors pandas numpy scikit-learn pefile rapidfuzz requests anthropic
> ```

**Bước 3: Cấu hình API Keys**
```bash
# Tạo file .env ở thư mục gốc
echo "ANTHROPIC_API_KEY=sk-ant-xxxx" > .env
echo "NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" >> .env
```

> Đăng ký API key miễn phí:
> - NVD API: https://nvd.nist.gov/developers/request-an-api-key
> - Anthropic (Claude): https://console.anthropic.com/

**Bước 4: Build models (lần đầu, offline)**
```bash
# 4a. Build FAISS CPE index (~800K CPE entries, chạy 1 lần ~10 phút)
python untils/build_cpe_index.py

# 4b. Train severity models (nếu chưa có models/)
python untils/run_training_pipeline.py

# 4c. Fine-tune BERT (optional, cần GPU hoặc ~2h trên CPU)
python untils/finetune_bert_severity.py
```

> Nếu đã có file `models/` (commit sẵn trong repo) thì **bỏ qua bước 4**.

### 2.3 Chạy server

```bash
# Từ thư mục gốc
python backend/app.py
```

**Kết quả khởi động:**
```
======================================================================
[*] SOFTWARE VULNERABILITY ASSESSMENT TOOL
    AI + CVE Database Edition
======================================================================
[+] NVD API v2 initialized
[+] CPE Extractor initialized
[+] PE Static Analyzer initialized
[+] Package Analyzer initialized
[+] CWE Predictor initialized (Hướng 3)

[*] AI Feature Status:
[+] Claude AI (CPE matching + risk narrative): ENABLED
[+] Semantic CPE Matcher (FAISS): ENABLED
[+] Severity Pipeline: ENABLED (bert, xgboost, tfidf)
[+] SecBERT Semantic Relevance: ENABLED

 * Running on http://127.0.0.1:5000
```

Mở trình duyệt: **http://localhost:5000**

### 2.4 Sử dụng qua API (cURL)

```bash
# Phân tích file PE
curl -X POST http://localhost:5000/api/analyze \
     -F "file=@winrar.exe"

# Phân tích package manifest
curl -X POST http://localhost:5000/api/analyze \
     -F "file=@requirements.txt"

# Tìm kiếm theo tên phần mềm
curl -X POST http://localhost:5000/api/search \
     -H "Content-Type: application/json" \
     -d '{"software_name": "winrar", "version": "6.24"}'

# Truy vấn theo CPE trực tiếp
curl -X POST http://localhost:5000/api/query-cpe \
     -H "Content-Type: application/json" \
     -d '{"cpe": "cpe:2.3:a:rarlab:winrar:6.24:*:*:*:*:*:*:*"}'

# Kiểm tra trạng thái models
curl http://localhost:5000/api/status
```

### 2.5 Cấu trúc thư mục quan trọng

```
IA_1802/
├── backend/app.py          ← Điểm khởi động server
├── backend/                ← Toàn bộ logic xử lý
├── frontend/               ← Giao diện web
├── models/                 ← Trained models (FAISS, pkl)
├── data/cache/nvd/         ← Cache CVE JSON (tự tạo)
├── uploads/                ← File upload tạm (tự xóa sau scan)
├── .env                    ← API keys (không commit)
└── requirements.txt        ← Dependencies
```

---

## 3. Kiến trúc tổng thể

```
┌──────────────────────────────────────────────────────────────────────┐
│                         TẦNG GIAO DIỆN                               │
│                    Browser (HTML + JS + CSS)                         │
│         Upload file ──── Hiển thị kết quả CVE ──── Export PDF       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ HTTP REST / JSON
┌──────────────────────────────▼───────────────────────────────────────┐
│                         TẦNG API (Flask)                             │
│  /api/analyze   /api/search   /api/query-cpe   /api/status          │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
┌───────▼────────┐   ┌─────────▼────────┐   ┌────────▼────────┐
│  File Analysis │   │  CPE Extraction  │   │   NVD API v2    │
│                │   │                  │   │                 │
│ PE Binary      │   │ Rule-based       │   │ search_by_cpe   │
│ (pefile lib)   │   │ + FAISS Semantic │   │ search_by_cwe   │
│                │   │ + Claude Haiku   │   │ (with cache)    │
│ Package Mfst   │   │                  │   │                 │
│ (7 ecosystems) │   │                  │   │                 │
└────────────────┘   └──────────────────┘   └─────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
┌───────▼────────┐   ┌─────────▼────────┐   ┌────────▼────────┐
│ Severity       │   │  CVE Relevance   │   │  Claude AI      │
│ Pipeline       │   │  Scorer          │   │  Risk Narrative │
│                │   │                  │   │                 │
│ SecBERT 97.94% │   │ SecBERT Cosine   │   │ claude-sonnet   │
│ XGBoost 92-96% │   │ Similarity       │   │ Overall Risk    │
│ TF-IDF 86.83%  │   │                  │   │ Top Threats     │
│ Ensemble Vote  │   │                  │   │ Remediation     │
└────────────────┘   └──────────────────┘   └─────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────┐
│                      TẦNG DỮ LIỆU & MODEL                           │
│                                                                      │
│  NVD Cache (JSON)  │  FAISS Index  │  ML Models (.pkl)  │  Train CSV │
└──────────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────┐
│                       EXTERNAL APIs                                  │
│   NVD API v2 (nvd.nist.gov)   │   Anthropic Claude API              │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Luồng xử lý chi tiết

### 4.1 Luồng phân tích PE Binary (End-to-End)

```
╔══════════════════════════════════════════════════════════════════════╗
║  NGƯỜI DÙNG upload file winrar.exe                                  ║
╚═════════════════════════════╦════════════════════════════════════════╝
                              ║
                   ┌──────────▼──────────┐
                   │   BƯỚC 1            │
                   │   PE STATIC         │
                   │   ANALYSIS          │
                   │                     │
                   │  Đọc PE headers     │
                   │  → ProductName:     │
                   │    "WinRAR archiver"│
                   │  → Company: "RarLab"│
                   │  → Version: 6.24   │
                   │                     │
                   │  Import APIs:       │
                   │  → 247 functions    │
                   │  → Suspicious: 12  │
                   │    (Process Inj x3 │
                   │     Network x5     │
                   │     FileSys x4)    │
                   │                     │
                   │  Sections:          │
                   │  → .text entropy=  │
                   │    6.2 (normal)    │
                   │  → .rsrc entropy=  │
                   │    7.8 (HIGH!)     │
                   │                     │
                   │  Risk Score: 45/100 │
                   │  Level: MEDIUM      │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │   BƯỚC 2            │
                   │   CPE EXTRACTION    │
                   │   (3-tier)          │
                   │                     │
                   │  Tier 1: KNOWN_     │
                   │  PATTERNS lookup    │
                   │  "RarLab" + "WinRAR"│
                   │  → MATCH!           │
                   │  vendor = "rarlab"  │
                   │  product = "winrar" │
                   │                     │
                   │  CPE =              │
                   │  cpe:2.3:a:rarlab:  │
                   │  winrar:6.24:*:*:   │
                   │  *:*:*:*:*          │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │   BƯỚC 3            │
                   │   NVD API QUERY     │
                   │                     │
                   │  GET /rest/json/    │
                   │  cves/2.0?          │
                   │  cpeName=cpe:2.3:a: │
                   │  rarlab:winrar:6.24 │
                   │                     │
                   │  → 47 CVEs found   │
                   │  → Cache to JSON   │
                   │                     │
                   │  Top CVE:           │
                   │  CVE-2023-38831     │
                   │  CVSS 7.8 HIGH      │
                   │  "Archive path      │
                   │   traversal..."     │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │   BƯỚC 4            │
                   │   SEVERITY PIPELINE │
                   │   (Ensemble ML)     │
                   │                     │
                   │  For each CVE:      │
                   │                     │
                   │  Model 1: SecBERT   │
                   │  → HIGH (conf=0.94) │
                   │                     │
                   │  Model 2: XGBoost   │
                   │  → HIGH (conf=0.89) │
                   │                     │
                   │  Model 3: TF-IDF    │
                   │  → HIGH (conf=0.81) │
                   │                     │
                   │  Ensemble:          │
                   │  HIGH×(1.0+0.85+    │
                   │  0.70) = 2.55       │
                   │  → ai_severity=HIGH │
                   │  → confidence=0.91  │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │   BƯỚC 5            │
                   │   RELEVANCE SCORING │
                   │   (SecBERT Cosine)  │
                   │                     │
                   │  Profile text:      │
                   │  "WinRAR archive    │
                   │   manager, handles  │
                   │   compressed files, │
                   │   network download, │
                   │   high entropy sec" │
                   │                     │
                   │  vs CVE description:│
                   │  "path traversal in │
                   │   archive handling" │
                   │                     │
                   │  cosine_sim = 0.82  │
                   │  → CRITICAL relevance│
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │   BƯỚC 6            │
                   │   CLAUDE AI         │
                   │   RISK NARRATIVE    │
                   │   (claude-sonnet)   │
                   │                     │
                   │  Input: top-10 CVEs │
                   │  + stats            │
                   │                     │
                   │  Output:            │
                   │  overall_risk: HIGH │
                   │  summary: "WinRAR   │
                   │  6.24 có 47 lỗ hổng │
                   │  đã biết, nghiêm    │
                   │  trọng nhất là path │
                   │  traversal..."      │
                   │                     │
                   │  top_threats:       │
                   │  [Archive traversal,│
                   │   Code exec, DoS]  │
                   │                     │
                   │  recommendations:   │
                   │  [Upgrade to 7.10,  │
                   │   Restrict access,  │
                   │   Enable AV scan]  │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │   FINAL RESPONSE    │
                   │   JSON + UI render  │
                   │                     │
                   │  47 CVEs ranked by  │
                   │  relevance + severity│
                   │  + AI summary       │
                   └─────────────────────┘
```

### 4.2 Luồng dự phòng: Khi không có CPE (Hướng 3)

```
File .exe không có VersionInfo rõ ràng
(malware, custom tool, packed binary)
          │
          ▼
CPE Extraction → KHÔNG khớp ở cả 3 tiers
          │
          ▼
┌─────────────────────────────────────────┐
│  CWE BEHAVIOR PREDICTION                │
│  (cwe_predictor.py)                     │
│                                         │
│  Input: Danh sách APIs được import      │
│                                         │
│  Rule Mapping:                          │
│  VirtualAllocEx    → CWE-94 (0.95)      │
│  WriteProcessMemory→ CWE-94 (0.90)      │
│  CreateRemoteThread→ CWE-94 (0.85)      │
│  ShellExecute      → CWE-78 (0.88)      │
│  GetAsyncKeyState  → CWE-200 (0.80)     │
│  Section entropy>7 → CWE-506 (0.75)     │
│                                         │
│  Predicted CWEs:                        │
│  CWE-94  Code Injection      conf=0.95  │
│  CWE-78  OS Cmd Injection    conf=0.88  │
│  CWE-506 Embedded Malicious  conf=0.75  │
└──────────────────┬──────────────────────┘
                   │
                   ▼
NVD API: ?cweId=CWE-94  → 50 CVEs
         ?cweId=CWE-78  → 50 CVEs
         ?cweId=CWE-506 → 30 CVEs
                   │
                   ▼
Deduplicate + Rank by relevance score
                   │
                   ▼
Claude AI: ai_analyze_static_behavior()
→ MITRE ATT&CK techniques
→ Behavioral summary
→ Recommendations
```

### 4.3 Luồng phân tích Package Manifest

```
INPUT: requirements.txt
─────────────────────────────────────────────────
django==4.2.0
requests==2.28.0
pillow==9.5.0
cryptography==38.0.0
─────────────────────────────────────────────────
          │
          ▼ PackageAnalyzer.parse()
          │
  [Package List]:
  django 4.2.0 (Python/pip)
  requests 2.28.0 (Python/pip)
  pillow 9.5.0 (Python/pip)
  cryptography 38.0.0 (Python/pip)
          │
          ▼ CPE Mapping (parallel)
          │
  django      → cpe:2.3:a:djangoproject:django:4.2.0:*:*:*:*:*:*:*
  requests    → cpe:2.3:a:python-requests:requests:2.28.0:*:*:*:*:*:*:*
  pillow      → cpe:2.3:a:python-pillow:pillow:9.5.0:*:*:*:*:*:*:*
  cryptography→ cpe:2.3:a:cryptography:cryptography:38.0.0:*:*:*:*:*:*:*
          │
          ▼ NVD Query (for each package)
          │
  django 4.2.0      → 2 CVEs (MEDIUM, LOW)
  requests 2.28.0   → 0 CVEs
  pillow 9.5.0      → 5 CVEs (HIGH x2, MEDIUM x3)
  cryptography 38.0 → 8 CVEs (CRITICAL x1, HIGH x4, MEDIUM x3)
          │
          ▼ Severity + Relevance Enrichment
          │
  FINAL: 15 total CVEs across 3 packages
  Highest risk: cryptography (CRITICAL CVE-2023-49083)
```

---

## 5. Các Model AI sử dụng

### 5.1 Claude AI (Anthropic)

#### Model 1: `claude-haiku-4-5` — CPE Identification

```
Nhiệm vụ: Xác định vendor/product CPE từ metadata phần mềm

Lý do chọn claude-haiku:
  → Fast inference (<1s)
  → Cheap (giá thấp, dùng nhiều lần cho mỗi file upload)
  → Đủ thông minh cho structured extraction task

Prompt strategy: Zero-shot với few-shot examples
Input:
  - ProductName: "WinRAR archiver"
  - CompanyName: "RarLab"
  - Filename: "winrar.exe"
  - Version: "6.24.0"

Output (JSON):
  {
    "vendor": "rarlab",
    "product": "winrar",
    "confidence": "high",
    "reasoning": "RarLab is the developer of WinRAR"
  }

Triggered when: CPE không tìm được qua rule-based hoặc FAISS
Use cases:
  - Phần mềm tên tiếng nước ngoài / viết tắt
  - Tên thương mại ≠ tên CPE kỹ thuật
  - Edge cases: "Adobe Acrobat" → vendor="adobe", product="acrobat_reader"
```

#### Model 2: `claude-sonnet-4-6` — Risk Narrative

```
Nhiệm vụ: Tạo báo cáo rủi ro bằng ngôn ngữ tự nhiên

Lý do chọn claude-sonnet:
  → Reasoning mạnh hơn cho security analysis
  → Hiểu context multi-CVE phức tạp
  → Tạo khuyến nghị thực tế, không chung chung

Input: Top-10 CVEs (by CVSS) + statistics + software metadata

Output Structure:
  {
    "overall_risk": "HIGH",
    "risk_summary": "WinRAR 6.24 có 47 lỗ hổng đã biết. Nghiêm trọng
                     nhất là CVE-2023-38831 (CVSS 7.8) cho phép attacker
                     thực thi code tùy ý khi người dùng mở archive độc hại.",
    "top_threats": [
      "Archive path traversal (CVE-2023-38831) - Remote Code Execution",
      "ZIP bomb/DoS attacks (CVE-2022-30333) - Denial of Service",
      "Memory corruption in RAR5 handler - Potential heap overflow"
    ],
    "recommendations": [
      "Upgrade WinRAR to version 7.10 (latest)",
      "Restrict archive handling to trusted sources only",
      "Enable Windows Exploit Guard for winrar.exe"
    ],
    "key_attack_vectors": ["Network", "Local"]
  }

Static behavior analysis (khi không có CVE):
  Input: PE static analysis findings (APIs, entropy, strings)
  Output: MITRE ATT&CK techniques, CWE suggestions, behavioral summary
```

### 5.2 SecBERT — Domain-specific Security BERT

```
Base model: jackaduma/SecBERT
  → BERT trained trên security text corpus (CVE, NVD, security papers)
  → Hiểu domain-specific terminology tốt hơn BERT gốc

Dùng trong HAI task:

Task A: Severity Classification (Fine-tuned)
  Fine-tuned trên: data/training/cve_severity_train.csv
  Training data: ~50,000 CVE descriptions + NVD CVSS labels
  Architecture: SecBERT + Linear classifier (4 classes)
  Max token length: 256
  Accuracy: 97.94%

  Tại sao tốt hơn TF-IDF:
    TF-IDF: "memory corruption" ≠ "buffer overflow" (khác token)
    SecBERT: "memory corruption" ≈ "buffer overflow" (cùng semantic space)

Task B: CVE Relevance Scoring (Inference only, no fine-tune)
  Dùng SecBERT như sentence encoder:
  → Build software profile text → encode → vector 768-dim
  → Encode mỗi CVE description → vector 768-dim
  → Cosine similarity = relevance score
  Mean pooling qua all tokens → sentence vector
```

### 5.3 Sentence-BERT (MiniLM-L6) — CPE Semantic Search

```
Model: sentence-transformers/all-MiniLM-L6-v2
  → Nhẹ hơn BERT gốc (6 layers thay vì 12)
  → Tối ưu cho semantic similarity tasks
  → 384-dim vector output

Nhiệm vụ: Tìm CPE phù hợp nhất trong ~800,000 entries NVD

Cách xây dựng FAISS index (offline):
  1. Tải NVD CPE dictionary (~800K entries)
  2. Format mỗi entry thành text: "vendor product version"
  3. Encode tất cả → ma trận (800K × 384)
  4. Build FAISS IndexFlatIP (Inner Product)
  5. Lưu: models/cpe_index.faiss + models/cpe_meta.pkl

Query tại runtime:
  query = "WinRAR archiver RarLab"
  query_vec = model.encode(query)  # 384-dim
  D, I = index.search(query_vec, k=5)  # top-5 candidates
  → Trả về CPE có cosine similarity cao nhất
```

---

## 6. Thuật toán cốt lõi

### 6.1 Thuật toán Ensemble Severity Classification

```
Mục tiêu: Dự đoán severity (CRITICAL/HIGH/MEDIUM/LOW) với độ chính xác cao nhất
          bằng cách kết hợp 3 model khác nhau.

Input: CVE description text + CVSS vector string

────────────────────────────────────────────────────────────────────
Model 1: TF-IDF + Logistic Regression (baseline)
────────────────────────────────────────────────────────────────────
  Features: TF-IDF(description, max_features=50000, ngram_range=(1,2))
  Classifier: LogisticRegression(C=1.0, multi_class='multinomial')
  Output: {CRITICAL: 0.1, HIGH: 0.7, MEDIUM: 0.15, LOW: 0.05}
  Weight: 0.70

────────────────────────────────────────────────────────────────────
Model 2: XGBoost + CVSS Feature Engineering
────────────────────────────────────────────────────────────────────
  Text features: TF-IDF(description, max_features=5000)
  CVSS features (8 dimensions):
    AV (Attack Vector):    Network=3, Adjacent=2, Local=1, Physical=0
    AC (Attack Complexity):Low=1, High=0
    PR (Privileges Req.):  None=2, Low=1, High=0
    UI (User Interaction): None=1, Required=0
    S  (Scope):            Changed=1, Unchanged=0
    C  (Confidentiality):  High=2, Medium=1, Low/None=0
    I  (Integrity):        High=2, Medium=1, Low/None=0
    A  (Availability):     High=2, Medium=1, Low/None=0

  Combined: [TF-IDF 5000-dim | CVSS 8-dim] → XGBoost
  Output: {CRITICAL: 0.05, HIGH: 0.82, MEDIUM: 0.1, LOW: 0.03}
  Weight: 0.85

  Lý do dùng XGBoost:
    → Bắt được interaction giữa CVSS metrics
      (AV:Network + PR:None + UI:None = cực kỳ nguy hiểm)
    → Nhanh: <1ms inference, không cần GPU
    → Tự train lại nếu không có model file

────────────────────────────────────────────────────────────────────
Model 3: Fine-tuned SecBERT
────────────────────────────────────────────────────────────────────
  Tokenize: AutoTokenizer.from_pretrained("jackaduma/SecBERT")
  Input: description text, max_length=256, truncate=True
  Forward pass: BERT(input_ids, attention_mask)
  Pooling: [CLS] token representation
  Classifier head: Linear(768 → 4) + Softmax
  Output: {CRITICAL: 0.03, HIGH: 0.91, MEDIUM: 0.05, LOW: 0.01}
  Weight: 1.00

────────────────────────────────────────────────────────────────────
Ensemble Voting (Weighted Soft Voting):
────────────────────────────────────────────────────────────────────
  score[label] = Σ (weight_i × prob_i[label])

  score[CRITICAL] = 0.70×0.10 + 0.85×0.05 + 1.00×0.03 = 0.132
  score[HIGH]     = 0.70×0.70 + 0.85×0.82 + 1.00×0.91 = 1.117  ← MAX
  score[MEDIUM]   = 0.70×0.15 + 0.85×0.10 + 1.00×0.05 = 0.240
  score[LOW]      = 0.70×0.05 + 0.85×0.03 + 1.00×0.01 = 0.086

  predicted_severity = argmax(score) = "HIGH"
  confidence = 1.117 / (0.132+1.117+0.240+0.086) = 0.706

  Graceful degradation:
    Nếu BERT unavailable → chỉ dùng XGBoost + TF-IDF
    Nếu cả 2 ML model unavailable → dùng CVSS NVD score trực tiếp
```

### 6.2 Thuật toán CVE Relevance Scoring

```
Mục tiêu: Với một file PE cụ thể, CVE nào thực sự nguy hiểm?
          (Không phải mọi CVE của WinRAR đều quan trọng như nhau)

Bước 1: Build Software Profile Text
  Profile = kết hợp thông tin hành vi của file:

  profile_text = """
  Software: winrar 6.24
  Suspicious APIs: CreateFile, WriteFile, ZipInflate, MiniZip
  Import categories: File System Manipulation, Network Communication
  Embedded components: zlib 1.2.11 (CVE risk: compression)
  High entropy sections: .rsrc (7.8) - possible packed resources
  Strings: URLs found: update.rarlab.com
  Risk factors: network_communication, file_operations
  """

Bước 2: Encode Profile với SecBERT
  profile_vec = SecBERT.encode(profile_text)
  # profile_vec: numpy array shape (768,)

Bước 3: Encode CVE Descriptions
  for cve in cves:
      cve_vec = SecBERT.encode(cve['description'])
      # cve_vec: numpy array shape (768,)

Bước 4: Cosine Similarity
  def cosine_sim(a, b):
      return np.dot(a, b) / (norm(a) × norm(b))

  relevance_score = cosine_sim(profile_vec, cve_vec)
  # range: 0.0 (không liên quan) → 1.0 (rất liên quan)

Bước 5: Label Assignment
  score ≥ 0.70 → CRITICAL relevance
  score ≥ 0.50 → HIGH relevance
  score ≥ 0.30 → MEDIUM relevance
  score < 0.30 → LOW / MINIMAL

Fallback (SecBERT không available):
  → Sắp xếp CVE theo CVSS score giảm dần
  → Không có relevance score, chỉ có severity label
```

### 6.3 Thuật toán Shannon Entropy (Phát hiện Packing)

```
Mục tiêu: Phát hiện binary bị obfuscate/pack/encrypt
          (dấu hiệu của malware hoặc binary chứa nội dung ẩn)

Công thức:
  H(X) = -Σ P(xi) × log2(P(xi))

  Trong đó:
    xi = giá trị byte (0-255)
    P(xi) = tần suất xuất hiện của byte xi trong section

Ý nghĩa:
  H ≈ 0.0 : Section chứa toàn 0x00 (empty)
  H ≈ 4.0 : Text, code thông thường
  H ≈ 6.0 : Compressed data nhẹ
  H > 7.0 : Highly compressed / encrypted / packed ← ĐÁNH DẤU
  H = 8.0 : Maximum randomness (AES-encrypted data)

Ví dụ thực tế:
  Section .text  → H = 5.8 (code bình thường)
  Section .rsrc  → H = 7.8 (HIGH ENTROPY → suspicious!)
  Section .UPX0  → H = 7.9 (UPX packed binary)
```

### 6.4 Thuật toán CVSS Feature Engineering (XGBoost)

```
Input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

Parsing:
  AV = "N" → 3  (Network = most dangerous)
  AC = "L" → 1  (Low complexity)
  PR = "N" → 2  (No privileges needed)
  UI = "N" → 1  (No user interaction)
  S  = "U" → 0  (Unchanged scope)
  C  = "H" → 2  (High confidentiality impact)
  I  = "H" → 2  (High integrity impact)
  A  = "H" → 2  (High availability impact)

Feature vector: [3, 1, 2, 1, 0, 2, 2, 2]

Tại sao encoding này hiệu quả:
  CVE với AV:N PR:N UI:N → [3, ?, 2, 1, ...]
  → XGBoost học được pattern này = CRITICAL/HIGH
  CVE với AV:P PR:H UI:R → [0, ?, 0, 0, ...]
  → XGBoost học được = MEDIUM/LOW

Kết hợp với TF-IDF:
  Final features = [TF-IDF 5000-dim] concat [CVSS 8-dim]
  → 5008 total features per CVE
  → XGBoost(n_estimators=100, max_depth=6)
```

### 6.5 Thuật toán CWE Behavior Prediction (Hướng 3)

```
Input: Danh sách APIs được import trong PE binary

Rule-based Mapping:

API_TO_CWE = {
  # Process Injection
  ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"):
      → CWE-94 (Code Injection) confidence=0.95

  # Privilege Escalation
  ("AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue"):
      → CWE-269 (Improper Privilege Management) confidence=0.90

  # Credential Theft
  ("CryptAcquireContext", "CryptGetHashParam") + keylogger APIs:
      → CWE-255 (Credentials Management) confidence=0.85

  # Destructive
  ("SHFileOperation", "DeleteFile") + overwrite patterns:
      → CWE-732 (Incorrect Permission Assignment) confidence=0.80
}

Scoring:
  confidence = base_confidence × (matched_apis / total_apis_in_group)

  VD: CWE-94 group có 5 APIs, file import được 3
  → confidence = 0.95 × (3/5) = 0.57

Query NVD:
  GET /rest/json/cves/2.0?cweId=CWE-94
  → Trả về CVEs có liên quan đến code injection
  → Áp dụng relevance scoring như bình thường
```

---

## 7. Kết quả & Đánh giá

### 7.1 Độ chính xác Model

| Model | Accuracy | F1-Macro | Inference Time |
|-------|----------|----------|----------------|
| TF-IDF + Logistic Regression | 86.83% | 0.85 | <1ms |
| XGBoost + CVSS Features | 92–96% | 0.91–0.95 | <1ms |
| SecBERT Fine-tuned | **97.94%** | **0.978** | ~100ms (CPU) |
| Zero-shot NLI (loại bỏ) | 27% | 0.25 | ~500ms |
| **Ensemble (3 models)** | **~98%** | **~0.98** | ~120ms |

> **Kết luận:** Zero-shot NLI thất bại vì không hiểu domain security.
> Fine-tuning SecBERT trên dữ liệu CVE tăng accuracy từ 27% → 97.94%.

### 7.2 So sánh CPE Extraction Methods

| Phương pháp | Precision | Recall | Chi phí |
|-------------|-----------|--------|---------|
| Rule-based (KNOWN_PATTERNS) | ~99% | ~60% | O(1) |
| FAISS Semantic (MiniLM) | ~85% | ~25% | ~5ms |
| Claude AI (Haiku) | ~92% | ~95% | ~500ms + API cost |
| **3-tier Ensemble** | **~95%** | **~90%** | varies |

> **Kết luận:** Rule-based có precision cao nhưng recall thấp (chỉ biết ~200 phần mềm).
> Claude AI mở rộng coverage lên 90%+ recall nhờ hiểu ngôn ngữ tự nhiên.

### 7.3 Thời gian phân tích

| Scenario | Thời gian |
|----------|----------|
| PE file, CPE khớp rule-based, no AI | ~2–5s |
| PE file, dùng Claude AI cho CPE | ~5–8s |
| PE file, full pipeline (all AI + ML) | ~10–15s |
| Package manifest (10 dependencies) | ~15–30s |
| NVD cache hit (CVE đã tải trước) | giảm ~2–3s |

---

## 8. Demo chức năng

### 8.1 Use Case 1: Phân tích WinRAR

```
Input: Upload winrar.exe (WinRAR 6.24.0)

Kết quả:
  File: winrar.exe (2.3 MB)
  Product: WinRAR archiver 6.24.0
  Company: RarLab
  CPE: cpe:2.3:a:rarlab:winrar:6.24:*:*:*:*:*:*:*
  Extraction: known_pattern (Tier 1)

  CVE Statistics:
    Total: 47 CVEs
    CRITICAL: 2
    HIGH: 15
    MEDIUM: 25
    LOW: 5
    Avg CVSS: 6.8 | Max CVSS: 9.8

  Top CVE: CVE-2023-38831
    CVSS: 7.8 (HIGH)
    AI Severity: HIGH (confidence: 0.94)
    Relevance: CRITICAL (score: 0.82)
    Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

  AI Risk Summary:
    "WinRAR 6.24 có 47 lỗ hổng đã biết, trong đó nguy hiểm nhất
     là CVE-2023-38831 (CVSS 7.8) - lỗ hổng path traversal trong
     xử lý file archive có thể cho phép thực thi code tùy ý..."

  Recommendations:
    1. Upgrade lên WinRAR 7.10 (phiên bản mới nhất)
    2. Không mở archive từ nguồn không tin cậy
    3. Bật tính năng Windows Defender Application Guard
```

### 8.2 Use Case 2: File không rõ nguồn gốc (Hướng 3)

```
Input: Upload unknown_tool.exe (không có VersionInfo)

Kết quả:
  CPE: NOT FOUND (tất cả 3 tiers đều fail)
  → Kích hoạt CWE Behavior Prediction

  Detected APIs:
    VirtualAllocEx, WriteProcessMemory, CreateRemoteThread (Process Injection)
    RegCreateKeyEx, RegSetValueEx (Registry Manipulation)
    WSAStartup, connect, send/recv (Network)

  Predicted CWEs:
    CWE-94 (Code Injection)    confidence=0.95
    CWE-269 (Privilege Escal.) confidence=0.72
    CWE-319 (Cleartext Trans.) confidence=0.68

  CVEs found via CWE: 45 CVEs

  Claude Static Analysis:
    overall_risk: CRITICAL
    behavioral_summary: "Binary này có khả năng thực hiện process
      injection vào các tiến trình khác để thực thi code, đồng thời
      thiết lập persistence qua registry..."
    attack_techniques:
      T1055 - Process Injection
      T1547 - Boot/Logon Autostart Execution
      T1071 - Application Layer Protocol
```

### 8.3 Use Case 3: Phân tích requirements.txt (Python Project)

```
Input: Upload requirements.txt
django==4.2.0
pillow==9.5.0
cryptography==38.0.0

Kết quả:
  Packages analyzed: 3
  Total CVEs: 15

  cryptography 38.0.0: CRITICAL (8 CVEs)
    → CVE-2023-49083 CVSS 9.1 — NULL pointer dereference
    → Upgrade to: cryptography>=41.0.6

  pillow 9.5.0: HIGH (5 CVEs)
    → CVE-2023-44271 CVSS 7.5 — Uncontrolled resource consumption
    → Upgrade to: Pillow>=10.0.1

  django 4.2.0: MEDIUM (2 CVEs)
    → CVE-2023-36053 CVSS 5.3 — ReDoS in EmailValidator
    → Upgrade to: django>=4.2.3
```

---

## Tóm tắt kỹ thuật (1 slide)

```
┌─────────────────────────────────────────────────────────────────────┐
│            TECHNOLOGY SUMMARY                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  INPUT           PROCESSING                      OUTPUT            │
│  ─────────       ──────────────────────────       ──────────        │
│  .exe/.dll  →    PE Static Analysis         →    CVE List           │
│  .sys       →    (pefile, entropy, APIs)    →    + CVSS             │
│                                             →    + AI Severity      │
│  reqts.txt  →    Package Parser             →    + Relevance        │
│  pkg.json   →    (7 ecosystems)             →    + Risk Summary     │
│                                                                     │
│  KEY ALGORITHMS:                                                    │
│  ─────────────────────────────────────────────────────────────────  │
│  CPE Extraction: Rule-based → FAISS (MiniLM 384d) → Claude Haiku   │
│  Severity: Ensemble(SecBERT 97.9% + XGBoost 92% + TF-IDF 86%)     │
│  Relevance: SecBERT Cosine Similarity (profile vs CVE desc)        │
│  Fallback: CWE Behavior Prediction (API → CWE → NVD query)         │
│  Narrative: Claude Sonnet (risk summary + recommendations)         │
│                                                                     │
│  STACK: Python · Flask · PyTorch · HuggingFace · FAISS · XGBoost   │
│         Anthropic Claude API · NVD REST API v2                     │
└─────────────────────────────────────────────────────────────────────┘
```
