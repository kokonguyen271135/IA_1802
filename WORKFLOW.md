# Workflow — Software Vulnerability Assessment Tool

> **Luận văn:** Nghiên cứu và Phát triển Công cụ Đánh giá Lỗ hổng Phần mềm
> kết hợp AI và Cơ sở Dữ liệu CVE

---

## 1. Tổng quan luồng xử lý (High-level Flow)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER INPUT                                      │
│                                                                          │
│   ┌──────────────────┐        ┌──────────────────┐                      │
│   │  PE Binary File  │   OR   │  Package Manifest│                      │
│   │ (.exe/.dll/.sys) │        │ (requirements.txt│                      │
│   └────────┬─────────┘        │  package.json...)│                      │
│            │                  └────────┬─────────┘                      │
└────────────┼───────────────────────────┼────────────────────────────────┘
             │                           │
             ▼                           ▼
    ┌─────────────────┐        ┌──────────────────┐
    │ Static Analyzer │        │ Package Analyzer  │
    │  (PE Binary)    │        │  (Manifest File) │
    └────────┬────────┘        └────────┬─────────┘
             │                          │
             ▼                          ▼
    ┌──────────────────────────────────────────────┐
    │             CPE Extraction Layer             │
    │  Rule-based → FAISS Semantic → Claude AI     │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────┐
    │              NVD API v2 Query                │
    │    Search CVEs by CPE / CWE / Keyword        │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────┐
    │             AI / ML Enrichment               │
    │  ┌─────────────┐  ┌──────────────────────┐  │
    │  │  Severity   │  │   Relevance Scoring  │  │
    │  │  Pipeline   │  │   (SecBERT Cosine)   │  │
    │  │(BERT/XGB/TF)│  └──────────────────────┘  │
    │  └─────────────┘                             │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────┐
    │          Claude AI Risk Narrative            │
    │  Overall Risk / Threats / Recommendations    │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────┐
    │              Final Report                    │
    │  CVE List + Severity + Relevance + Summary   │
    └──────────────────────────────────────────────┘
```

---

## 2. Workflow chi tiết: Phân tích PE Binary

```
INPUT: file.exe / file.dll / file.sys
          │
          ▼
┌─────────────────────────────────────────────┐
│  BƯỚC 1 — PE Static Analysis                │
│  (backend/static_analyzer.py)               │
│                                             │
│  • Đọc PE headers, sections                 │
│  • Trích xuất Import Table (DLL + API)      │
│  • Phát hiện suspicious APIs theo nhóm:     │
│    - Process Injection                      │
│    - Privilege Escalation                   │
│    - Network Communication                  │
│    - Keylogging / Credential Theft          │
│    - Anti-Analysis / Evasion                │
│    - File System Manipulation               │
│    - Registry Manipulation                  │
│  • Đọc VersionInfo: ProductName, Company,   │
│    FileVersion, ProductVersion              │
│  • Phát hiện embedded components            │
│    (OpenSSL, libcurl, Python, SQLite...)     │
│  • Tính Shannon Entropy mỗi section         │
│  • Tính Risk Score (0–100)                  │
│  • Trích xuất strings: URLs, IPs, Commands  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  BƯỚC 2 — CPE Extraction                    │
│  (backend/cpe_extractor.py)                 │
│                                             │
│  Pipeline (theo thứ tự ưu tiên):            │
│                                             │
│  2a. KNOWN_PATTERNS matching                │
│      ProductName / CompanyName              │
│      → vendor + product (lookup table)      │
│      Ví dụ: "WinRAR" → rarlab/winrar        │
│                   │                         │
│                   │ Không khớp              │
│                   ▼                         │
│  2b. FAISS Semantic Search                  │
│      (backend/cpe_semantic_matcher.py)      │
│      → Encode text → vector                 │
│      → cosine similarity trên CPE index     │
│                   │                         │
│                   │ Không chắc chắn         │
│                   ▼                         │
│  2c. Claude AI (claude-haiku)               │
│      (backend/ai_analyzer.py)               │
│      → Prompt với metadata phần mềm         │
│      → Trả về vendor/product JSON           │
│                                             │
│  Kết quả: cpe:2.3:a:vendor:product:version  │
└──────────────────────┬──────────────────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
   CPE xác định được          Không xác định được CPE
          │                         │
          ▼                         ▼
┌──────────────────┐    ┌───────────────────────────┐
│  BƯỚC 3A         │    │  BƯỚC 3B — Hướng 3        │
│  NVD CPE Query   │    │  CWE Behavior Prediction  │
│  (nvd_api_v2.py) │    │  (cwe_predictor.py)       │
│                  │    │                           │
│  Query NVD API   │    │  API behavior → CWE IDs:  │
│  by cpe_name     │    │  VirtualAllocEx →         │
│  → list of CVEs  │    │    CWE-94 (Code Injection)│
│                  │    │  ShellExecute →            │
│                  │    │    CWE-78 (OS Cmd Inject) │
│                  │    │                           │
│                  │    │  Query NVD by cweId       │
│                  │    │  → list of CVEs           │
└────────┬─────────┘    └──────────────┬────────────┘
         │                             │
         └──────────────┬──────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────┐
│  BƯỚC 4 — AI/ML Severity Enrichment         │
│  (backend/ai/severity_pipeline.py)          │
│                                             │
│  Với mỗi CVE:                               │
│                                             │
│  Model 1: SecBERT fine-tuned (97.94% acc)   │
│    → predict severity từ description text   │
│                                             │
│  Model 2: XGBoost + CVSS features (92-96%)  │
│    → features: CVSS vector, AV, AC, Au      │
│                                             │
│  Model 3: TF-IDF + Logistic Reg. (86.83%)   │
│    → statistical baseline                   │
│                                             │
│  Ensemble voting (weighted):                │
│    BERT×1.00 + XGB×0.85 + TFIDF×0.70       │
│  → predicted_severity: CRITICAL/HIGH/MED/LOW│
│  → confidence score (0–1)                   │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  BƯỚC 5 — CVE Relevance Scoring             │
│  (backend/ai/relevance_scorer.py)           │
│                                             │
│  Xây dựng Software Profile Text từ:         │
│    - Imported API categories                │
│    - Detected components                    │
│    - Suspicious behaviors                   │
│    - Risk factors                           │
│                                             │
│  SecBERT Semantic Similarity:               │
│    cosine_sim(profile_vec, cve_desc_vec)    │
│  → relevance score 0.0–1.0                  │
│  → relevance label: CRITICAL/HIGH/MED/LOW  │
│                                             │
│  Fallback (no SecBERT): sort by CVSS DESC   │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  BƯỚC 6 — Claude AI Risk Narrative          │
│  (backend/ai_analyzer.py)                   │
│                                             │
│  Input: top-10 CVEs (by CVSS) + stats       │
│  Model: claude-sonnet-4-6                   │
│                                             │
│  Output:                                    │
│  • overall_risk: CRITICAL/HIGH/MED/LOW      │
│  • risk_summary: 2–3 câu mô tả rủi ro      │
│  • top_threats: [3 mối đe dọa chính]        │
│  • recommendations: [3 biện pháp xử lý]    │
│  • key_attack_vectors: [Network, Local...]  │
│                                             │
│  (Static: ai_analyze_static_behavior)       │
│  • behavioral_summary, attack_techniques    │
│  • MITRE ATT&CK mapping, CWE suggestions   │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
               ┌───────────────┐
               │  FINAL OUTPUT │
               │  JSON Response│
               └───────────────┘
```

---

## 3. Workflow chi tiết: Phân tích Package Manifest

```
INPUT: requirements.txt / package.json / pom.xml / go.mod / ...
          │
          ▼
┌─────────────────────────────────────────────┐
│  Package Analyzer                           │
│  (backend/package_analyzer.py)              │
│                                             │
│  Hỗ trợ: Python, Node.js, Maven, Gradle,   │
│           PHP Composer, Ruby Gems, Go, Rust │
│                                             │
│  Parse → list of {name, version, ecosystem} │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  CPE Mapping cho mỗi package                │
│  (cpe_extractor.py → lookup table)          │
│                                             │
│  Ví dụ:                                     │
│  requests 2.28.0 → cpe:2.3:a:python-       │
│                      requests:requests:...  │
│  django 4.2.0    → cpe:2.3:a:django-       │
│                      project:django:...     │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
  [Song song/Parallel] NVD Query cho mỗi package
                       │
                       ▼
  AI/ML Enrichment (Severity + Relevance)
                       │
                       ▼
  Tổng hợp: danh sách packages + CVEs + risk
                       │
                       ▼
               ┌───────────────┐
               │  FINAL OUTPUT │
               └───────────────┘
```

---

## 4. Workflow: Search by Software Name

```
INPUT: software_name + version (e.g., "winrar 6.24")
          │
          ▼
    CPE Extraction (KNOWN_PATTERNS → FAISS → Claude AI)
          │
          ▼
    NVD API Query by CPE
          │
          ▼
    AI/ML Enrichment
          │
          ▼
    Claude Risk Narrative
          │
          ▼
    OUTPUT: CVE report
```

---

## 5. State Machine của CPE Extraction

```
                    ┌─────────────────────┐
                    │  START: Metadata    │
                    │  (name, company,    │
                    │   filename, ver)    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐    MATCH
                    │  KNOWN_PATTERNS     │──────────► CPE Found
                    │  (lookup table)     │           (extraction_method:
                    └──────────┬──────────┘            'known_pattern')
                               │ NO MATCH
                               ▼
                    ┌─────────────────────┐    HIGH
                    │  FAISS Semantic     │  SIMILARITY
                    │  Search             │──────────► CPE Found
                    │  (sentence-bert +   │           (extraction_method:
                    │   faiss-cpu index)  │            'semantic_match')
                    └──────────┬──────────┘
                               │ LOW SIMILARITY
                               ▼
                    ┌─────────────────────┐   SUCCESS
                    │  Claude AI          │──────────► CPE Found
                    │  (claude-haiku)     │           (extraction_method:
                    │  JSON response      │            'ai_enhanced')
                    └──────────┬──────────┘
                               │ FAILURE / LOW CONFIDENCE
                               ▼
                    ┌─────────────────────┐
                    │  Generic Fallback   │──────────► Hướng 3:
                    │  (filename-based)   │            CWE Prediction
                    └─────────────────────┘
```

---

## 6. Ensemble Severity Prediction Flow

```
CVE Description + CVSS Vector String
          │
          ├──────────────────┬──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
   │  SecBERT    │   │  XGBoost    │   │  TF-IDF     │
   │  (fine-tune │   │  + CVSS     │   │  + LogReg   │
   │  97.94% acc)│   │  features   │   │  86.83% acc │
   │             │   │  92-96% acc │   │             │
   │  weight=1.0 │   │  weight=0.85│   │  weight=0.70│
   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │  Weighted Voting    │
                  │  score[sev] = Σ     │
                  │  (weight × P[sev])  │
                  └──────────┬──────────┘
                             │
                             ▼
              ┌──────────────────────────┐
              │  predicted_severity      │
              │  CRITICAL / HIGH /       │
              │  MEDIUM / LOW            │
              │  + confidence (0–1)      │
              └──────────────────────────┘
```

---

## 7. API Endpoints Flow

```
POST /api/analyze
     │
     ├── Detect file type
     │     ├── PE Binary (.exe/.dll/.sys) → PEStaticAnalyzer
     │     └── Manifest file              → PackageAnalyzer
     │
     ├── CPE Extraction
     ├── NVD Query
     ├── AI/ML Enrichment (Severity + Relevance)
     └── Claude Risk Narrative
         └── Response JSON

POST /api/search
     │
     ├── software_name + version
     ├── CPE Extraction
     ├── NVD Query
     └── Response JSON

POST /api/query-cpe
     │
     ├── cpe_string (raw)
     ├── NVD Query
     └── Response JSON

POST /api/export-all
     │
     └── Export ALL CVEs for CPE (no pagination limit)

GET /api/status
     └── System status: AI/ML model availability
```

---

## 8. Error Handling & Fallback Strategy

```
                     ┌──────────────────┐
                     │  Graceful        │
                     │  Degradation     │
                     └──────────────────┘

AI Feature Unavailable:
  ANTHROPIC_API_KEY not set / anthropic not installed
    → Skip ai_match_cpe, ai_analyze_severity
    → Trả về CVEs không có AI narrative

SecBERT Unavailable:
  torch/transformers not installed / model not cached
    → Skip semantic relevance scoring
    → Sort CVEs by CVSS score thay thế

BERT Severity Model Unavailable:
  → Thử XGBoost → Thử TF-IDF
  → Nếu tất cả unavailable → dùng NVD CVSS severity

NVD API Error / Rate Limit:
  → Trả về cache nếu có
  → Log error, tiếp tục xử lý

CPE Extraction Failure:
  → Hướng 3: CWE-based search
  → Nếu cả 2 fail → trả về static analysis only
```
