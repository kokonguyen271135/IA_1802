# System Design — Software Vulnerability Assessment Tool

> **Luận văn:** Nghiên cứu và Phát triển Công cụ Đánh giá Lỗ hổng Phần mềm
> kết hợp AI và Cơ sở Dữ liệu CVE
>
> **Stack:** Python 3.11 · Flask · Claude AI (Anthropic) · SecBERT · XGBoost · NVD API v2

---

## 1. Kiến trúc tổng thể (System Architecture)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PRESENTATION LAYER                                 │
│                                                                              │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │                    Web Browser (Client)                            │    │
│   │   frontend/templates/index.html                                    │    │
│   │   frontend/static/js/main.js                                       │    │
│   │   frontend/static/css/style.css                                    │    │
│   └─────────────────────────────┬──────────────────────────────────────┘    │
└─────────────────────────────────┼────────────────────────────────────────────┘
                                  │ HTTP/REST (JSON)
┌─────────────────────────────────┼────────────────────────────────────────────┐
│                           API GATEWAY LAYER                                  │
│                                                                              │
│   ┌─────────────────────────────▼──────────────────────────────────────┐    │
│   │                  Flask Web Server                                   │    │
│   │                  backend/app.py                                     │    │
│   │                                                                     │    │
│   │  POST /api/analyze          POST /api/search                        │    │
│   │  POST /api/analyze-packages POST /api/query-cpe                    │    │
│   │  POST /api/export-all       GET  /api/status                       │    │
│   └─────────────────────────────┬──────────────────────────────────────┘    │
└─────────────────────────────────┼────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────┼────────────────────────────────────────────┐
│                           CORE PROCESSING LAYER                              │
│                                                                              │
│  ┌────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐ │
│  │  File Analysis     │  │  CPE Extraction      │  │  CVE Fetching        │ │
│  │                    │  │                      │  │                      │ │
│  │ PEStaticAnalyzer   │  │ CPEExtractor         │  │ NVDAPIv2             │ │
│  │ PackageAnalyzer    │  │ CPESemanticMatcher   │  │ (cache + rate limit) │ │
│  │                    │  │ AI CPE Matching      │  │                      │ │
│  └────────────────────┘  └──────────────────────┘  └──────────────────────┘ │
│                                                                              │
│  ┌────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐ │
│  │  Severity Pipeline │  │  Relevance Scorer    │  │  Risk Narrative      │ │
│  │                    │  │                      │  │                      │ │
│  │ SecBERT (fine-tune)│  │ SecBERT Cosine Sim   │  │ Claude Sonnet        │ │
│  │ XGBoost + CVSS     │  │ (profile vs CVE desc)│  │ (claude-sonnet-4-6)  │ │
│  │ TF-IDF + LogReg    │  │                      │  │                      │ │
│  │ Ensemble Voting    │  │                      │  │                      │ │
│  └────────────────────┘  └──────────────────────┘  └──────────────────────┘ │
│                                                                              │
│  ┌────────────────────┐  ┌──────────────────────┐                           │
│  │  CWE Predictor     │  │  CWE Predictor       │                           │
│  │  (Hướng 3)         │  │  (Luận văn hướng 3)  │                           │
│  │                    │  │                      │                           │
│  │ API behavior →     │  │  SecBERT fine-tune   │                           │
│  │ CWE mapping        │  │  CWE classification  │                           │
│  └────────────────────┘  └──────────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────┼────────────────────────────────────────────┐
│                           DATA & MODEL LAYER                                 │
│                                                                              │
│  ┌──────────────┐  ┌─────────────────┐  ┌────────────────┐  ┌────────────┐  │
│  │  NVD Cache   │  │  FAISS Index    │  │  ML Models     │  │  Training  │  │
│  │  (JSON files)│  │  cpe_index.faiss│  │  severity_clf  │  │  Data      │  │
│  │  data/cache/ │  │  cpe_meta.pkl   │  │  (.pkl)        │  │  CSV files │  │
│  └──────────────┘  └─────────────────┘  └────────────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────┼────────────────────────────────────────────┐
│                           EXTERNAL SERVICES                                  │
│                                                                              │
│  ┌──────────────────────┐       ┌───────────────────────────────────────┐   │
│  │  NVD API v2           │       │  Anthropic Claude API                  │   │
│  │  nvd.nist.gov        │       │  api.anthropic.com                    │   │
│  │                      │       │                                       │   │
│  │  Rate: 50 req/30s    │       │  claude-haiku  → CPE matching         │   │
│  │  (with API key)      │       │  claude-sonnet → risk analysis        │   │
│  └──────────────────────┘       └───────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Design

### 2.1 File Analysis Layer

#### `PEStaticAnalyzer` — `backend/static_analyzer.py`

| Trách nhiệm | Chi tiết |
|-------------|----------|
| PE Parsing | Dùng `pefile` library để đọc PE headers, sections, imports |
| Import Analysis | Phân loại APIs vào 9 nhóm nguy hiểm (Process Injection, Privilege Escalation, v.v.) |
| Component Detection | Tìm embedded libraries qua regex patterns (OpenSSL, libcurl, Python...) |
| Entropy Calculation | Shannon entropy từng section — phát hiện packing/encryption |
| String Extraction | URLs, IP addresses, suspicious commands từ binary strings |
| Risk Scoring | Tổng hợp Risk Score 0–100 từ API categories + entropy + strings |

**Output structure:**
```json
{
  "file_info": { "name", "size", "hash_md5", "hash_sha256", "compile_time" },
  "product_info": { "product_name", "company_name", "file_version", "product_version" },
  "sections": [ { "name", "entropy", "high_entropy", "size" } ],
  "imports": {
    "by_category": { "Process Injection": [...], "Network": [...] },
    "suspicious": [ { "function", "dll", "risk", "category" } ]
  },
  "components": [ { "name", "version", "cpe_vendor", "cpe_product" } ],
  "strings": { "URLs": [...], "IP Addresses": [...], "Suspicious Commands": [...] },
  "risk": { "score": 75, "level": "HIGH", "factors": [...] }
}
```

#### `PackageAnalyzer` — `backend/package_analyzer.py`

| Ecosystem | File |
|-----------|------|
| Python | `requirements.txt`, `Pipfile`, `setup.cfg` |
| Node.js | `package.json`, `yarn.lock` |
| Java | `pom.xml` (Maven), `build.gradle` (Gradle) |
| PHP | `composer.json` |
| Ruby | `Gemfile` |
| Go | `go.mod` |
| Rust | `Cargo.toml` |

---

### 2.2 CPE Extraction Layer

#### `CPEExtractor` — `backend/cpe_extractor.py`

**3-tier extraction pipeline:**

```
Tier 1: KNOWN_PATTERNS (dict lookup)
  ~200 known software patterns
  ProductName/CompanyName → (vendor, product)
  Độ chính xác: rất cao, không tốn tài nguyên

Tier 2: FAISS Semantic Search (backend/cpe_semantic_matcher.py)
  models/cpe_index.faiss — vector index của ~800,000 CPE entries
  models/cpe_meta.pkl   — metadata mapping
  Encode query → MiniLM-L6-v2 → 384-dim vector
  cosine similarity search → top-K candidates

Tier 3: Claude AI (claude-haiku-4-5)
  Prompt engineering với software metadata
  Xử lý edge cases: tên viết tắt, alias, tên quốc tế
  Response: { vendor, product, confidence, reasoning }
```

---

### 2.3 NVD API Layer

#### `NVDAPIv2` — `backend/nvd_api_v2.py`

| Feature | Chi tiết |
|---------|----------|
| API Version | NVD REST API v2.0 |
| Search Mode | `cpeName` — tìm CVE theo CPE string đầy đủ |
| Rate Limiting | 50 req/30s (với key), 5 req/30s (không key) |
| Pagination | Tự động xử lý nhiều trang (max 2000/page) |
| Caching | JSON file per CVE → `data/cache/nvd/` |
| Response Fields | CVE ID, CVSS v3/v2, severity, description, CWEs, references |

**CVE object format:**
```json
{
  "cve_id": "CVE-2024-12345",
  "cvss_score": 9.8,
  "severity": "CRITICAL",
  "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "description": "...",
  "weaknesses": ["CWE-787"],
  "references": [...],
  "published": "2024-01-01",
  "lastModified": "2024-01-15"
}
```

---

### 2.4 AI/ML Enrichment Layer

#### Severity Pipeline — `backend/ai/severity_pipeline.py`

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENSEMBLE ARCHITECTURE                        │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Model 1: SecBERT Fine-tuned                             │  │
│  │  File: backend/bert_severity_classifier.py               │  │
│  │  Base: jackaduma/SecBERT (domain-specific BERT)          │  │
│  │  Training: CVE descriptions → 4-class classification     │  │
│  │  Accuracy: 97.94%    Weight: 1.00                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Model 2: XGBoost + CVSS Features                        │  │
│  │  File: backend/xgboost_severity_classifier.py            │  │
│  │  Features: CVSS vector parsed (AV, AC, Au, C, I, A)     │  │
│  │           + TF-IDF text features from description        │  │
│  │  Accuracy: 92–96%    Weight: 0.85                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Model 3: TF-IDF + Logistic Regression                   │  │
│  │  File: backend/severity_classifier.py                    │  │
│  │  Features: TF-IDF vectors từ CVE description             │  │
│  │  Saved model: models/severity_clf.pkl                    │  │
│  │  Accuracy: 86.83%    Weight: 0.70                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Weighted Ensemble:                                             │
│    score[label] = Σ (model_weight × model_prob[label])         │
│    predicted = argmax(score)                                    │
│    confidence = max_score / Σ scores                           │
└─────────────────────────────────────────────────────────────────┘
```

#### Relevance Scorer — `backend/ai/relevance_scorer.py`

**Ý tưởng:**
Không phải mọi CVE của một phần mềm đều nguy hiểm như nhau với *file cụ thể*
đang phân tích. Relevance scorer đánh giá CVE nào thực sự liên quan đến hành
vi của file.

**Cách hoạt động:**
```
1. Build Software Profile Text:
   "This PE binary uses Process Injection APIs (VirtualAllocEx,
    WriteProcessMemory, CreateRemoteThread). It communicates over
    network (WSAStartup, connect, send). Contains OpenSSL 1.1.1..."

2. Encode profile → SecBERT vector (768-dim)

3. For each CVE:
   Encode description → SecBERT vector
   relevance_score = cosine_similarity(profile_vec, cve_vec)

4. Label mapping:
   score ≥ 0.7 → CRITICAL relevance
   score ≥ 0.5 → HIGH relevance
   score ≥ 0.3 → MEDIUM relevance
   score < 0.3 → LOW relevance / MINIMAL
```

#### SecBERT CVE Scorer — `backend/secbert_cve_scorer.py`

| Field | Value |
|-------|-------|
| Base Model | `jackaduma/SecBERT` |
| Task | Sentence embedding (mean pooling) |
| Vector Dim | 768 |
| Similarity Metric | Cosine similarity |
| Usage | Build profile → encode CVEs → rank by similarity |

---

### 2.5 Claude AI Integration — `backend/ai_analyzer.py`

#### Claude Haiku — CPE Matching
```
Model: claude-haiku-4-5-20251001
Use case: Fast, cheap lookup — xác định vendor/product NVD
Input: ProductName, CompanyName, Filename, Version
Output: { vendor, product, confidence, reasoning }
Max tokens: 256
```

#### Claude Sonnet — Risk Analysis
```
Model: claude-sonnet-4-6
Use case: Deep security analysis — viết risk narrative
Input: top-10 CVEs (by CVSS) + severity stats + software info
Output: {
  overall_risk, risk_summary,
  top_threats, recommendations, key_attack_vectors
}
Max tokens: 600

Static Behavior Analysis:
Input: PE static analysis findings
Output: {
  behavioral_summary, vulnerability_types,
  attack_techniques (MITRE ATT&CK), cwe_suggestions,
  recommendations
}
Max tokens: 700
```

---

### 2.6 CWE Predictor — `backend/cwe_predictor.py` (Hướng 3)

**Vấn đề giải quyết:**
Khi không xác định được CPE (không biết phần mềm là gì), không thể tra NVD
theo CPE. Hướng 3 dùng *hành vi* của file để tra CVE theo CWE.

**Rule-based API → CWE mapping:**

| API Group | CWE |
|-----------|-----|
| VirtualAllocEx, WriteProcessMemory | CWE-94 (Code Injection) |
| ShellExecute, WinExec, CreateProcess | CWE-78 (OS Command Injection) |
| High entropy sections | CWE-506 (Embedded Malicious Code) |
| RegCreateKey, RegSetValue | CWE-269 (Improper Privilege Management) |
| WSAStartup, connect, send/recv | CWE-319 (Cleartext Transmission) |
| GetAsyncKeyState, SetWindowsHookEx | CWE-200 (Info Exposure) |

**Flow:**
```
PE APIs → Rule Matching → CWE IDs (with confidence)
→ NVD Query: ?cweId=CWE-XX → CVE list
→ AI/ML Enrichment → Return top CVEs
```

---

## 3. Data Flow Diagram

```
                    ┌──────────────┐
                    │   Browser    │
                    └──────┬───────┘
                           │ multipart/form-data (file upload)
                           │ OR application/json (search)
                           ▼
                    ┌──────────────┐
                    │  Flask App   │◄──── uploads/ (temp storage)
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌──────────────┐ ┌──────────────┐
    │  PE Analyzer│ │  Package     │ │  Search by   │
    │             │ │  Analyzer    │ │  Name+Ver    │
    └──────┬──────┘ └──────┬───────┘ └──────┬───────┘
           │               │                │
           └───────────────┴────────────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  CPE Extractor   │
                  │  (3-tier)        │
                  └────────┬─────────┘
                           │
               ┌───────────┴────────────┐
          CPE Found               CPE not found
               │                        │
               ▼                        ▼
    ┌─────────────────┐     ┌──────────────────────┐
    │  NVD API v2     │     │  CWE Predictor       │
    │  by cpeName     │     │  (Hướng 3)           │
    │  ↓              │     │  API → CWE → NVD     │
    │  data/cache/nvd/│     │                      │
    └────────┬────────┘     └──────────┬───────────┘
             │                         │
             └────────────┬────────────┘
                          │ CVE list
                          ▼
             ┌────────────────────────┐
             │  Severity Pipeline     │
             │  BERT + XGB + TF-IDF   │
             │  → ai_severity per CVE │
             └────────────┬───────────┘
                          │
                          ▼
             ┌────────────────────────┐
             │  Relevance Scorer      │
             │  SecBERT cosine sim    │
             │  → relevance per CVE  │
             └────────────┬───────────┘
                          │
                          ▼
             ┌────────────────────────┐
             │  Claude AI Narrative   │
             │  Risk summary +        │
             │  recommendations       │
             └────────────┬───────────┘
                          │
                          ▼
             ┌────────────────────────┐
             │  JSON Response          │
             │  → Browser renders     │
             └────────────────────────┘
```

---

## 4. Directory Structure

```
IA_1802/
│
├── backend/                    # Core application logic
│   ├── app.py                  # Flask server, API endpoints
│   ├── static_analyzer.py      # PE binary analysis
│   ├── package_analyzer.py     # Package manifest parsing
│   ├── cpe_extractor.py        # CPE identification (rule-based)
│   ├── cpe_semantic_matcher.py # CPE FAISS semantic search
│   ├── nvd_api_v2.py           # NVD API v2 client + cache
│   ├── ai_analyzer.py          # Claude AI integration
│   ├── cwe_predictor.py        # CWE-based CVE lookup (Hướng 3)
│   ├── contextual_scorer.py    # (legacy) contextual scoring
│   │
│   ├── severity_classifier.py      # TF-IDF + Logistic Regression
│   ├── bert_severity_classifier.py # SecBERT fine-tuned classifier
│   ├── xgboost_severity_classifier.py # XGBoost + CVSS features
│   ├── secbert_cve_scorer.py       # SecBERT cosine similarity scoring
│   ├── zero_shot_severity.py       # (legacy) Zero-shot NLI
│   │
│   └── ai/                     # Unified AI pipeline
│       ├── __init__.py
│       ├── severity_pipeline.py   # Ensemble severity model
│       └── relevance_scorer.py    # CVE relevance scoring
│
├── frontend/                   # Web interface
│   ├── templates/index.html
│   └── static/
│       ├── css/style.css
│       └── js/main.js
│
├── models/                     # Trained model files
│   ├── cpe_index.faiss         # FAISS index (~800K CPE vectors)
│   ├── cpe_meta.pkl            # CPE metadata
│   ├── severity_clf.pkl        # TF-IDF + LogReg model
│   └── severity_report.txt     # Model evaluation report
│
├── data/
│   ├── cache/nvd/              # Cached CVE JSON files
│   └── training/               # Training datasets
│       └── cve_severity_train.csv
│
├── untils/                     # Utility scripts (offline)
│   ├── build_cpe_index.py      # Build FAISS CPE index
│   ├── train_severity_model.py # Train TF-IDF classifier
│   ├── train_xgboost_severity.py
│   ├── finetune_bert_severity.py
│   ├── run_training_pipeline.py
│   ├── build_training_data.py
│   ├── enrich_with_nvd.py
│   ├── download_dataset.py
│   ├── download_models.py
│   ├── preprocess_data.py
│   └── evaluate_models.py
│
├── tests/                      # Test suite
│   ├── test_api.py
│   ├── test_complete.py
│   ├── test_cpe_extractor.py
│   ├── run_all_test.py
│   └── demo.py
│
├── uploads/                    # Temporary file uploads
├── requirements.txt
├── WORKFLOW.md                 # This workflow document
└── SYSTEM_DESIGN.md            # This design document
```

---

## 5. Technology Stack

| Layer | Technology | Lý do chọn |
|-------|-----------|------------|
| Web Framework | Flask 3.x + Flask-CORS | Lightweight, phù hợp prototype/thesis |
| PE Parsing | `pefile` | Standard library cho Windows PE format |
| AI API | Anthropic Claude (Haiku + Sonnet) | State-of-the-art reasoning, CPE lookup + risk narrative |
| NLP/Embeddings | `sentence-transformers` + SecBERT | Domain-specific (security) text encoding |
| Vector Search | FAISS (faiss-cpu) | Billion-scale approximate nearest neighbor search |
| Gradient Boosting | XGBoost | High accuracy, interpretable CVSS feature engineering |
| Classical ML | scikit-learn (LogReg + TF-IDF) | Fast baseline, good F1 trên tabular data |
| Deep Learning | PyTorch + HuggingFace Transformers | Fine-tune BERT trên domain-specific data |
| Fuzzy Matching | `rapidfuzz` + `fuzzywuzzy` | Package name normalization |
| Reporting | `reportlab` | PDF export |
| Data Processing | pandas + numpy | Dataset manipulation |

---

## 6. Model Performance Summary

| Model | Task | Accuracy | Notes |
|-------|------|----------|-------|
| SecBERT fine-tuned | Severity Classification | **97.94%** | Domain-specific BERT |
| XGBoost + CVSS | Severity Classification | 92–96% | Tabular CVSS features |
| TF-IDF + LogReg | Severity Classification | 86.83% | Fast statistical baseline |
| Zero-shot NLI | Severity Classification | 27% | Không phù hợp, đã loại bỏ |
| SecBERT | CVE Relevance Scoring | — | Cosine similarity, no label |
| FAISS Semantic | CPE Matching | — | ~800K CPE search |

---

## 7. Security Considerations

| Vấn đề | Giải pháp |
|--------|-----------|
| File upload safety | `werkzeug.secure_filename`, giới hạn extension |
| API key exposure | `.env` file, `python-dotenv`, không commit key |
| NVD API rate limit | Per-key rate limiting, local cache |
| Large file handling | Stream processing, giới hạn file size |
| Malware sample handling | Isolated analysis, không execute binary |

---

## 8. Scalability & Future Improvements

```
Hiện tại (Thesis / Prototype):
├── Single-process Flask (dev server)
├── File-based cache (JSON)
├── Synchronous API calls
└── In-process ML models

Production scaling (nếu cần):
├── Gunicorn + NGINX (multi-worker)
├── Redis cache thay file cache
├── Celery async tasks cho phân tích nặng
├── PostgreSQL lưu kết quả scan
├── Docker container per analysis (sandboxing)
└── Model serving với TorchServe / TF Serving
```

---

## 9. Environment Variables

| Variable | Required | Default | Mô tả |
|----------|----------|---------|-------|
| `ANTHROPIC_API_KEY` | Optional | — | Claude AI features |
| `NVD_API_KEY` | Optional | hardcoded | Tăng rate limit NVD |
| `FLASK_ENV` | Optional | production | Flask mode |
| `FLASK_PORT` | Optional | 5000 | Server port |

---

## 10. Luồng Training (Offline)

```
untils/ scripts — chạy một lần để build models

1. download_dataset.py
   └── Tải CVE dataset từ Kaggle / NVD

2. preprocess_data.py
   └── Clean, normalize CVE descriptions

3. build_training_data.py + enrich_with_nvd.py
   └── Enrich với CVSS scores từ NVD API

4. train_severity_model.py
   └── Train TF-IDF + LogReg → models/severity_clf.pkl

5. train_xgboost_severity.py
   └── Train XGBoost + CVSS features

6. finetune_bert_severity.py
   └── Fine-tune SecBERT trên CVE severity data

7. build_cpe_index.py
   └── Download NVD CPE dictionary
   └── Encode ~800K CPE → vectors (sentence-bert)
   └── Build FAISS index → models/cpe_index.faiss

8. evaluate_models.py
   └── So sánh accuracy, F1 của tất cả models
   └── → models/severity_report.txt
```
