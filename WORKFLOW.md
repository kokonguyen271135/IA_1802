# Workflow Dự Án: Software Vulnerability Assessment Tool

## Tổng Quan

Đây là ứng dụng web full-stack kết hợp AI và Machine Learning để đánh giá lỗ hổng phần mềm. Hệ thống tích hợp:
- Phân tích file PE binary (Windows executables)
- Phân tích file khai báo package (requirements.txt, package.json, v.v.)
- Tra cứu CVE từ NVD (National Vulnerability Database)
- Phân loại mức độ nghiêm trọng bằng ensemble ML (TF-IDF, BERT, XGBoost)
- CPE matching bằng Claude AI + FAISS semantic search

---

## 1. WORKFLOW KHỞI CHẠY HỆ THỐNG

```
[Khởi động]
     │
     ▼
python backend/app.py
     │
     ├─ Khởi tạo Flask app (port 5000)
     ├─ Load SeverityPipeline (TF-IDF + BERT + XGBoost models)
     ├─ Load SecBERT semantic scorer
     ├─ Load FAISS CPE index (models/cpe_index.faiss)
     ├─ Kết nối NVD API (key từ env var NVD_API_KEY)
     ├─ Kết nối Claude API (key từ env var ANTHROPIC_API_KEY)
     └─ Sẵn sàng nhận request tại http://localhost:5000
```

**Yêu cầu môi trường:**
```bash
export ANTHROPIC_API_KEY="your-key"   # Claude AI CPE matching
export NVD_API_KEY="your-key"          # NVD API (50 req/30s thay vì 5 req/30s)
pip install -r requirements.txt
python backend/app.py
```

---

## 2. WORKFLOW PHÂN TÍCH FILE PE BINARY

```
User upload file .exe/.dll/.sys/.ocx/.drv
     │
     ▼
POST /api/analyze
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 1: STATIC ANALYSIS               │
│  static_analyzer.py (630 dòng)                 │
│                                                │
│  ├─ Tính hash (MD5, SHA256)                    │
│  ├─ Parse PE VersionInfo:                      │
│  │     ProductName, CompanyName,               │
│  │     FileVersion, OriginalFilename           │
│  ├─ Phân tích PE sections (entropy)            │
│  ├─ Phân tích DLL imports:                     │
│  │     100+ suspicious APIs / 8 categories:   │
│  │     - Process Injection (VirtualAlloc...)   │
│  │     - Anti-Debugging (IsDebuggerPresent)    │
│  │     - Network (WSASocket, connect)          │
│  │     - Registry (RegOpenKey, RegSetValue)    │
│  │     - Privilege Escalation                  │
│  │     - DLL Injection                         │
│  │     - Cryptography                          │
│  │     - File Operations                       │
│  ├─ Phát hiện embedded components:            │
│  │     OpenSSL, libcurl, zlib, Node.js...     │
│  └─ Tính Risk Score (0-100)                   │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 2: CPE EXTRACTION                │
│  cpe_extractor.py (366 dòng)                  │
│                                                │
│  Thử theo thứ tự ưu tiên:                     │
│  1. PE VersionInfo → KNOWN_PATTERNS (150+ SW) │
│     VD: "WinRAR" → cpe:2.3:a:rarlab:winrar:* │
│  2. Filename pattern matching                  │
│  3. [Nếu thất bại → kích hoạt AI/FAISS]      │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 3: CPE RESOLUTION                │
│  ai_analyzer.py + FAISS                       │
│                                                │
│  Nếu CPE chưa xác định rõ:                   │
│  ├─ AI: Claude haiku (claude-haiku-4-5-20251001)│
│  │     Input: ProductName, CompanyName,        │
│  │            FileName, Version               │
│  │     Output: vendor/product (confidence)    │
│  └─ Semantic: FAISS CPE index               │
│        (cosine similarity trên embeddings)   │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 4: NVD CVE LOOKUP                │
│  nvd_api_v2.py (412 dòng)                     │
│                                                │
│  ├─ Kiểm tra local cache (data/cache/nvd/)    │
│  ├─ Query NVD API v2 bằng CPE string          │
│  │     https://services.nvd.nist.gov/...      │
│  ├─ Fallback: keyword search nếu CPE rỗng     │
│  └─ Trả về list CVE (tối đa 2000/request)     │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 5: SEVERITY CLASSIFICATION       │
│  ai/severity_pipeline.py                      │
│                                                │
│  Ensemble (confidence-weighted voting):       │
│  ├─ TF-IDF + Logistic Regression (weight 70%) │
│  │     Accuracy: 86.83%, rất nhanh (CPU)      │
│  ├─ Fine-tuned SecBERT (weight 100%)          │
│  │     Accuracy: 97.94%, chậm hơn (GPU/CPU)  │
│  ├─ XGBoost + CVSS features (weight 85%)      │
│  │     Accuracy: 92-96%                       │
│  └─ Output: severity + confidence + models    │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 6: RELEVANCE SCORING             │
│  contextual_scorer.py + secbert_cve_scorer.py │
│                                                │
│  Phương pháp kết hợp:                         │
│  ├─ Rule-based: CVE keywords ↔ PE capabilities│
│  │     VD: "buffer overflow" → cần file có   │
│  │         suspicious memory APIs             │
│  └─ Semantic: SecBERT + CodeBERT embeddings   │
│        CVE description ↔ PE import sequence  │
│        Cosine similarity trong 768-dim space  │
│        Ngưỡng: ≥0.72 CRITICAL, ≥0.55 HIGH... │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 7: BEHAVIORAL ANALYSIS           │
│  codebert_analyzer.py (416 dòng)              │
│                                                │
│  ├─ Encode suspicious API sequences bằng      │
│  │     microsoft/codebert-base                │
│  ├─ So sánh với 15+ malware patterns:         │
│  │     Process Hollowing, DLL Injection...    │
│  └─ Map sang MITRE ATT&CK framework           │
└────────────────────────────────────────────────┘
     │
     ▼
Trả về JSON kết quả:
  - File metadata + risk score
  - CPE đã resolve
  - Top 50 CVEs (sorted by relevance + CVSS)
  - AI severity predictions
  - Behavioral analysis report
  - MITRE ATT&CK mapping
```

---

## 3. WORKFLOW PHÂN TÍCH PACKAGE MANIFEST

```
User upload requirements.txt / package.json / pom.xml...
     │
     ▼
POST /api/analyze  hoặc  POST /api/analyze-packages
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 1: DETECT ECOSYSTEM              │
│  package_analyzer.py (463 dòng)               │
│                                                │
│  Hỗ trợ 7 ecosystems:                         │
│  ├─ Python  → requirements.txt, Pipfile       │
│  ├─ Node.js → package.json, yarn.lock         │
│  ├─ Java   → pom.xml (Maven), build.gradle    │
│  ├─ PHP    → composer.json                    │
│  ├─ Ruby   → Gemfile                          │
│  ├─ Go     → go.mod                           │
│  └─ Rust   → Cargo.toml                       │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│          BƯỚC 2: PARSE DEPENDENCIES            │
│                                                │
│  Trích xuất: name + version                   │
│  VD: Flask==2.3.0 → {name: Flask, ver: 2.3.0}│
└────────────────────────────────────────────────┘
     │
     ▼
     └─ Cho mỗi package (song song):
          │
          ▼
     ┌─────────────────────────────────────────┐
     │  CPE Resolution (giống PE binary)       │
     │  1. Known CPE hints (Django, Flask...)  │
     │  2. Claude AI matching                  │
     │  3. FAISS semantic search               │
     │  4. NVD keyword fallback               │
     └─────────────────────────────────────────┘
          │
          ▼
     ┌─────────────────────────────────────────┐
     │  NVD CVE Lookup theo CPE               │
     └─────────────────────────────────────────┘
          │
          ▼
     ┌─────────────────────────────────────────┐
     │  Severity Classification (Ensemble)    │
     └─────────────────────────────────────────┘
          │
          ▼
     Kết quả per-package CVEs
     │
     ▼
Kết quả tổng hợp toàn bộ manifest:
  - Per-package CVE list
  - Severity distribution
  - Highest risk packages
  - Total vulnerability count
```

---

## 4. WORKFLOW TÌM KIẾM THEO TÊN PHẦN MỀM

```
User nhập: Software Name + Version
     │
     ▼
POST /api/search
Body: {"software_name": "WinRAR", "version": "6.0", "max_results": 50}
     │
     ▼
┌────────────────────────────────────────────────┐
│  1. CPE Resolution từ tên phần mềm            │
│     ├─ AI: Claude haiku matching               │
│     ├─ FAISS semantic search                   │
│     └─ Pattern matching                        │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│  2. NVD query by CPE                          │
│     Fallback: keyword search nếu CPE thất bại │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│  3. Severity + Relevance enrichment           │
└────────────────────────────────────────────────┘
     │
     ▼
Trả về list CVEs với scores
```

---

## 5. WORKFLOW TRAINING MODELS (One-time Setup)

```
python untils/run_training_pipeline.py
     │
     ▼
┌────────────────────────────────────────────────┐
│  BƯỚC 1: Thu thập dữ liệu (30-60 phút)        │
│  build_training_data.py                       │
│                                                │
│  ├─ Keyword mode: ~5k-15k CVE records (10ph)  │
│  └─ Bulk mode: 220k+ CVE records (60ph)       │
│                                                │
│  Output: data/training/cve_severity_train.csv  │
│  Format: description,severity,cvss_score,...   │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│  BƯỚC 2: Train TF-IDF + Logistic Regression   │
│  train_severity_model.py (~5 phút, CPU-only)  │
│                                                │
│  ├─ TF-IDF vectorization (n-gram 1-3)         │
│  ├─ Logistic Regression với class balancing   │
│  ├─ 5-fold cross-validation                   │
│  └─ Output: models/severity_clf.pkl           │
│     Accuracy: 86.83%                          │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│  BƯỚC 3: Fine-tune SecBERT                    │
│  finetune_bert_severity.py                    │
│  GPU ~30ph / CPU ~2 giờ                       │
│                                                │
│  ├─ Base model: jackaduma/SecBERT             │
│  ├─ Fine-tune trên CVE descriptions           │
│  ├─ 3-5 epochs với learning rate scheduling   │
│  └─ Output: models/bert_severity/             │
│     Accuracy: 97.94%                          │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│  BƯỚC 4: Train XGBoost                        │
│  train_xgboost_severity.py (~10 phút)         │
│                                                │
│  ├─ Features: TF-IDF + CVSS score + vector    │
│  ├─ Gradient boosting với early stopping      │
│  └─ Output: models/xgboost_clf.pkl            │
│     Accuracy: 92-96%                          │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│  BƯỚC 5: Build CPE Semantic Index             │
│  build_cpe_index.py (~15-30 phút)             │
│                                                │
│  ├─ Download NVD CPE dictionary               │
│  ├─ Generate embeddings (sentence-transformers)│
│  ├─ Build FAISS IVF index                     │
│  └─ Output: models/cpe_index.faiss            │
│             models/cpe_meta.pkl               │
└────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────┐
│  BƯỚC 6: Evaluate & Report                    │
│  evaluate_models.py                           │
│                                                │
│  ├─ So sánh accuracy, F1, precision, recall   │
│  └─ Output: models/severity_report.txt        │
└────────────────────────────────────────────────┘
```

---

## 6. CÁC API ENDPOINTS

| Endpoint | Method | Mô Tả |
|----------|--------|--------|
| `/` | GET | Frontend SPA (index.html) |
| `/api/analyze` | POST | Upload PE binary hoặc package manifest |
| `/api/analyze-packages` | POST | Alias cho phân tích packages |
| `/api/search` | POST | Tìm kiếm theo tên phần mềm + version |
| `/api/query-cpe` | POST | Query trực tiếp bằng CPE string |
| `/api/export-all` | POST | Export toàn bộ CVE cho CPE (không giới hạn) |
| `/api/status` | GET | Trạng thái hệ thống + features available |
| `/api/stats` | GET | Alias cho `/api/status` |

---

## 7. KIẾN TRÚC CÁC THÀNH PHẦN

```
┌─────────────────────────────────────────────────────┐
│                     FRONTEND                         │
│              (HTML + CSS + Vanilla JS)              │
│    - Tab: File Analysis / Package / Search / CPE    │
│    - Drag-and-drop upload                           │
│    - Real-time results display                      │
└─────────────────────────┬───────────────────────────┘
                          │ HTTP REST API
┌─────────────────────────▼───────────────────────────┐
│                   FLASK BACKEND                      │
│                    app.py                           │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Static   │  │ Package  │  │ Search/CPE Query │  │
│  │ Analyzer │  │ Analyzer │  │                  │  │
│  └──────┬───┘  └──────┬───┘  └────────┬─────────┘  │
│         │             │               │            │
│  ┌──────▼─────────────▼───────────────▼─────────┐  │
│  │              CPE Extraction Layer             │  │
│  │    KNOWN_PATTERNS → AI (Claude) → FAISS      │  │
│  └──────────────────────┬────────────────────────┘  │
│                         │                          │
│  ┌──────────────────────▼────────────────────────┐  │
│  │           NVD API v2 Client                   │  │
│  │        + Local Cache System                   │  │
│  └──────────────────────┬────────────────────────┘  │
│                         │                          │
│  ┌──────────────────────▼────────────────────────┐  │
│  │         ML Enrichment Pipeline                │  │
│  │                                               │  │
│  │  Severity: TF-IDF + SecBERT + XGBoost        │  │
│  │  Relevance: Rule-based + SecBERT/CodeBERT     │  │
│  │  Behavior: CodeBERT + MITRE ATT&CK            │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   External Services   │
              │                       │
              │  NVD API v2 (NIST)   │
              │  Anthropic Claude API │
              │  HuggingFace Models  │
              └───────────────────────┘
```

---

## 8. WORKFLOW TEST

```
python tests/run_all_test.py
     │
     ├─ test_api.py          → Test Flask endpoints (unit)
     ├─ test_complete.py     → End-to-end integration tests
     ├─ test_cpe_extractor.py→ Unit tests CPE extraction
     └─ demo.py              → Interactive demonstration
```

**Chạy từng bộ test:**
```bash
pytest tests/test_api.py -v
pytest tests/test_complete.py -v
pytest tests/test_cpe_extractor.py -v
python tests/demo.py
```

---

## 9. CẤU TRÚC THƯ MỤC

```
IA_1802/
├── backend/                  # Flask REST API
│   ├── app.py               # Entry point chính
│   ├── ai/                  # ML pipeline
│   │   ├── severity_pipeline.py   # Ensemble classifier
│   │   └── relevance_scorer.py    # CVE relevance
│   ├── ai_analyzer.py       # Claude AI integration
│   ├── cpe_extractor.py     # CPE từ PE files
│   ├── nvd_api_v2.py        # NVD API client
│   ├── package_analyzer.py  # Parse manifest files
│   ├── static_analyzer.py   # PE static analysis
│   ├── codebert_analyzer.py # Behavioral analysis
│   ├── secbert_cve_scorer.py# Semantic relevance
│   ├── contextual_scorer.py # Rule-based relevance
│   ├── severity_classifier.py    # TF-IDF model
│   ├── bert_severity_classifier.py # BERT model
│   ├── xgboost_severity_classifier.py # XGBoost
│   └── zero_shot_severity.py     # Deprecated NLI
├── frontend/                # Web UI
│   ├── templates/index.html # SPA
│   └── static/css,js/
├── untils/                  # Training scripts
│   ├── run_training_pipeline.py  # Master orchestrator
│   ├── build_training_data.py    # Data collection
│   ├── train_severity_model.py   # TF-IDF training
│   ├── finetune_bert_severity.py # BERT fine-tuning
│   ├── train_xgboost_severity.py # XGBoost training
│   ├── build_cpe_index.py        # FAISS index
│   ├── evaluate_models.py        # Metrics report
│   └── preprocess_data.py        # Data cleaning
├── tests/                   # Test suite
├── models/                  # ML artifacts
│   ├── cpe_index.faiss      # FAISS semantic index
│   ├── cpe_meta.pkl         # CPE metadata
│   └── severity_clf.pkl     # Trained classifiers
├── data/                    # Data storage
│   ├── cache/nvd/           # API response cache
│   └── training/            # Training datasets
├── uploads/                 # Temporary uploads
└── requirements.txt         # Python dependencies
```

---

## 10. LUỒNG DỮ LIỆU TỔNG QUAN

```
                    ┌─────────────┐
                    │    NVD API  │
                    │  (NIST.gov) │
                    └──────┬──────┘
                           │ CVE data
                    ┌──────▼──────┐
                    │  Local Cache│
                    │data/cache/  │
                    └──────┬──────┘
                           │
┌──────────┐        ┌──────▼──────┐        ┌──────────┐
│ PE File  │──────▶ │             │◀────── │ Package  │
│ (.exe)   │        │   Flask     │        │Manifest  │
└──────────┘        │   Backend   │        └──────────┘
                    │   app.py    │
┌──────────┐        │             │◀────── ┌──────────┐
│ Software │──────▶ │             │        │  Claude  │
│  Name +  │        └──────┬──────┘        │  AI API  │
│  Version │               │               └──────────┘
└──────────┘        ┌──────▼──────┐
                    │ ML Models   │
                    │TF-IDF+BERT  │
                    │  +XGBoost   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Frontend   │
                    │  (Browser)  │
                    └─────────────┘
```

---

## 11. ĐỘ CHÍNH XÁC CÁC MODEL

| Model | Accuracy | Tốc độ | Yêu cầu |
|-------|----------|--------|---------|
| TF-IDF + Logistic Regression | 86.83% | Rất nhanh | CPU only |
| XGBoost + CVSS | 92-96% | Nhanh | CPU only |
| Fine-tuned SecBERT | 97.94% | Chậm | GPU/CPU |
| Ensemble (kết hợp 3) | Tốt nhất | Trung bình | GPU/CPU |

---

*Tài liệu được tạo tự động bằng phân tích codebase.*
