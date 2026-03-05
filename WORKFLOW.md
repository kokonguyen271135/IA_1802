# Workflow Hệ Thống: Software Vulnerability Assessment Tool

---

## Kiến Trúc Tổng Quan

Hệ thống có **3 loại input** khác nhau, nhưng tất cả đều đi qua **1 pipeline lõi chung**:

```
         ┌──────────────────────────────────────────────┐
INPUT    │  File PE (.exe/.dll)  │  Package Manifest  │  Tìm theo tên  │
         └──────────┬───────────┴────────┬───────────┴───────┬──────────┘
                    │                    │                   │
                    ▼                    ▼                   ▼
         ┌──────────────────────────────────────────────────────────────┐
         │                   BƯỚC 1: TRÍCH XUẤT THÔNG TIN              │
         │  PE → PEStaticAnalyzer    Package → PackageAnalyzer         │
         │  Lấy: ProductName,        Lấy: {name, version}              │
         │        version, hash       từng dependency                  │
         └──────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
         ┌──────────────────────────────────────────────────────────────┐
         │              BƯỚC 2: _resolve_cpe()  ← DÙNG CHUNG          │
         │                                                              │
         │  1. CPEExtractor (rule-based, 150+ known patterns)          │
         │       VD: "WinRAR" → cpe:2.3:a:rarlab:winrar:*             │
         │         ↓ nếu không khớp                                    │
         │  2. Claude AI (ai_match_cpe) — hiểu tên sản phẩm ngữ nghĩa │
         │         ↓ nếu AI thất bại hoặc không có key                │
         │  3. FAISS Semantic Search — cosine similarity trên CPE index│
         └──────────────────────────┬───────────────────────────────────┘
                                    │ CPE string: cpe:2.3:a:vendor:product:ver:*
                                    ▼
         ┌──────────────────────────────────────────────────────────────┐
         │              BƯỚC 3: NVDAPIv2.search_by_cpe()  ← DÙNG CHUNG│
         │                                                              │
         │  ├─ Kiểm tra local cache (data/cache/nvd/)                 │
         │  ├─ Query NVD API v2 (services.nvd.nist.gov)               │
         │  ├─ Fallback: keyword search nếu CPE rỗng                  │
         │  └─ Trả về list CVE (tối đa 2000 kết quả)                 │
         └──────────────────────────┬───────────────────────────────────┘
                                    │ List[CVE]
                                    ▼
         ┌──────────────────────────────────────────────────────────────┐
         │              BƯỚC 4: _enrich_cves()  ← DÙNG CHUNG          │
         │                                                              │
         │  ai_enrich_severity():  Phân loại mức nghiêm trọng          │
         │  ┌─ TF-IDF + Logistic Regression   (weight 70%, acc 86.8%) │
         │  ├─ Fine-tuned SecBERT             (weight 100%, acc 97.9%)│
         │  └─ XGBoost + CVSS features        (weight 85%, acc 94%)   │
         │     → Ensemble voting → severity + confidence               │
         │                                                              │
         │  ai_score_relevance():  CVE nào thực sự liên quan file này? │
         │  ┌─ Rule-based: CVE keywords ↔ PE suspicious API categories │
         │  └─ SecBERT/CodeBERT: cosine similarity CVE desc ↔ imports  │
         │     → relevance score 0.0–1.0 cho từng CVE                 │
         └──────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
                          JSON response trả về client
```

---

## Chi Tiết Từng Loại Input

### Input 1: File PE Binary

```
POST /api/analyze  (file .exe / .dll / .sys / .ocx / .drv)
         │
         ▼
_analyze_pe(filepath, filename)
         │
         ├─ pe_analyzer.analyze(filepath)          ← static_analyzer.py
         │     • Hash: MD5, SHA256
         │     • VersionInfo: ProductName, CompanyName, FileVersion
         │     • Sections: entropy, tên section bất thường
         │     • Imports: DLL + suspicious API detection
         │     • Components: OpenSSL, libcurl, Node.js nhúng trong file
         │     • Risk score: tổng hợp tất cả dấu hiệu nguy hiểm
         │
         ├─ cpe_extractor.extract_from_file(filepath)
         │     → _resolve_cpe()  [shared - xem trên]
         │
         ├─ nvd_api.search_by_cpe(cpe)
         │     → NVD query [shared - xem trên]
         │
         ├─ _enrich_cves(cves, software_analysis=pe_result)
         │     → Severity + Relevance [shared - xem trên]
         │     ↑ software_analysis truyền vào để relevance scoring
         │       biết file này có những API/capability gì
         │
         └─ codebert_analyzer.analyze(pe_result)   ← codebert_analyzer.py
               • Encode suspicious API sequence bằng CodeBERT
               • So sánh với 15+ malware behavioral patterns
               • Output: behavior profile + MITRE ATT&CK mapping
```

**Kết quả trả về:**
```json
{
  "analysis_type": "binary",
  "filename": "...", "hash": {...}, "risk": {"level": "HIGH", "score": 72},
  "cpe": "cpe:2.3:a:vendor:product:version:*...",
  "vulnerabilities": [
    {"cve_id": "CVE-2024-...", "severity": "CRITICAL", "cvss_score": 9.8,
     "ai_severity": {"severity": "CRITICAL", "confidence": 0.97},
     "relevance": {"score": 0.81, "label": "CRITICAL RELEVANCE"}}
  ],
  "cve_statistics": {"total": 42, "critical": 5, "high": 18, ...},
  "behavior_profile": {...},
  "mitre_techniques": [...]
}
```

---

### Input 2: Package Manifest

```
POST /api/analyze  (requirements.txt / package.json / pom.xml / ...)
         │
         ▼
_analyze_package_manifest(filepath, filename)
         │
         ├─ pkg_analyzer.analyze(filepath)          ← package_analyzer.py
         │     • Detect ecosystem: Python/Node/Maven/Gradle/PHP/Ruby/Go/Rust
         │     • Parse dependencies: [{name, version}, ...]
         │
         └─ Vòng lặp: for each package in dependencies:
               │
               ├─ Lookup known CPE hints (Django→django:django, Flask→pallets:flask...)
               ├─ _resolve_cpe()  [shared - xem trên]
               ├─ nvd_api.search_by_cpe(cpe)  [shared]
               └─ _enrich_cves(cves)          [shared]
                     ↑ Không truyền software_analysis vì package
                       không có behavioral context như PE
```

**Kết quả trả về:**
```json
{
  "analysis_type": "packages",
  "ecosystem": "python",
  "packages": [
    {
      "name": "Django", "version": "3.2.0",
      "cpe": "cpe:2.3:a:djangoproject:django:3.2.0:*...",
      "vulnerabilities": [...],
      "cve_count": 12
    }
  ],
  "total_vulnerabilities": 47,
  "summary": {"critical": 3, "high": 15, ...}
}
```

---

### Input 3: Tìm Kiếm Theo Tên

```
POST /api/search
Body: {"software_name": "WinRAR", "version": "6.0", "max_results": 50}
         │
         ▼
         ├─ _resolve_cpe({product: "WinRAR", version: "6.0",
         │                extraction_method: "manual_input"})
         │     [shared - xem trên]
         │
         ├─ nvd_api.search_by_cpe(cpe)  [shared]
         │
         └─ _enrich_cves(cves)          [shared]
```

```
POST /api/query-cpe
Body: {"cpe": "cpe:2.3:a:rarlab:winrar:6.0:*:*:*:*:*:*:*"}
         │
         ├─ Bỏ qua bước resolve_cpe (đã có CPE sẵn)
         ├─ nvd_api.search_by_cpe(cpe)  [shared]
         └─ _enrich_cves(cves)          [shared]
```

---

## Sơ Đồ Shared Components

```
                    ┌─────────────────────────────────────┐
                    │         SHARED CORE PIPELINE        │
                    │                                     │
  PE Analysis ─────▶│  _resolve_cpe()                    │
  Package Analysis ─▶│    ├─ CPEExtractor (rules)         │
  Search ────────────▶│    ├─ Claude AI (ai_match_cpe)    │
  CPE Query ─────────▶│    └─ FAISS semantic              │
                    │                                     │
                    │  NVDAPIv2.search_by_cpe()           │
                    │    ├─ Local cache                   │
                    │    ├─ NVD API v2                    │
                    │    └─ Keyword fallback              │
                    │                                     │
                    │  _enrich_cves()                     │
                    │    ├─ SeverityPipeline (ensemble)   │
                    │    └─ RelevanceScorer               │
                    └─────────────────────────────────────┘
                         ↑                    ↑
              models/severity_clf.pkl    models/cpe_index.faiss
              models/bert_severity/      (được load 1 lần khi khởi động)
              models/xgboost_clf.pkl
```

---

## Training Pipeline (One-time Setup)

Pipeline training tạo ra các file model được load lúc khởi động:

```
python untils/run_training_pipeline.py
         │
         ├─ build_training_data.py
         │     NVD API → 5k–220k CVE records
         │     Output: data/training/cve_severity_train.csv
         │
         ├─ preprocess_data.py
         │     Làm sạch data, cân bằng class
         │
         ├─ train_severity_model.py
         │     TF-IDF + Logistic Regression
         │     Output: models/severity_clf.pkl          ← load lúc boot
         │
         ├─ finetune_bert_severity.py
         │     Fine-tune jackaduma/SecBERT trên CVE descriptions
         │     Output: models/bert_severity/             ← load lúc boot
         │
         ├─ train_xgboost_severity.py
         │     XGBoost + CVSS numeric features
         │     Output: models/xgboost_clf.pkl            ← load lúc boot
         │
         ├─ build_cpe_index.py
         │     Download NVD CPE dictionary
         │     Generate sentence-transformer embeddings
         │     Build FAISS IVF index
         │     Output: models/cpe_index.faiss            ← load lúc boot
         │             models/cpe_meta.pkl
         │
         └─ evaluate_models.py
               So sánh accuracy/F1/precision/recall
               Output: models/severity_report.txt
```

---

## Khởi Động Hệ Thống

```
python backend/app.py
         │
         ├─ Khởi tạo 4 service object (dùng suốt vòng đời app):
         │     nvd_api       = NVDAPIv2(api_key)       ← giữ session + cache
         │     cpe_extractor = CPEExtractor()           ← load KNOWN_PATTERNS
         │     pe_analyzer   = PEStaticAnalyzer()       ← ready to parse PE
         │     pkg_analyzer  = PackageAnalyzer()        ← load ecosystem parsers
         │
         ├─ Load ML models vào RAM (nếu có):
         │     SeverityPipeline: TF-IDF + SecBERT + XGBoost
         │     RelevanceScorer:  SecBERT + CodeBERT
         │     FAISS CPE index
         │
         └─ Flask listen trên port 5000
               GET  /            → frontend SPA
               POST /api/analyze → _analyze_pe() hoặc _analyze_package_manifest()
               POST /api/search  → search by name
               POST /api/query-cpe → direct CPE query
               POST /api/export-all → export không giới hạn
               GET  /api/status  → feature availability check
```

---

## Tóm Tắt

| Component | Vai trò | Được dùng bởi |
|-----------|---------|---------------|
| `_resolve_cpe()` | Tìm CPE từ tên phần mềm | PE, Package, Search |
| `NVDAPIv2` | Truy vấn CVE từ NVD | PE, Package, Search, CPE Query |
| `_enrich_cves()` | Gán severity + relevance | PE, Package, Search, CPE Query |
| `PEStaticAnalyzer` | Phân tích PE binary | PE only |
| `PackageAnalyzer` | Parse manifest dependencies | Package only |
| `CodeBERT Analyzer` | Behavioral + MITRE mapping | PE only |
| ML Models (BERT/XGBoost) | Severity classification | Tất cả (qua _enrich_cves) |
| FAISS Index | Semantic CPE search | Tất cả (qua _resolve_cpe) |
