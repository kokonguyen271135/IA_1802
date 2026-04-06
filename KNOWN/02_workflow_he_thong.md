# Workflow Hệ Thống

## Kiến Trúc Tổng Thể

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Browser)                        │
│   HTML + CSS + JavaScript   |   http://localhost:5000            │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP POST (multipart/form-data)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     BACKEND (Flask Server)                       │
│                        backend/app.py                            │
│                                                                  │
│  /api/analyze  ──►  PE binary  ──►  _analyze_pe()               │
│                 ──►  Manifest  ──►  _analyze_package_manifest()  │
│  /api/search   ──►  Software name  ──►  search_by_name()        │
│  /api/query-cpe ──►  CPE string  ──►  query_cpe()               │
└──────────────────────────────┬──────────────────────────────────┘
                               │
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
    ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
    │  AI Models  │    │  NVD API v2  │    │  Static      │
    │  (local)    │    │  (remote)    │    │  Analyzer    │
    └─────────────┘    └──────────────┘    └──────────────┘
```

---

## Chi Tiết Workflow Phân Tích PE

### Bước 1: Upload & Route
```
User chọn file → POST /api/analyze
Flask nhận file → lưu vào uploads/
Detect file type:
  .exe/.dll/.sys → _analyze_pe()
  requirements.txt/package.json → _analyze_package_manifest()
```

### Bước 2: Static Analysis
```
PEStaticAnalyzer.analyze(filepath)
  ├── PE Header: arch, timestamp, entry point, subsystem
  ├── Sections: .text .data .rdata — entropy, size, flags
  ├── Imports: DLL list, function list
  │   └── Match với SUSPICIOUS_APIS database
  │       → by_category: {Process Injection: [...], Keylogging: [...]}
  │       → suspicious: [{function, dll, risk, category}]
  ├── Exports: exported functions
  ├── Strings: URLs, IPs, Paths, Base64, Commands
  ├── Version Info: ProductName, CompanyName, FileVersion
  └── Risk Score: 0-100 dựa trên suspicious APIs + entropy + strings
```

### Bước 3: EMBER ML Scoring
```
ember_score_file(filepath)
  ├── extract_feature1390_from_exe(filepath)
  │   ├── ByteHistogram (256 dim)
  │   ├── ByteEntropyHistogram (256 dim)
  │   ├── StringFeatures (103 dim): numstrings, avlength, entropy, paths, urls...
  │   ├── GeneralFileInfo (10 dim): filesize, exports, imports...
  │   ├── HeaderFileInfo (62 dim): machine, characteristics, dll_characteristics...
  │   ├── SectionInfo (253 dim): name hashes, sizes, entropies...
  │   ├── ImportsInfo (1280 dim): FeatureHasher(dll:fn pairs)
  │   └── ExportsInfo (128 dim): FeatureHasher(export names)
  │   Total: 1,390 features
  │
  └── xgb_model.predict_proba([features])
      → probability: 0.0 - 1.0
      → label: BENIGN / MALWARE
      → level: CLEAN / SUSPICIOUS / MALWARE / CRITICAL
```

### Bước 4: CPE Extraction & CVE Lookup
```
CPEExtractor.extract_from_file(filepath)
  ├── Đọc PE VersionInfo (FileDescription, ProductName, FileVersion)
  ├── Pattern matching tên file → known software
  └── Build CPE: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*

Nếu CPE không chính xác → FAISS Semantic Matcher
  ├── Query: ProductName hoặc filename
  └── So sánh với 109 CPE vector → best match

NVD API v2 Query:
  ├── search_by_cpe(cpe) → CVE list
  ├── Nếu 0 kết quả → search_by_keyword(product + version)
  └── max_results: 50 CVEs
```

### Bước 5: AI Enrichment
```
_enrich_cves(cves, software_analysis)
  ├── ai_enrich_severity(cves)
  │   ├── bert_severity_classifier.predict(description)
  │   │   → CRITICAL/HIGH/MEDIUM/LOW + confidence
  │   └── xgboost_severity_classifier.predict(description, vector_string)
  │       → CRITICAL/HIGH/MEDIUM/LOW + confidence
  │   Ensemble: weighted voting (BERT=1.00, XGBoost=0.85)
  │
  └── ai_score_relevance(software_analysis, cves)
      ├── Build behavior profile text từ PE analysis
      ├── SecBERT embed profile text → vector
      ├── SecBERT embed mỗi CVE description → vector
      ├── cosine_similarity(profile, cve) → score 0.0-1.0
      └── Label: CRITICAL>=0.72, HIGH>=0.55, MEDIUM>=0.50, LOW>=0.30
      Filter: bỏ LOW + MINIMAL (safety net: giữ nếu filter wipe hết)
```

### Bước 6: CWE Behavior Prediction (Hướng 3)
```
Gate check:
  ember_prob >= 0.50 OR có HIGH/CRITICAL suspicious API (tên hợp lệ)
  → YES: chạy Hướng 3
  → NO: skip (file clean)

CWEPredictor.predict_and_fetch(analysis)
  ├── Build behavior profile text
  ├── CWE Classifier (fine-tuned SecBERT, 15 classes)
  │   → Top-5 CWEs với confidence score
  │   → Bỏ CWE có conf < 0.10
  │
  ├── Target detection: extract software name từ strings/version
  │
  ├── NVD Query: CWE_id + target_keyword
  │   └── Nếu < 5 CVE và EMBER >= 50% → Behavior keyword search
  │       Top 3 behaviors → keyword mapping → search_by_keyword (5 CVE/behavior)
  │
  └── Merge + dedup → return cve_results

app.py:
  ├── _enrich_cves(cwe_cves) → SecBERT relevance scoring
  ├── Sort by relevance score DESC
  └── Keep top 10 CVEs
```

### Bước 7: Response
```
Result dict:
  ├── success, filename, analysis_type
  ├── risk: {score, level, factors, method}
  ├── ember_behavioral: {probability, label, level}
  ├── pe_info, sections, imports, exports, strings
  ├── cpe, cpe_info, ai_cpe, sem_cpe
  ├── vulnerabilities: [CVE list]
  ├── cve_statistics: {total, by_severity, avg_cvss}
  ├── cwe_analysis: {predicted_cwes, cve_results}
  └── component_vulnerabilities: [embedded lib CVEs]

Flask jsonify(result) → HTTP 200
Frontend render → Dashboard
```

---

## Workflow Package Manifest

```
Upload requirements.txt
    ↓
PackageAnalyzer.analyze()
  ├── Detect ecosystem: pip / npm / maven / cargo...
  └── Parse: [{name, version, extras}]
    ↓
Với mỗi package:
  ├── CPE lookup (hardcoded hints hoặc FAISS)
  ├── NVD search_by_cpe() hoặc search_by_keyword()
  └── ai_enrich_severity()
    ↓
Aggregate: total unique CVEs, global statistics
    ↓
Response: per-package results + all_cves
```

---

## Các API Endpoints

| Method | Endpoint | Chức năng |
|--------|----------|-----------|
| POST | /api/analyze | Phân tích PE hoặc manifest |
| POST | /api/search | Tìm CVE theo tên phần mềm |
| POST | /api/query-cpe | Query CVE theo CPE string |
| POST | /api/export-all | Export toàn bộ CVE không giới hạn |
| GET | /api/status | Trạng thái hệ thống + AI features |

---

## Models Được Sử Dụng

| Model | Task | Accuracy | Location |
|-------|------|----------|----------|
| XGBoost (EMBER) | Malware detection | AUC=0.9994 | models/ember2017_xgb.json |
| SecBERT fine-tuned | Severity classification | 97.94% | models/bert_severity/ |
| XGBoost | Severity (CVSS+text) | 92-96% | models/xgboost_severity/ |
| SecBERT fine-tuned | CWE classification | 86.59% | models/bert_cwe/ |
| all-MiniLM-L6-v2 | CVE relevance scoring | — | HuggingFace |
| FAISS index | CPE semantic matching | — | models/cpe_index/ |
