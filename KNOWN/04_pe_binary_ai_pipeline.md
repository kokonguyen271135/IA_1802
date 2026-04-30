# Pipeline Phân Tích PE Binary — Chi Tiết AI

## Tổng Quan Luồng Dữ Liệu

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        USER UPLOAD (.exe / .dll / .sys)                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
         ┌──────────────────┐            ┌──────────────────────┐
         │  STATIC ANALYSIS  │            │   AI BEHAVIORAL       │
         │ (PEStaticAnalyzer)│            │   SCORING (EMBER)     │
         │   [Rule-based]    │            │   [XGBoost ML]        │
         └──────────────────┘            └──────────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │    CPE RESOLUTION      │
                        │  [Rule + AI FAISS]     │
                        └───────────────────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │     NVD API v2         │
                        │   CVE DATABASE         │
                        └───────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
         ┌──────────────────┐            ┌──────────────────────┐
         │ AI SEVERITY       │            │  AI RELEVANCE         │
         │ PREDICTION        │            │  SCORING              │
         │ [BERT Ensemble]   │            │  [SecBERT NLI]        │
         └──────────────────┘            └──────────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
               ┌──────────────────┐  ┌──────────────────────┐
               │   CWE BEHAVIOR   │  │   RULE-BASED           │
               │   PREDICTION     │  │   RECOMMENDATIONS      │
               │   (Hướng 3)      │  │   ENGINE               │
               └──────────────────┘  └──────────────────────┘
                         │                     │
                         └──────────┬──────────┘
                                    ▼
                        ┌───────────────────────┐
                        │      FRONTEND UI       │
                        │  Kết quả phân tích     │
                        └───────────────────────┘
```

---

## Khối 1 — Static Analysis (Rule-based, KHÔNG phải AI)

```
File: backend/static_analyzer.py → PEStaticAnalyzer

Input: raw PE file bytes
       │
       ├── [1a] File Info + Hash
       │     MD5, SHA1, SHA256 (chunked 65536 bytes/lần)
       │
       ├── [1b] PE Header (pefile)
       │     machine: x86 / x64 / ARM / ARM64
       │     compile_time → fake timestamp nếu < 1995 hoặc > 2035
       │     subsystem: GUI / Console / Native / EFI
       │     flags: has_tls, has_debug, has_resources
       │
       ├── [1c] Section Analysis
       │     Shannon Entropy → > 7.0 = packed/encrypted
       │     Suspicious section name (không trong whitelist KNOWN_SECTIONS)
       │
       ├── [1d] Import Table ← QUAN TRỌNG NHẤT
       │     Đối chiếu toàn bộ import với SUSPICIOUS_APIS database:
       │
       │     Category             Risk      Ví dụ API
       │     ──────────────────────────────────────────────────────────
       │     Code Execution       CRITICAL  ShellExecute, CreateProcess
       │     Process Injection    HIGH      VirtualAllocEx, WriteProcessMemory
       │     Keylogging           HIGH      SetWindowsHookEx, GetAsyncKeyState
       │     Privilege Escalation HIGH      AdjustTokenPrivileges, OpenProcessToken
       │     Anti-Debugging       MEDIUM    IsDebuggerPresent, NtQueryInformationProcess
       │     Network Comm         MEDIUM    InternetOpen, URLDownloadToFile
       │     Service Manipulation MEDIUM    CreateService, OpenSCManager
       │     Dynamic Loading      MEDIUM    LoadLibraryEx, GetProcAddress
       │     Registry             LOW       RegCreateKeyEx, RegSetValueEx
       │     Cryptography         LOW       CryptEncrypt, BCryptHashData
       │     ──────────────────────────────────────────────────────────
       │
       ├── [1e] String Extraction (scan 50MB đầu)
       │     URLs (http/https), IP Addresses, Email
       │     Registry Keys (HKLM\..., HKCU\...)
       │     File Paths (C:\...)
       │     Suspicious Commands (cmd.exe, powershell, certutil, mshta)
       │     Potential Base64 payloads
       │
       ├── [1f] Component Detection
       │     Regex scan strings + 4MB raw bytes:
       │     OpenSSL 1.0.1, Python 3.9, libcurl 7.68, SQLite 3.35...
       │     DLL names: python39.dll → Python 3.9, msvcr100.dll → MSVC 10.0
       │
       └── [1g] Static Risk Score (heuristic)
             CRITICAL API: +20/cái
             HIGH API:     +12/cái
             MEDIUM API:   +4/cái
             High entropy section: +20/cái
             Suspicious section name: +5/cái
             Embedded URLs: +3/URL (max 15)
             Embedded IPs: +5/IP (max 20)
             Suspicious commands: +10/cái
             Base64 payloads: +2/cái (max 10)
             TLS callbacks: +5
             Score 0–100 → CLEAN / LOW / MEDIUM / HIGH / CRITICAL

Output: {suspicious_apis[], sections[], strings{}, risk{score,level,factors}, components[]}
```

---

## Khối 2 — EMBER XGBoost ★ AI

```
File: backend/ai/ember_behavioral_scorer.py
      backend/ai/ember1390_encoder.py
      Model: models/ember2017_xgb.json

Input: raw PE file bytes
       │
       ▼
┌──────────────────────────────────────────────────────┐
│  ember1390_encoder.py → extract_feature1390_from_exe  │
│                                                       │
│  ember.PEFeatureExtractor(feature_version=1)          │
│  Trích xuất 1390 features:                           │
│                                                       │
│  [0..255]   Byte histogram (256 dims)                 │
│             Phân phối byte 0x00-0xFF toàn file        │
│                                                       │
│  [256..]    Byte entropy histogram                    │
│             Entropy theo từng vùng file               │
│                                                       │
│  [....]     String features                           │
│             Tỷ lệ printable, độ dài trung bình        │
│                                                       │
│  [....]     General header info                       │
│             File size, has_debug, exports count       │
│                                                       │
│  [....]     Section features (per section)            │
│             Virtual size, entropy, flags              │
│                                                       │
│  [....]     Import hash (FeatureHasher)               │
│             Fingerprint DLL + function names          │
│                                                       │
│  [....]     Export hash                               │
│             Fingerprint exported symbols              │
└──────────────────────────────────────────────────────┘
       │
       ▼ numpy array shape (1, 1390)
┌──────────────────────────────────────────────────────┐
│  XGBoost Booster — ember2017_xgb.json                │
│                                                       │
│  Training data: EMBER 2017 Dataset                   │
│  600,000 PE samples (train) + 200,000 (test)         │
│  Label: malware (1) / benign (0)                     │
│                                                       │
│  Performance:                                         │
│  ROC-AUC  = 0.9994                                   │
│  F1-score = 0.9906                                   │
│  Accuracy = 98.99%                                   │
│  Threshold = 0.51                                    │
└──────────────────────────────────────────────────────┘
       │
       ▼ probability: 0.0 → 1.0
       ├── ≥ 0.80 → CRITICAL / MALWARE
       ├── ≥ 0.51 → HIGH     / MALWARE   ← threshold
       ├── ≥ 0.35 → MEDIUM   / SUSPICIOUS
       ├── ≥ 0.15 → LOW      / SUSPICIOUS
       └── < 0.15 → CLEAN    / BENIGN

Output: {probability, level, label, method: "EMBER XGBoost"}

Vai trò trong hệ thống:
  → Nguồn DUY NHẤT tính AI Risk Score (prob × 100)
  → Gate cho Hướng 3 (prob ≥ 0.50 → chạy CWE prediction)
  → CLEAN detection (prob < 0.20 + không có CVE → hiển thị CLEAN)
  → Giải thích mâu thuẫn (prob < 0.20 nhưng có CVE → thêm note)

LƯU Ý QUAN TRỌNG:
  EMBER đo "file này trông giống malware không"
  CVE đo "phần mềm này có lỗ hổng đã biết không"
  → Hai thứ hoàn toàn độc lập nhau
```

---

## Khối 3 — CPE Resolution (Rule + AI FAISS)

```
File: backend/cpe_extractor.py
      backend/cpe_semantic_matcher.py
      Model: models/cpe_index.faiss + models/cpe_meta.pkl

Input: PE Version Info {ProductName, CompanyName, FileVersion}
       │
       ├── [Rule] KNOWN_PATTERNS lookup (200+ entries hardcoded)
       │         "sql server"   → cpe:2.3:a:microsoft:sql_server:...
       │         "putty"        → cpe:2.3:a:simon_tatham:putty:...
       │         "mysql"        → cpe:2.3:a:oracle:mysql:...
       │         "apache"       → cpe:2.3:a:apache:http_server:...
       │
       └── [AI FAISS] Khi rule-based thất bại
             │
             ├── SentenceTransformer encode ProductName → vector 768 dims
             ├── FAISS IndexFlatIP tìm vector gần nhất trong CPE dictionary
             │     Metric: cosine similarity (dot product trên normalized vectors)
             └── Confidence thresholds:
                   ≥ 0.80 → high   → dùng kết quả
                   ≥ 0.60 → medium → dùng kết quả
                   < 0.60 → low    → bỏ qua, không dùng

Output: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
```

---

## Khối 4 — NVD API v2 (Không phải AI)

```
File: backend/nvd_api_v2.py

Input: CPE string
       │
       ├── search_by_cpe(cpe, max=50)     → NVD REST API v2
       ├── 0 kết quả → search_by_keyword("{product} {version}", max=50)
       └── 0 kết quả → search_by_keyword("{product}", max=50)

Output: raw CVE list
        [{cve_id, description, cvss_score, severity, vector_string, published}]
```

---

## Khối 5 — AI Severity Prediction ★ AI

```
File: backend/ai/severity_pipeline.py
      backend/bert_severity_classifier.py
      backend/xgboost_severity_classifier.py
      Model: models/bert_severity/ + models/xgboost_severity/

Input: CVE description text + CVSS vector string
       │
       ├── [AI Model 1] Fine-tuned BERT (weight: 1.00)
       │     Base: DistilBERT / SecBERT
       │     Fine-tuned trên: NVD CVE descriptions dataset
       │     Accuracy: 97.94%
       │     │
       │     ├── AutoTokenizer.encode(description, max_length=256)
       │     ├── AutoModelForSequenceClassification forward pass
       │     ├── Softmax(logits) → probabilities{CRITICAL, HIGH, MEDIUM, LOW}
       │     └── → {predicted_severity, confidence, probabilities}
       │
       ├── [AI Model 2] XGBoost + CVSS Features (weight: 0.85)
       │     Accuracy: 92–96%
       │     Features: TF-IDF(description) + CVSS numeric components
       │     → {predicted_severity, confidence}
       │
       └── [Ensemble] Confidence-weighted voting
             sev_score[s] += weight × confidence    (primary vote)
             sev_score[s] += weight × 0.25 × p[s]  (soft vote từ prob vector)
             Normalize → winner = argmax(sev_score)

Output: cve['ai_severity'] = {
            predicted_severity: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW",
            confidence: 0.0–1.0,
            source: "ensemble"|"bert"|"xgboost",
            models_used: ["bert", "xgboost"],
            ensemble_scores: {CRITICAL:0.4, HIGH:0.3, MEDIUM:0.2, LOW:0.1}
        }

Mục đích: Thay thế NVD severity label gốc (NVD đôi khi gán sai mức độ)
```

---

## Khối 6 — AI Relevance Scoring ★ AI

```
File: backend/ai/relevance_scorer.py
      backend/secbert_cve_scorer.py
      Model: jackaduma/SecBERT (HuggingFace)
             Fallback: all-mpnet-base-v2 → all-MiniLM-L6-v2

Input: PE analysis dict + CVE list
       │
       ├── [Bước 1] Build behavior profile text (natural language)
       │     Ví dụ:
       │     "File imports VirtualAllocEx, WriteProcessMemory (Process Injection).
       │      Detected: CreateRemoteThread HIGH risk.
       │      High entropy section .rsrc — possible packing.
       │      Embedded URLs: http://..."
       │
       └── [Bước 2] SecBERT NLI Scoring
             ├── Encode behavior_profile_text → vector 768 dims
             ├── Encode mỗi CVE description  → vector 768 dims
             ├── cosine_similarity(profile_vec, cve_vec) → score 0–1
             └── Threshold mapping:
                   ≥ 0.72 → CRITICAL relevance
                   ≥ 0.55 → HIGH
                   ≥ 0.50 → MEDIUM
                   ≥ 0.30 → LOW
                   < 0.30 → MINIMAL → BỊ FILTER BỎ

             Sort: relevance score DESC → CVSS score DESC
             Filter: bỏ MINIMAL/LOW
             Safety net: nếu filter xóa hết → giữ lại toàn bộ

Output: mỗi CVE có thêm:
        cve['relevance'] = {score, label, method: "secbert", model}

Mục đích: Loại bỏ CVE không liên quan đến hành vi thực tế của file
          Khác với keyword matching — SecBERT hiểu ngữ nghĩa:
          "improper memory boundary check in heap" ≈ "Process Injection"
          dù không có từ nào trùng nhau
```

---

## Khối 7 — CWE Behavior Prediction / Hướng 3 (Conditional AI)

```
File: backend/cwe_predictor.py
      Model: models/bert_cwe/ (SecBERT fine-tuned, 15 CWE classes, acc=86.59%)

Điều kiện kích hoạt:
  ✓ Không có CPE rõ ràng (không biết phần mềm gì)
  ✓ EMBER prob ≥ 0.50  HOẶC  có HIGH/CRITICAL suspicious API
  ✗ Bỏ qua nếu EMBER thấp + không có API nguy hiểm (tránh CVE ảo)

Input: suspicious APIs + behavior signals
       │
       ├── [AI] CWE Classification (fine-tuned SecBERT)
       │     Input: behavior profile text
       │     Output: Top-5 CWEs với confidence score
       │     Bỏ CWE có confidence < 0.10
       │     Ví dụ:
       │       VirtualAllocEx + WriteProcessMemory → CWE-94 (Code Injection)
       │       SetWindowsHookEx + GetAsyncKeyState → CWE-319 (Keylogging)
       │       AdjustTokenPrivileges               → CWE-269 (Privilege Escalation)
       │       InternetOpen + URLDownloadToFile    → CWE-200 (Info Exposure)
       │
       ├── Query NVD by predicted CWE IDs → raw CVE list
       ├── enrich_cves() → BERT severity + SecBERT relevance scoring
       └── Sort by relevance DESC → Top 10

Merge với CVE từ CPE:
  - Không có CVE từ CPE → dùng hoàn toàn Hướng 3
  - Có CVE từ CPE → merge nếu relevance ≥ 0.4, dedup by CVE-ID, max 50
  - Tính lại ai_risk từ EMBER + merged CVE list
```

---

## Khối 8 — Rule-based Recommendations (Không phải AI)

```
File: backend/app.py → _generate_recommendations()

Input: CVE list + EMBER result + suspicious APIs
       │
       ├── Parse CVSS vector string mỗi CVE:
       │     AV:N → network-accessible (nguy hiểm hơn AV:L)
       │     AC:L → low complexity (dễ khai thác)
       │     PR:N → không cần authentication
       │     UI:N → không cần user interaction
       │     C:H / I:H / A:H → impact cao
       │
       ├── Detect 12 threat types từ keywords trong description
       ├── Embed CVE-ID + CVSS score vào từng recommendation
       │
       └── Special cases:
             EMBER < 0.20 + có CVE  → thêm note giải thích mâu thuẫn
             Không CVE + EMBER < 0.20 → return CLEAN status
             Không CVE + EMBER cao  → dùng behavioral signals

Output: {overall_risk, risk_summary, top_threats[], recommendations[], cvss_vectors[]}
```

---

## Tóm Tắt 5 AI Component

| # | AI Component | Loại AI | Model | Đo cái gì | Accuracy |
|---|---|---|---|---|---|
| 1 | EMBER XGBoost | Gradient Boosting | ember2017_xgb.json | File có phải malware? | AUC=0.9994 |
| 2 | FAISS + SentenceTransformer | Vector Similarity | cpe_index.faiss | Phần mềm này là CPE gì? | — |
| 3 | BERT fine-tuned (Severity) | Transformer | models/bert_severity/ | CVE này nguy hiểm mức nào? | 97.94% |
| 4 | SecBERT NLI (Relevance) | Transformer | jackaduma/SecBERT | CVE có liên quan file này không? | — |
| 5 | SecBERT fine-tuned (CWE) | Transformer | models/bert_cwe/ | File hành xử như lỗ hổng loại nào? | 86.59% |

```
Mỗi AI độc lập — Graceful Degradation:
  Thiếu EMBER    → bỏ behavioral score, vẫn có CVE
  Thiếu BERT     → dùng NVD severity gốc
  Thiếu SecBERT  → sort by CVSS thay vì semantic similarity
  Thiếu FAISS    → chỉ dùng rule-based CPE lookup (200+ patterns)
  Thiếu CWE model → bỏ Hướng 3, chỉ dùng CPE-based CVE
```

---

## Điểm Khác Biệt EMBER vs Static Risk

| | Static Risk Score | EMBER Score |
|---|---|---|
| Phương pháp | Rule-based heuristic | XGBoost ML |
| Input | Suspicious API list, entropy, strings | 1390 numeric features từ raw bytes |
| Training | Không có (rules viết tay) | 600,000 PE samples thực tế |
| Kết quả | Score 0–100 theo quy tắc cộng điểm | Probability 0.0–1.0 từ model |
| Vai trò | Giải thích tại sao đáng ngờ | Quyết định file có phải malware không |
| Dùng để | Hiển thị chi tiết cho user | Tính AI Risk Score + gate Hướng 3 |
