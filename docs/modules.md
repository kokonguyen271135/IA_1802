# Tài liệu Module — Lý thuyết + Source Code

> Slide này trả lời feedback của thầy: **"Kiến thức lý thuyết và source code phải chia sẻ cho các thành viên nắm bắt những phần trọng yếu"**.
>
> Mỗi member phải đọc **toàn bộ tài liệu này** trước khi bảo vệ. Khi hội đồng hỏi bất kỳ module nào, member phụ trách phải trả lời được.

## Cấu trúc dự án

```
IA_1802/
├── backend/                       # Logic chính
│   ├── app.py                     # Flask entry point
│   ├── ai_analyzer.py             # AI orchestrator
│   ├── static_analyzer.py         # AST + regex pattern matching
│   ├── package_analyzer.py        # Parse requirements.txt / package.json
│   ├── cpe_extractor.py           # Map package → CPE 2.3
│   ├── cpe_semantic_matcher.py    # Fuzzy + semantic CPE matching
│   ├── nvd_api_v2.py              # NVD CVE API client + cache
│   ├── cwe_predictor.py           # SecBERT CWE classifier (15 cls)
│   ├── bert_severity_classifier.py # SecBERT severity (4 cls)
│   ├── xgboost_severity_classifier.py # XGBoost severity
│   ├── codebert_analyzer.py       # CodeBERT semantic code matching
│   ├── secbert_cve_scorer.py      # SecBERT scoring helpers
│   ├── severity_classifier.py     # Logistic baseline
│   ├── zero_shot_severity.py      # BART-MNLI baseline
│   ├── contextual_scorer.py       # Final risk score (CVSS + AI + asset)
│   └── ai/
│       ├── ember1390_encoder.py   # Extract 1390 PE features
│       ├── ember_behavioral_scorer.py
│       ├── relevance_scorer.py
│       └── severity_pipeline.py   # Ensemble BERT + XGBoost
├── frontend/                      # Flask templates + static
├── models/                        # Pre-trained checkpoints + reports
├── data/                          # Cache (NVD responses)
├── tests/                         # Integration + demo scripts
├── KNOWN/                         # Known-good baselines
└── requirements.txt
```

## Module 1 — Static Analyzer (`backend/static_analyzer.py`)

**Lý thuyết**:
- AST (Abstract Syntax Tree): cây cú pháp do parser Python sinh ra
- Pattern matching: regex để bắt anti-pattern (vd: `eval(`, `os.system(`, f-string SQL)
- CWE rules: mỗi rule map tới 1 CWE-ID

**Trọng yếu**:
- Đầu vào: file source code (Python/JS/Java)
- Đầu ra: list `Finding(line, cwe, severity, confidence, fix_hint)`
- Tốc độ: ~50 file/s (single thread)

**Câu hỏi hội đồng có thể hỏi**:
- "Tại sao không dùng Bandit / Semgrep?" → Có dùng làm baseline, nhưng ta tự viết để tích hợp với AI và giảng dạy được flow
- "Có false positive không?" → Có. Mitigate bằng cách kết hợp với CodeBERT semantic check

## Module 2 — Package Analyzer (`backend/package_analyzer.py`)

**Lý thuyết**:
- Manifest formats: `requirements.txt` (pip), `package.json` (npm), `pom.xml` (maven), `Gemfile` (ruby), `go.mod` (go)
- Version specifiers: PEP 440 (Python), SemVer (npm/Go), Maven version range
- Lockfile vs manifest

**Trọng yếu**:
- Parse 6 format khác nhau
- Normalize tên package (vd: `Django` ≡ `django`)
- Resolve version range thành phiên bản cụ thể

## Module 3 — CPE Extractor + Matcher (`backend/cpe_*.py`)

**Lý thuyết**:
- CPE 2.3 spec: `cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<lang>:...`
- Fuzzy matching: Levenshtein distance, RapidFuzz scorer
- Sentence embedding: encode tên product → vector, cosine similarity

**Pipeline**:
1. Lookup exact match trong CPE dictionary (~1.2M entries)
2. Nếu không có → RapidFuzz top-5 candidates (ratio ≥ 85)
3. Nếu vẫn ambiguous → semantic match với sentence-transformers
4. Vendor disambiguation bằng metadata bổ sung (license, homepage)

**Câu hỏi hội đồng**:
- "Làm sao biết `python` là python.org hay Anaconda?" → Dùng vendor field + license fingerprint
- "Tốc độ thế nào?" → 1.2M dict load 1 lần (~2s), mỗi query ~5ms

## Module 4 — NVD API (`backend/nvd_api_v2.py`)

**Lý thuyết**:
- NVD REST API v2: https://services.nvd.nist.gov/rest/json/cves/2.0
- Rate limit: 5 req/30s không key, 50 req/30s có API key
- CVSS v2 vs v3 vs v3.1: cấu trúc khác, metric khác

**Trọng yếu**:
- Cache layer (file-based JSON trong `data/cache/`)
- Retry với exponential backoff cho rate limit
- Parse `cvssMetricV31` → numeric score + vector

## Module 5 — Fine-tuned SecBERT — CWE (`backend/cwe_predictor.py`)

**Lý thuyết**:
- Transfer learning: pretrain trên text → finetune trên task downstream
- Classification head: linear layer 768 → 15 (số class)
- Cross-entropy loss với class weights (vì imbalanced)

**Trọng yếu**:
- Architecture: SecBERT base (12 layers) + Dropout(0.1) + Linear(768→15)
- Training: 8 epochs, early stopping patience=3
- Best F1: 85.58% (macro)
- 15 CWE classes: 119, 787, 125, 416, 476, 362, 94, 78, 190, 264, 200, 287, 798, 400, 843
- Loại bỏ: 9 web CWEs (79, 89...) + 5 low-discriminability classes

**Câu hỏi hội đồng**:
- "Tại sao chỉ 15 class?" → Vì PE-relevant. Web CWE cần dataset khác (CodeQL, SARD)
- "Imbalance handling?" → Class weights inversely proportional to support

## Module 6 — Fine-tuned SecBERT — Severity (`backend/bert_severity_classifier.py`)

**Lý thuyết**: Tương tự Module 5 nhưng task khác.
- Output: 4 class CRITICAL/HIGH/MEDIUM/LOW
- Best F1: 98.13% (macro) — cao hơn CWE vì task dễ hơn (4 class thay vì 15)

## Module 7 — XGBoost Severity (`backend/xgboost_severity_classifier.py`)

**Lý thuyết**:
- Gradient Boosted Trees: ensemble of weak learners (decision tree)
- TF-IDF: term frequency × inverse document frequency
- CVSS as numerical feature

**Trọng yếu**:
- Features: 5,000 TF-IDF + 8 CVSS = 5,008 dims
- Hyperparams: 200 trees, max_depth=6, lr=0.1
- F1: 86.08% — yếu hơn BERT nhưng cực nhanh (0.01ms/sample vs 106ms)

## Module 8 — Ensemble Pipeline (`backend/ai/severity_pipeline.py`)

**Lý thuyết**:
- Confidence-weighted voting: hard vote × weight + soft vote × weight × prob
- Calibration: model confidence ≠ probability thật

**Logic**:
```python
score[s] = sum( w_i * conf_i if pred_i==s else w_i * 0.25 * prob_i[s] )
```

- Weight BERT = 1.00 (model chính)
- Weight XGBoost = 0.85 (backup)
- Fallback: nếu thiếu model nào, dùng model còn lại

## Module 9 — EMBER 1390 Encoder (`backend/ai/ember1390_encoder.py`)

**Lý thuyết**:
- LIEF: cross-platform PE/ELF/MachO parser
- Static analysis features (không cần execute binary)
- Hashed features: dùng feature hashing trick (hash trick) để giảm dim

**Trọng yếu**: 14 nhóm × tổng 1390 features (xem `docs/ai_features.md`)

## Module 10 — CodeBERT Analyzer (`backend/codebert_analyzer.py`)

**Lý thuyết**:
- Pre-trained on 6 languages (Python, Java, JS, PHP, Ruby, Go)
- Bimodal: code + natural language
- Cosine similarity giữa code embedding và CVE description embedding

**Use case**: Khi static analyzer không bắt được pattern, dùng semantic similarity.

## Module 11 — Contextual Scorer (`backend/contextual_scorer.py`)

**Công thức**:
```
final_score = 0.40 * cvss_base
            + 0.25 * ai_severity_confidence * 10
            + 0.20 * exploit_availability_score
            + 0.15 * asset_criticality_score
```

**Asset criticality**:
- CRITICAL = 10, HIGH = 7, MEDIUM = 4, LOW = 1

**Exploit availability**:
- ExploitDB → +5
- Public PoC (GitHub) → +3
- CISA KEV catalog → +10 (đang bị khai thác)

## Module 12 — Backend Flask App (`backend/app.py`)

**Endpoints chính**:
- `POST /scan/file` — single file scan (kịch bản basic)
- `POST /scan/dependencies` — manifest scan (kịch bản trung cấp)
- `POST /scan/enterprise` — full pipeline (kịch bản nâng cao)
- `GET /api/cve/<id>` — CVE detail
- `GET /api/health` — health check

## Bảng phân công đọc tài liệu

| Member | Phải đọc kỹ | Phải hiểu sơ |
|--------|-------------|--------------|
| Member 1 (Lead) | Module 8, 11, 12 | Tất cả |
| Member 2 (CWE) | Module 5, 10 | Module 1, 11 |
| Member 3 (Malware) | Module 7, 9 | Module 6, 8 |
| Member 4 (Static + CPE) | Module 1, 3 | Module 2, 4 |
| Member 5 (Backend) | Module 2, 4, 12 | Module 11 |
| Member 6 (Frontend) | Module 12 (API) | Tất cả ở mức tổng quan |

## Ôn tập trước bảo vệ — Câu hỏi thường gặp

1. **Tại sao chọn SecBERT thay vì BERT?** → Đã pretrain trên security corpus
2. **Tại sao Ensemble?** → Giảm variance, BERT yếu với CVSS structured
3. **Imbalanced dataset xử lý sao?** → Class weights, không SMOTE (vì text data)
4. **Overfitting handling?** → Early stopping, dropout 0.1, validation split
5. **Sao không dùng GPT-4 / Claude?** → Cost, privacy, không deterministic, không thể fine-tune cho task hẹp
6. **Dataset có data leakage?** → Đã dedup theo CVE-ID, split stratified theo year
7. **Inference speed có production-ready?** → Ensemble ~107ms/sample, batch 32 → ~3.5s, đủ cho enterprise scan
