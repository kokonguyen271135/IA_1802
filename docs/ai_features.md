# Đặc trưng (Features) của các Model AI

> Slide này trả lời feedback của thầy: **"Phần AI thì chú ý tới các đặc trưng"**.
> Mỗi model đều phải nói rõ: input là gì, biến đổi như thế nào, đầu ra ra sao.

## 1. Tổng quan pipeline đặc trưng

```
INPUT                  FEATURE EXTRACTION              MODEL              OUTPUT
─────                  ───────────────────             ─────              ──────

CVE description    →   SecBERT tokenizer (256 tok)  →  BERT (768d)    →   Severity (4 cls)
                                                                          + CWE (15 cls)

PE binary file     →   LIEF parser → 1390 features  →  XGBoost        →   Malware/Benign

Source code        →   CodeBERT tokenizer            →  CodeBERT       →   Code embedding
                       (Python/Java/C/C++)              (768d)            → similarity vs CVE

Package list       →   Name normalize + version      →  CPE matcher   →    CPE 2.3 strings
                                                       (rapidfuzz)         → NVD lookup

CVSS vector        →   Parse AV/AC/PR/UI/S/C/I/A    →  XGBoost        →   Severity score
                       → 8 numerical features
```

## 2. Chi tiết từng nhóm đặc trưng

### 2.1. SecBERT (Severity & CWE Classification)

**Input**: CVE description text (tiếng Anh)

**Pre-processing**:
- Tokenize bằng SecBERT WordPiece tokenizer
- Max length = 256 tokens (truncate nếu dài hơn)
- Pad tokens [PAD] cho ngắn hơn
- Special tokens: [CLS] đầu, [SEP] cuối

**Feature representation**:
- Embedding layer: vocab × 768
- Output [CLS] token = vector 768 chiều biểu diễn toàn bộ description
- 12 transformer layers × 12 attention heads

**Tại sao chọn SecBERT thay vì BERT thường?**
- Pre-train trên **security corpus** (CVE descriptions, security blogs, advisory text)
- Vocab có sẵn các token bảo mật: `XSS`, `SQLi`, `RCE`, `CVE-`, `CWE-`, `CVSS`
- F1 cao hơn BERT-base ~3% trên task severity (98.13% vs 95.20%)

**File**: `backend/bert_severity_classifier.py`, `backend/cwe_predictor.py`

### 2.2. EMBER 1390 Features (Malware Detection)

**Input**: PE binary file (.exe, .dll)

**14 nhóm features (tổng 1,390 chiều)**:

| Group | Features | Mô tả |
|-------|----------|-------|
| ByteHistogram | 256 | Tần suất xuất hiện của 256 byte values |
| ByteEntropyHistogram | 256 | Shannon entropy theo từng vùng byte |
| StringExtractor | 104 | Thống kê string in được (length, count, paths, URLs, registry keys) |
| GeneralFileInfo | 10 | Kích thước, # exports, # imports, has_debug, has_signature... |
| HeaderFileInfo | 62 | PE header: timestamp, machine type, subsystem, characteristics |
| SectionInfo | 255 | Section names (.text, .data, .rdata...), sizes, entropy, virtualSize |
| ImportsInfo | 256 | DLL imports (hashed): kernel32.dll!CreateProcessA, ws2_32.dll!socket... |
| ExportsInfo | 128 | Tên exported functions (hashed) |
| DataDirectories | 15 | PE data directories (Export, Import, Resource, Exception...) |
| TLSInfo | 1 | Có TLS callback hay không (kỹ thuật anti-debug) |
| LoadConfigurationInfo | 5 | Load config: SecurityCookie, GuardCFCheck... |
| RichHeader | 16 | Microsoft Rich Header (linker fingerprint) |
| VersionInfo | 16 | CompanyName, ProductName (hashed) |
| DebugInfo | 10 | Debug directory entries |

**Pre-processing**:
- Parse PE bằng `lief` (Python binding của LIEF)
- Extract features bằng `ember.PEFeatureExtractor` (1390 dims)
- Không cần normalize (XGBoost robust với scale)

**File**: `backend/ai/ember1390_encoder.py`

**Đặc trưng quan trọng nhất** (theo SHAP analysis từ paper):
1. ByteHistogram[0x00] — số byte zero
2. SectionInfo entropy của `.text` section
3. Has debug info
4. Number of imports
5. File size

### 2.3. XGBoost CVE Severity (Hybrid Features)

**Input**: CVE description + CVSS vector

**5,008 features**:

| Group | # Features | Mô tả |
|-------|-----------|-------|
| TF-IDF unigram + bigram | 5,000 | `max_features=5000`, `ngram_range=(1,2)`, `stop_words='english'` |
| CVSS Attack Vector (AV) | 1 | NETWORK=4, ADJACENT=3, LOCAL=2, PHYSICAL=1 |
| CVSS Attack Complexity (AC) | 1 | LOW=2, HIGH=1 |
| CVSS Privileges Required (PR) | 1 | NONE=3, LOW=2, HIGH=1 |
| CVSS User Interaction (UI) | 1 | NONE=2, REQUIRED=1 |
| CVSS Scope (S) | 1 | UNCHANGED=1, CHANGED=2 |
| CVSS Confidentiality (C) | 1 | HIGH=3, LOW=2, NONE=1 |
| CVSS Integrity (I) | 1 | HIGH=3, LOW=2, NONE=1 |
| CVSS Availability (A) | 1 | HIGH=3, LOW=2, NONE=1 |

**Tại sao kết hợp TF-IDF + CVSS?**
- TF-IDF bắt **ngữ nghĩa surface** (từ "remote code execution" → CRITICAL)
- CVSS vector bắt **đặc trưng có cấu trúc** (AV:N + AC:L + PR:N → CRITICAL)
- Kết hợp 2 nguồn → robust hơn khi description thiếu thông tin

**File**: `backend/xgboost_severity_classifier.py`

### 2.4. CodeBERT (Code Vulnerability Analysis)

**Input**: Source code snippet (Python, Java, C, C++, JS)

**Pre-processing**:
- Tokenize bằng CodeBERT BPE tokenizer (vocab 50k)
- Max length = 512 tokens
- Concat: `<CLS> code_tokens <SEP>`

**Features**:
- 12-layer transformer, 768 dims
- Output: cosine similarity giữa code và CVE description
- Threshold = 0.65 → flag đoạn code khả nghi

**File**: `backend/codebert_analyzer.py`

### 2.5. CPE Semantic Matcher (Package Identification)

**Input**: Tên package + version (vd: `Django==2.0.1`)

**Feature pipeline**:
1. **Lexical match (rapidfuzz)**: Levenshtein ratio ≥ 85
2. **Semantic match (sentence-transformers)**: 
   - Encode tên package → vector 384 dims (`all-MiniLM-L6-v2`)
   - Cosine similarity với CPE dictionary
3. **Version match**: Parse semver, so sánh range trong CPE 2.3
4. **Vendor disambiguation**: Khi cùng tên (vd: `python` của python.org vs Anaconda)

**File**: `backend/cpe_semantic_matcher.py`, `backend/cpe_extractor.py`

### 2.6. Contextual Scorer (Final Risk Score)

Đặc trưng cuối cùng tổng hợp 4 nguồn:

| Feature | Weight | Mô tả |
|---------|--------|-------|
| CVSS base score | 0.40 | Từ NVD (0.0–10.0) |
| AI severity confidence | 0.25 | Từ Ensemble (0.0–1.0) |
| Exploit availability | 0.20 | Có trong ExploitDB? Có public PoC? |
| Asset criticality | 0.15 | User-defined: Critical/High/Medium/Low |

**Output**: Final risk score (0–10) + ưu tiên patch

**File**: `backend/contextual_scorer.py`

## 3. Slide minh hoạ — Feature Importance

Từ SHAP analysis (chạy trên test set):

```
TOP 10 FEATURES (XGBoost Severity)
══════════════════════════════════════
1. CVSS Attack Vector (AV)        ████████████ 24.3%
2. CVSS Confidentiality (C)       ██████████   18.7%
3. tf-idf "remote"                ████████      9.2%
4. CVSS Privileges Required (PR)  ███████       7.8%
5. tf-idf "execution"             ██████        6.1%
6. CVSS Integrity (I)             █████         5.3%
7. tf-idf "denial of service"     ████          4.5%
8. CVSS Availability (A)          ████          4.1%
9. tf-idf "buffer overflow"       ███           3.6%
10. tf-idf "authentication"       ███           3.2%
```

→ **Insight**: CVSS vector đóng góp ~60% feature importance — chứng tỏ structured data quan trọng hơn text alone.

## 4. Đặc trưng nào KHÔNG được dùng (và vì sao)

| Feature đã thử | Lý do loại |
|----------------|------------|
| Word2Vec embedding | Kém SecBERT 5–7% F1 |
| Character n-gram | Tăng dim không hiệu quả, slow training |
| Vendor name one-hot | Sparse quá, overfit |
| Year of CVE | Data leakage (model học theo năm) |
| CWE label as feature | Circular: ta cũng đang predict CWE |
