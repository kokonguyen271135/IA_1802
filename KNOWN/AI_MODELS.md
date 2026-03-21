# Các Model AI trong Hệ Thống

---

## Tổng Quan

Hệ thống dùng 5 model AI/ML, mỗi model đảm nhận một nhiệm vụ riêng biệt trong pipeline.

| Model | Loại | File | Nhiệm vụ |
|--|--|--|--|
| SecBERT Severity | Fine-tuned Transformer | `models/bert_severity/` | Phân loại mức độ nguy hiểm CVE |
| XGBoost Severity | Gradient Boosting | `models/xgboost_severity.pkl` | Phân loại severity (backup) |
| TF-IDF + LogReg | Statistical | `models/severity_clf.pkl` | Phân loại severity (baseline) |
| SecBERT CWE | Fine-tuned Transformer | `models/bert_cwe/` | Dự đoán loại lỗ hổng từ PE |
| FAISS CPE Index | Vector Index | `models/cpe_index.faiss` | Tìm CPE bằng semantic search |

Ngoài ra: **Claude API** (claude-sonnet-4-6) cho CPE matching và risk narrative.

---

## Model 1 — SecBERT Severity Classifier

**File model:** `models/bert_severity/`
**Code:** `backend/ai/severity_pipeline.py`
**Training script:** `untils/finetune_bert_severity.py`

### Nhiệm vụ

Phân loại mức độ nguy hiểm của một CVE thành 4 nhãn: `CRITICAL / HIGH / MEDIUM / LOW`.

### Kiến trúc

- **Base model:** `jackaduma/SecBERT` — BERT được pre-train trên corpus bảo mật (CVE, security advisories, threat intel)
- **Architecture:** BERT encoder (12 layers, 768-dim, 12 attention heads) + linear classification head (768 → 4)
- **Input:** Text mô tả CVE (chuỗi tối đa 512 tokens)
- **Output:** Probability distribution over 4 classes

### Cách hoạt động

```
CVE description (text)
    │
    ▼
Tokenizer: WordPiece tokenization → input_ids, attention_mask
    │
    ▼
SecBERT encoder:
    - 12 transformer blocks
    - Self-attention: học mối quan hệ giữa từ trong ngữ cảnh bảo mật
    - [CLS] token → 768-dim embedding đại diện cho toàn bộ mô tả
    │
    ▼
Linear head: 768 → 4 (logits)
    │
    ▼
Softmax → probabilities [CRITICAL, HIGH, MEDIUM, LOW]
    │
    ▼
argmax → predicted severity
```

### Training

- **Dữ liệu:** CVE descriptions từ NVD database với nhãn severity gốc
- **File data:** `data/training/cve_severity_train.csv`
- **Accuracy:** 97.94%
- **Trọng số trong ensemble:** 1.00 (cao nhất)

---

## Model 2 — XGBoost Severity Classifier

**File model:** `models/xgboost_severity.pkl`
**Training script:** `untils/train_xgboost_severity.py`

### Nhiệm vụ

Phân loại severity CVE, bổ sung cho SecBERT bằng cách khai thác thêm CVSS metrics (dữ liệu có cấu trúc).

### Kiến trúc

- **Algorithm:** XGBoost (gradient boosted decision trees)
- **Input features:** TF-IDF vector của description + CVSS numeric features
  - `cvssV3_baseScore` (0–10)
  - `exploitabilityScore`
  - `impactScore`
  - `attackVector` (one-hot encoded)
  - `privilegesRequired`
  - `userInteraction`
- **Output:** CRITICAL / HIGH / MEDIUM / LOW

### Cách hoạt động

```
CVE description + CVSS metrics
    │
    ▼
TF-IDF vectorizer: description → sparse vector (n_features từ)
Numeric scaler: CVSS metrics → normalized floats
    │
    ▼
Concatenate: [tfidf_vector | cvss_features]
    │
    ▼
XGBoost forest:
    - Nhiều decision trees, mỗi cây sửa lỗi của cây trước
    - Gradient boosting: tối ưu cross-entropy loss
    │
    ▼
Softmax → severity label
```

### Điểm mạnh

Khai thác được cả ngữ nghĩa văn bản lẫn điểm số kỹ thuật CVSS — trong khi BERT chỉ xử lý văn bản.

- **Accuracy:** 92–96%
- **Trọng số trong ensemble:** 0.85

---

## Model 3 — TF-IDF + Logistic Regression (Baseline)

**File model:** `models/severity_clf.pkl`
**Training script:** `untils/train_severity_model.py`

### Nhiệm vụ

Phân loại severity CVE — model đơn giản nhất, dùng làm baseline và fallback khi 2 model trên chưa load xong.

### Cách hoạt động

```
CVE description
    │
    ▼
TF-IDF Vectorizer:
    - Tokenize → n-gram (1,2)
    - Tính TF × IDF cho mỗi token
    - Output: sparse vector chiều cao (vocabulary size)
    │
    ▼
Logistic Regression:
    - Học ranh giới tuyến tính phân tách 4 lớp
    - Predict via: P(class) = sigmoid(W·x + b)
    │
    ▼
Severity label
```

- **Accuracy:** 86.83%
- **Trọng số trong ensemble:** 0.70

---

## Cách Ensemble 3 Model Severity

**File:** `backend/ai/severity_pipeline.py`

3 model chạy song song, kết quả được gộp bằng weighted voting:

```
weighted_probs = (bert_probs × 1.00 + xgb_probs × 0.85 + tfidf_probs × 0.70)
              / (1.00 + 0.85 + 0.70)

predicted_severity = argmax(weighted_probs)
confidence         = max(weighted_probs)
```

Kết quả cuối chứa cả 3 dự đoán riêng lẻ để người dùng có thể kiểm tra từng model.

---

## Model 4 — SecBERT CWE Classifier

**File model:** `models/bert_cwe/`
**Code:** `backend/cwe_predictor.py`
**Training script:** `untils/train_cwe_classifier.py`

### Nhiệm vụ

Dự đoán CWE (Common Weakness Enumeration) từ mô tả hành vi PE binary. Đây là trái tim của **Hướng 3**.

### Input đặc biệt

Input không phải CVE description mà là **behavior profile** được xây dựng từ PE analysis:

```python
# Ví dụ profile được sinh ra:
"This Windows executable imports APIs from the following behavior categories:
Anti-Debugging, Process Injection, Dynamic Loading, Keylogging.
The file contains process injection capabilities using: SuspendThread,
ResumeThread, VirtualProtect, MapViewOfFile. This indicates potential memory
manipulation and code injection into other processes. The file implements
anti-debugging and sandbox evasion techniques (IsDebuggerPresent).
The file hooks keyboard and window events for keylogging and credential
harvesting. Contains 22 hardcoded URLs suggesting C2 communication.
Has 1 high-entropy section(s), indicating packing or obfuscation."
```

### Cách hoạt động

```
PE analysis result
    │
    ▼
build_profile_text():
    - Liệt kê behavior categories từ imports
    - Mô tả cụ thể từng kỹ thuật (process injection, keylogging, ...)
    - Thêm thống kê (URL count, IP count, entropy)
    │
    ▼
SecBERT tokenizer + encoder (giống model severity)
    │
    ▼
Classification head: 768 → N_CWE_classes
    │
    ▼
Top-5 CWE predictions + confidence scores
```

### Fallback: Rule-based

Nếu model chưa được train hoặc không có GPU, hệ thống dùng bảng ánh xạ cứng:

```python
BEHAVIOR_TO_CWE = {
    'Process Injection': [('CWE-94', 0.95), ('CWE-269', 0.70)],
    'Keylogging':        [('CWE-200', 0.85), ('CWE-312', 0.65)],
    'Network':           [('CWE-918', 0.70), ('CWE-319', 0.65)],
    ...
}
```

---

## Model 5 — FAISS CPE Semantic Index

**File model:** `models/cpe_index.faiss`
**Code:** `backend/cpe_semantic_matcher.py`
**Build script:** `untils/build_cpe_index.py`

### Nhiệm vụ

Khi tên file/phần mềm không khớp rule-based và Claude AI cũng không chắc, FAISS tìm CPE gần nhất trong không gian vector.

### Cách hoạt động

**Lúc build index:**
```
Danh sách tất cả CPE (vendor:product) từ NVD
    │
    ▼
sentence-transformers/all-MiniLM-L6-v2:
    encode mỗi CPE string → 384-dim float32 vector
    │
    ▼
FAISS IndexFlatIP (inner product = cosine similarity):
    Lưu tất cả vectors vào flat index
    Ghi ra models/cpe_index.faiss
```

**Lúc query:**
```
Tên phần mềm cần tìm (vd: "WinRAR 6.21")
    │
    ▼
sentence-transformers.encode(query) → query_vector
    │
    ▼
faiss.search(query_vector, k=5):
    Tìm 5 CPE gần nhất (cosine similarity cao nhất)
    │
    ▼
Lọc theo threshold similarity >= 0.50
    │
    ▼
Trả về best match CPE + confidence score
```

---

## Claude API (claude-sonnet-4-6)

**Code:** `backend/ai_analyzer.py`
**API:** Anthropic API

### Nhiệm vụ 1: CPE Matching

Khi rule-based thất bại, Claude được hỏi:
```
"Xác định vendor và product CPE cho file: {filename}
 VersionInfo: {product_name}, {company}, {description}
 Trả về JSON: {vendor, product, confidence}"
```

### Nhiệm vụ 2: Risk Narrative

Claude tổng hợp kết quả phân tích thành đoạn văn mô tả rủi ro cho người đọc:
```
"Phân tích CVE sau cho {software_name}:
 Top CVEs: {cve_list}
 Thống kê: {statistics}
 Viết executive summary về rủi ro bảo mật."
```

Output: Đoạn văn tiếng Anh mô tả chi tiết các lỗ hổng nguy hiểm nhất.

---

## SecBERT Relevance Scorer

**Code:** `backend/ai/relevance_scorer.py`, `backend/secbert_cve_scorer.py`
**Model:** `jackaduma/SecBERT` (không fine-tune, dùng pretrained embeddings)

### Nhiệm vụ

Tính mức độ liên quan giữa CVE và PE file cụ thể — không phải hỏi "CVE này nguy hiểm không?" mà hỏi "CVE này có liên quan đến FILE NÀY không?".

### Cách hoạt động

```
PE behavior profile text  +  CVE description
    │                             │
    ▼                             ▼
SecBERT.encode()          SecBERT.encode()
    │                             │
768-dim vector            768-dim vector
    │                             │
    └─────── cosine_similarity ───┘
                    │
              score ∈ [0, 1]
                    │
         map to: CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
```

**Điểm quan trọng:** Hai file khác nhau scan cùng phiên bản Windows sẽ nhận được relevance score khác nhau cho cùng 1 CVE, vì SecBERT so sánh behavior profile (khác nhau) với CVE description.

---

## Tóm Tắt Pipeline Tổng Hợp

```
PE File
  │
  ├─[Static Analysis]────────────────────────────────────────────────┐
  │                                                                   │
  ├─[CPE Resolution]                                                  │
  │   Rule → Claude API → FAISS                                       │
  │                                                                   │
  ├─[NVD API] → Danh sách CVE                                        │
  │                                                                   ▼
  │                                             [CWE Predictor] ← Hướng 3
  │                                             SecBERT CWE / Rule-based
  │                                                   │
  │                                               NVD by CWE
  │                                                   │
  └─────────────────── CVE List ──────────────────────┘
                            │
                    [Severity Pipeline]
                    SecBERT + XGBoost + TF-IDF
                    Weighted ensemble voting
                            │
                    [Relevance Scorer]
                    SecBERT cosine similarity
                    PE profile ↔ CVE description
                            │
                    [Risk Score Calculator]
                    Harmonic weighted rel (80%)
                    + CVSS avg (20%)
                            │
                    [Claude Narrative]
                    Executive risk summary
                            │
                         JSON Response
```
