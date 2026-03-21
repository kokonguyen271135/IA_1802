# Thuật Toán Của Hệ Thống

---

## 1. Thuật Toán Tính AI Risk Score

**File:** `backend/app.py` — hàm `_compute_ai_risk_score()`

**Mục tiêu:** Tổng hợp toàn bộ CVE thành 1 con số (0–100) và level (CLEAN / LOW / MEDIUM / HIGH / CRITICAL).

### Bước 1: Harmonic Weighted Relevance

Lấy top-5 CVE có relevance score cao nhất, tính trung bình có trọng số harmonic:

```
top5 = sorted(relevance_scores, desc)[:5]
harmonic_max = 1/1 + 1/2 + 1/3 + 1/4 + 1/5 = 2.283
raw_weighted = Σ(score[i] / (i+1))  với i = 0..4
weighted_rel = raw_weighted / harmonic_max  ∈ [0, 1]
```

**Lý do dùng harmonic:** CVE quan trọng nhất được nhân hệ số lớn hơn (1.0), CVE thứ 5 nhân hệ số nhỏ (0.2). Chia cho `harmonic_max` để normalize về [0,1], tránh bão hòa sai.

### Bước 2: Tính 2 thành phần

```
cvss_component      = (avg_cvss / 10.0) × 20   [max 20 điểm — bonus]
relevance_component = weighted_rel × 80          [max 80 điểm — quyết định level]
```

**Lý do phân chia 20/80:** CVSS là điểm kỹ thuật chung, không phản ánh mức độ liên quan thực sự. Semantic relevance mới là yếu tố quyết định level.

### Bước 3: Phân loại Level

```
score = min(100, round(cvss_component + relevance_component))

score ≥ 70  →  CRITICAL
score ≥ 40  →  HIGH
score ≥ 20  →  MEDIUM
score > 0   →  LOW
score = 0   →  CLEAN
```

**Ví dụ thực tế (WinRAR, 4 MEDIUM + 3 LOW, CVSS avg 7.7):**
```
weighted_rel = 0.483
cvss_component = (7.7/10) × 20 = 15.4 pts
rel_component  = 0.483 × 80   = 38.6 pts
score = round(54.0) = 54  →  HIGH
```

---

## 2. Thuật Toán Dự Đoán CWE (Hướng 3)

**File:** `backend/cwe_predictor.py` — hàm `predict_cwe()`

### Nguồn 1: API Behavior Categories

```
Với mỗi behavior_category trong PE imports:
    entries = danh sách API thuộc category đó
    scale   = min(1.0, 0.70 + len(entries) × 0.04)
              [nhiều API hơn = độ tin cậy cao hơn]

    Với mỗi (CWE, base_conf) trong BEHAVIOR_TO_CWE[category]:
        confidence = min(1.0, base_conf × scale)
```

**Bảng ánh xạ chính:**

| Behavior Category | CWE | Base Conf |
|--|--|--|
| Process Injection | CWE-94 (Code Injection) | 0.95 |
| Code Execution | CWE-78 (OS Command Inj) | 0.95 |
| Keylogging | CWE-200 (Info Exposure) | 0.85 |
| Network | CWE-918 (SSRF) | 0.70 |
| Registry | CWE-732 (Permissions) | 0.80 |
| Anti-Debugging | CWE-693 (Protection Failure) | 0.75 |

### Nguồn 2: String Patterns

```
Với mỗi string_pattern phát hiện trong PE:
    count = số lần xuất hiện
    Với mỗi (CWE, base_conf) trong STRING_TO_CWE[pattern]:
        confidence = min(1.0, base_conf + min(count-1, 5) × 0.02)
```

**Bảng ánh xạ:**

| Pattern | CWE | Lý do |
|--|--|--|
| Suspicious commands | CWE-78, CWE-77 | Command injection |
| IP addresses | CWE-918 | C2 SSRF indicator |
| URLs | CWE-494 | Unsafe download |
| Base64 strings | CWE-506 | Embedded payload |

### Nguồn 3: PE Section Entropy

```
high_entropy_sections = [s for s in sections if s.entropy > 7.0]
confidence = min(0.95, 0.60 + len(high_entropy_sections) × 0.10)
→ CWE-506 (Embedded Malicious Code)
```

### Tổng hợp và Boost

```
# Merge: lấy max confidence nếu cùng CWE
merged[cwe] = max(existing_conf, new_conf)

# Boost 10% nếu PE có risk_level = CRITICAL
if risk_level == 'CRITICAL':
    merged[cwe] = min(1.0, conf × 1.10)

# Label từ confidence
conf ≥ 0.80  →  HIGH
conf ≥ 0.55  →  MEDIUM
conf < 0.55  →  LOW

# Trả về top-5 CWE đã sort theo confidence
```

---

## 3. Thuật Toán CPE Resolution (3 Lớp)

**File:** `backend/app.py` — hàm `_resolve_cpe()`

```
Lớp 1 — Rule-based:
    Đọc PE VersionInfo (ProductName, FileDescription, CompanyName)
    So khớp với KNOWN_PATTERNS dictionary
    Nếu khớp confidence >= 'high' → dùng CPE này

Lớp 2 — Claude AI (nếu Lớp 1 thất bại):
    Gửi metadata lên Claude API
    Claude trả về: {vendor, product, confidence}
    Nếu confidence in ['high', 'medium'] → build CPE và dùng

Lớp 3 — FAISS Semantic (nếu cả 2 lớp trên thất bại):
    Encode tên file bằng sentence-transformers
    Tìm K-nearest neighbors trong CPE index (cosine similarity)
    Nếu similarity >= 0.50 và confidence in ['high', 'medium'] → dùng

Nếu cả 3 thất bại:
    → Chuyển sang Hướng 3 (CWE prediction)
    hoặc fallback sang keyword search
```

---

## 4. Thuật Toán Ensemble Severity Classification

**File:** `backend/ai/severity_pipeline.py`

### Thu thập prediction từ 3 models

```
predictions = []

if bert_available:
    bert_result = bert_model.predict(cve_description)
    predictions.append((bert_result, weight=1.00))

if xgboost_available:
    features = [description_tfidf_vector, cvss_base_score,
                exploitability_score, impact_score, ...]
    xgb_result = xgb_model.predict(features)
    predictions.append((xgb_result, weight=0.85))

if tfidf_available:
    tfidf_result = lr_model.predict(tfidf_vectorizer.transform(description))
    predictions.append((tfidf_result, weight=0.70))
```

### Weighted Voting

```
# Mỗi model trả về probability distribution [CRITICAL, HIGH, MEDIUM, LOW]
weighted_probs = Σ(prob_vector[i] × weight[i]) / Σ(weight[i])

# Softmax để normalize
final_probs = softmax(weighted_probs)

# Kết quả cuối
predicted_severity = argmax(final_probs)
confidence = max(final_probs)
```

---

## 5. Thuật Toán Tính Relevance Score (SecBERT)

**File:** `backend/ai/relevance_scorer.py` và `backend/secbert_cve_scorer.py`

### Bước 1: Xây dựng Behavior Profile

```
profile = "This PE imports {api_list} from {categories}."
        + "This indicates {behavior_description}."
        + [nếu có keylogging] "The file hooks keyboard events for credential harvesting."
        + [nếu entropy cao] "Has {n} high-entropy sections indicating packing."
        + "Contains {n} hardcoded URLs/IPs suggesting C2 communication."
```

### Bước 2: Encode và tính Cosine Similarity

```
profile_embedding = SecBERT.encode(profile)           # vector 768 chiều
cve_embeddings    = SecBERT.encode([cve.description]) # vector 768 chiều

cosine_sim = dot(profile_emb, cve_emb) / (|profile_emb| × |cve_emb|)
           ∈ [-1, 1]  (thực tế thường trong [0, 1] với SecBERT)
```

### Bước 3: Map sang Label

```
similarity ≥ 0.72  →  CRITICAL
similarity ≥ 0.55  →  HIGH
similarity ≥ 0.38  →  MEDIUM
similarity ≥ 0.22  →  LOW
otherwise          →  MINIMAL
```

---

## 6. Thuật Toán Lọc CVE trong Hướng 3

**File:** `backend/cwe_predictor.py` — hàm `_filter_relevant_cves()`

```
Với mỗi CVE tìm được từ NVD by CWE:
    score = 0

    # Từ khóa Windows/native → điểm dương
    score += count_matches(description, WINDOWS_KEYWORDS) × (+2)

    # Từ khóa hành vi active → điểm dương
    score += count_matches(description, ACTIVE_BEHAVIOR_KEYWORDS) × (+1)

    # CPE platform Windows → điểm dương
    if 'cpe:2.3:o:microsoft:windows' in cpe_list:
        score += 3

    # Web-only terms → điểm âm (PE binary không phải web server)
    score -= count_matches(description, WEB_ONLY_TERMS) × (-2)

    if score < 0:
        → loại bỏ CVE này
    else:
        → giữ lại, sort theo (score DESC, cwe_conf DESC, cvss DESC)
```

---

## Tóm Tắt Các Thuật Toán

| Thuật toán | Input | Output | Độ phức tạp |
|--|--|--|--|
| Harmonic Risk Score | Relevance scores + CVSS | Score 0-100 + Level | O(n log n) |
| CWE Prediction | PE behavior features | Top-5 CWE + confidence | O(n) |
| CPE Resolution | PE metadata | CPE string | O(1) → O(k) → O(n) |
| Ensemble Severity | CVE description | CRITICAL/HIGH/MEDIUM/LOW | O(1) per model |
| SecBERT Relevance | PE profile + CVE desc | Cosine similarity | O(n × d) |
| CVE Filtering | CVE list + PE context | Filtered + sorted list | O(n) |
