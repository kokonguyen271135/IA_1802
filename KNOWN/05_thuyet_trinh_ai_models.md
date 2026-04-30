# Nội dung thuyết trình — Phần AI Models

---

## Slide 1 — Tổng quan AI Pipeline

**Tiêu đề:** Kiến trúc AI trong hệ thống

**Nội dung:**

> Hệ thống tích hợp **3 mô hình AI độc lập**, mỗi mô hình giải quyết một bài toán khác nhau trong quy trình đánh giá lỗ hổng.

```
┌─────────────────────────────────────────────────────┐
│                   PE File Upload                    │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │   [1] EMBER XGBoost     │  ← Malware Detection
          │   1.390 static features │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │  [2] NVD API Query      │  ← Lấy danh sách CVE
          │  by CPE / CWE           │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │  [3] SecBERT Relevance  │  ← Lọc CVE theo behavior
          │  Semantic Similarity    │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │  [4] BERT + XGBoost     │  ← Phân loại mức độ nguy hiểm
          │  Ensemble Severity      │
          └─────────────────────────┘
```

**Điểm nói thêm:**
- Mỗi mô hình có thể hoạt động độc lập — hệ thống vẫn chạy nếu một mô hình không khả dụng (graceful degradation)
- Thứ tự chạy có chủ đích: phát hiện malware trước → lọc relevance → phân loại severity

---

## Slide 2 — Mô hình 1: EMBER XGBoost

**Tiêu đề:** Phát hiện Malware bằng Machine Learning

**Vấn đề cần giải quyết:**
> Trước khi phân tích CVE, cần biết file có thực sự nguy hiểm không. Antivirus truyền thống dựa trên signature — bỏ sót malware mới.

**Giải pháp — EMBER XGBoost:**

| Thành phần | Chi tiết |
|-----------|---------|
| Dataset | EMBER 2017 (Elastic) — 600K train + 200K test |
| Phương pháp | XGBoost trên 1.390 static features |
| Input | PE binary (headers, sections, imports, exports, strings) |
| Output | Xác suất malware: 0.0 → 1.0 |

**1.390 features trích xuất từ:**
- PE headers (timestamp, checksum, DLL characteristics...)
- Sections (entropy, size, tên section...)
- Import table (tên DLL, function calls...)
- Export table
- Strings (URLs, paths, registry keys...)
- General info (file size, virtual size...)

**Kết quả đánh giá:**

| Metric | Giá trị |
|--------|--------|
| ROC-AUC | **0.9994** |
| F1-score | **0.9906** |
| Accuracy | **98.99%** |
| Threshold | 0.51 |

**Phân ngưỡng kết quả:**
```
≥ 0.80  →  CRITICAL  (MALWARE)
≥ 0.51  →  HIGH      (MALWARE)
≥ 0.35  →  MEDIUM    (SUSPICIOUS)
≥ 0.15  →  LOW       (SUSPICIOUS)
< 0.15  →  CLEAN     (BENIGN)
```

**Điểm nói thêm:**
- EMBER là dataset chuẩn công nghiệp của Elastic Security
- AUC 0.9994 ≈ gần như hoàn hảo — 99.94% khả năng phân biệt malware/benign
- Không cần signature, không cần internet, inference < 50ms

---

## Slide 3 — Mô hình 2: SecBERT Semantic Relevance

**Tiêu đề:** Đánh giá Relevance bằng Semantic Similarity — Điểm mới của đề tài

**Vấn đề cần giải quyết:**
> Tool thông thường tìm CVE theo CPE → trả về **tất cả CVE** của phần mềm đó. Không phân biệt CVE nào thực sự liên quan đến hành vi cụ thể của file.

**Ví dụ:**
```
Notepad++ v8.6  →  NVD trả về 47 CVEs
→ Có CVE về buffer overflow, CVE về DLL hijacking,
  CVE về XSS trong plugin...

→ File cụ thể đang phân tích chỉ có hành vi:
  Process Injection + Network Communication
→ Chỉ CVE về buffer overflow mới thực sự liên quan!
```

**Giải pháp — SecBERT Semantic Scoring:**

**Bước 1:** Chuyển behavior của PE thành văn bản tự nhiên

```
"This Windows executable imports APIs from Process Injection,
Network Communication. The file contains process injection
capabilities using VirtualAllocEx, WriteProcessMemory,
CreateRemoteThread. The file communicates over the network
using socket APIs (connect, send, recv), suggesting remote
access or data exfiltration. Has 2 high-entropy sections,
indicating packing or encryption."
```

**Bước 2:** Encode bằng SecBERT → vector 768 chiều

**Bước 3:** Encode mô tả từng CVE → vector 768 chiều

**Bước 4:** Tính cosine similarity

```
similarity = cos(PE_vector, CVE_vector)
           = (PE · CVE) / (|PE| × |CVE|)
```

**Mapping score → nhãn:**

| Cosine Similarity | Nhãn |
|------------------|------|
| ≥ 0.72 | CRITICAL |
| ≥ 0.55 | HIGH |
| ≥ 0.50 | MEDIUM |
| ≥ 0.30 | LOW |
| < 0.30 | MINIMAL |

**Tại sao dùng SecBERT thay vì BERT thông thường?**
- SecBERT được pre-trained trên corpus **cybersecurity** (NVD, exploitdb, security blogs)
- Hiểu ngữ nghĩa domain: *"heap boundary check"* ≈ *"buffer overflow"*
- BERT thông thường không nắm được sắc thái kỹ thuật bảo mật

**So sánh:**

| Phương pháp | Khả năng |
|------------|---------|
| Keyword matching | Chỉ match từ chính xác |
| BERT thông thường | Hiểu ngữ nghĩa chung |
| **SecBERT** | **Hiểu ngữ nghĩa domain bảo mật** |

---

## Slide 4 — Mô hình 3: Ensemble Severity Classification

**Tiêu đề:** Phân loại Mức độ Nguy hiểm CVE — Ensemble BERT + XGBoost

**Vấn đề cần giải quyết:**
> CVSS score có sẵn nhưng chỉ là điểm thô — không phân loại ngữ nghĩa. Cần mô hình hiểu **nội dung mô tả** để phân loại CRITICAL / HIGH / MEDIUM / LOW chính xác hơn.

---

### Model A — Fine-tuned SecBERT

**Kiến trúc:**
```
Input: CVE description + CVSS vector string
         ↓
    Tokenizer (max 256 tokens)
    Format: "<description> [SEP] AV_N AC_L PR_N UI_N ..."
         ↓
    SecBERT Transformer Layers (768-dim hidden)
         ↓
    [CLS] token → Linear head → Softmax (4 classes)
         ↓
Output: {CRITICAL: 0.82, HIGH: 0.12, MEDIUM: 0.04, LOW: 0.02}
```

**Fine-tuning:**
- Base: `jackaduma/SecBERT`
- Dataset: NVD CVE descriptions có label severity
- Training: supervised classification, 4 classes
- **Accuracy: 97.94%**

---

### Model B — XGBoost + TF-IDF + CVSS Features

**Feature engineering:**

```
Text features (5.000 dims):
  TF-IDF(description, unigram+bigram, sublinear_tf=True)

CVSS numerical features (8 dims):
  AV: Network=3, Adjacent=2, Local=1, Physical=0
  AC: Low=1, High=0
  PR: None=2, Low=1, High=0
  UI: None=1, Required=0
  S:  Changed=1, Unchanged=0
  C/I/A: High=2, Medium=1, Low/None=0

→ Total: 5.008 features
```

**XGBoost config:**
```
n_estimators=200, max_depth=6
learning_rate=0.1, subsample=0.8
```

**Accuracy: 92–96%**

---

### Ensemble Voting Logic

```python
WEIGHTS = { 'bert': 1.00, 'xgboost': 0.85 }

for model in [bert, xgboost]:
    weight = WEIGHTS[model]
    conf   = model.confidence

    # Hard vote: đặt cược toàn bộ vào dự đoán chính
    score[predicted] += weight × conf

    # Soft vote: phân phối một phần theo probability vector
    for severity, prob in model.probabilities:
        score[severity] += weight × 0.25 × prob

→ Normalize → chọn severity có score cao nhất
```

**Ví dụ thực tế:**
```
CVE-2024-1234: "Remote code execution via heap overflow..."
CVSS: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

BERT    → CRITICAL (conf: 0.94)
XGBoost → CRITICAL (conf: 0.88)

Ensemble score:
  CRITICAL = 1.00×0.94 + 0.85×0.88 + (soft votes) = 1.69
  HIGH     = (soft votes only)                      = 0.08
  → Kết quả: CRITICAL (confidence: 0.95)
```

---

## Slide 5 — So sánh & Kết quả tổng hợp

**Tiêu đề:** Đánh giá hiệu suất các mô hình AI

| Mô hình | Nhiệm vụ | Metric chính | Giá trị |
|---------|----------|-------------|--------|
| EMBER XGBoost | Malware detection | ROC-AUC | **0.9994** |
| EMBER XGBoost | Malware detection | F1-score | **0.9906** |
| Fine-tuned BERT | Severity classification | Accuracy | **97.94%** |
| XGBoost + CVSS | Severity classification | Accuracy | **92–96%** |
| Ensemble | Severity classification | Accuracy | **≥ 97.94%** |
| SecBERT CWE | CWE prediction | Accuracy | **86.59%** |

**Điểm mạnh so với tool truyền thống:**

| | Tool truyền thống | Hệ thống này |
|---|---|---|
| Malware detection | Signature-based | ML trên 1.390 features |
| CVE relevance | Keyword match | Semantic similarity (SecBERT) |
| Severity | Chỉ dùng CVSS score | Fine-tuned BERT ensemble |
| File không rõ nguồn gốc | Không hỗ trợ | CWE prediction từ behavior |

---

## Câu hỏi hội đồng — Chuẩn bị sẵn

**"Tại sao dùng ensemble thay vì chỉ dùng BERT (đã 97.94%)?"**
> XGBoost bổ sung thông tin cấu trúc từ CVSS vector — thứ BERT không nắm tốt bằng (AV:N/AC:L... là numerical, không phải ngôn ngữ tự nhiên). Ensemble giảm variance, tăng robustness khi một mô hình không chắc chắn.

**"SecBERT relevance score có được validate không?"**
> Cosine similarity trong không gian embedding là metric chuẩn của NLP. Threshold (0.72 / 0.55 / 0.50 / 0.30) được chọn dựa trên domain knowledge bảo mật và thực nghiệm trên tập CVE thực tế.

**"EMBER 2017 có còn phù hợp năm 2024–2025 không?"**
> Dataset vẫn là benchmark chuẩn công nghiệp. Các features tĩnh của PE (headers, imports, entropy) không thay đổi theo thời gian. Hệ thống có pipeline retrain sẵn (`untils/retrain_xgboost.py`) để cập nhật khi có dữ liệu mới.

**"Tại sao chọn SecBERT thay vì BERT thông thường?"**
> SecBERT được pre-train trên cybersecurity corpus — hiểu đặc thù ngôn ngữ bảo mật tốt hơn, tránh phải fine-tune lại từ đầu trên domain mới. Ví dụ: "heap boundary check" và "buffer overflow" có embedding gần nhau trong SecBERT, còn BERT thường thì không.

**"Hệ thống xử lý file không phải PE (script, APK...) thế nào?"**
> Hệ thống có nhánh phân tích package manifest riêng (Python, Node.js, Java, PHP, Go, Rust, Ruby) — query NVD theo ecosystem + tên package + version. Không dùng EMBER XGBoost cho nhánh này vì không phải PE binary.

---

## Ghi chú thêm khi trình bày

- **Nhấn mạnh điểm mới:** SecBERT Semantic Relevance là đóng góp chính — không tool nào trên thị trường làm điều này
- **Số liệu mạnh:** AUC 0.9994 và 97.94% accuracy — nói to, tự tin
- **Graceful degradation:** hệ thống không phụ thuộc hoàn toàn vào AI — nếu model không load được, fallback về CVSS score
- **Thứ tự ưu tiên trình bày:** SecBERT Relevance (novelty) → EMBER (foundation) → Ensemble Severity (performance)
