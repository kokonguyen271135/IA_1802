# Model Results — Kết quả đánh giá các mô hình AI

---

## 1. Fine-tuned SecBERT — CVE Severity Classification

```
Base model : jackaduma/SecBERT
Task       : CVE Severity Classification (4 classes)
Device     : NVIDIA GeForce RTX 3050 Laptop GPU
Dataset    : 41,153 train | 5,485 val | 8,226 test
Time       : 1,641.2s (27.4 phút)
Epochs     : 3
LR         : 2e-05  |  Batch size: 16  |  Max length: 256 tokens
Class weights : CRITICAL=1.011  HIGH=0.970  MEDIUM=1.011  LOW=1.011
```

| Class    | Precision | Recall | F1     | Support |
|----------|-----------|--------|--------|---------|
| CRITICAL | 98.55%    | 99.90% | 99.22% | 2,035   |
| HIGH     | 97.25%    | 96.61% | 96.93% | 2,121   |
| MEDIUM   | 97.56%    | 96.12% | 96.83% | 2,035   |
| LOW      | 99.17%    | 99.95% | 99.56% | 2,035   |
| **Macro avg** | **98.13%** | **98.14%** | **98.13%** | 8,226 |

**Accuracy: 98.13% | Macro F1: 98.13% | Inference: 106.58 ms/sample**

Model saved: `models/bert_severity/`

---

## 2. XGBoost — CVE Severity Classification

```
Classifier : XGBoost 3.2.0
Features   : TF-IDF (5,000) + CVSS vector (8 features) = 5,008 total
Dataset    : 32,246 unique (sau dedup) → 25,796 train | 6,450 test
Time       : 111.2s
n_estimators=200 | max_depth=6 | learning_rate=0.1
subsample=0.8    | colsample_bytree=0.8
```

| Class    | Precision | Recall | F1     | Support |
|----------|-----------|--------|--------|---------|
| CRITICAL | 99.65%    | 98.80% | 99.22% | 582     |
| HIGH     | 93.61%    | 87.98% | 90.71% | 2,829   |
| MEDIUM   | 84.73%    | 91.93% | 88.18% | 2,715   |
| LOW      | 73.13%    | 60.49% | 66.22% | 324     |
| **Macro avg** | **87.78%** | **84.80%** | **86.08%** | 6,450 |

**Accuracy: 89.24% | Macro F1: 86.08% | Inference: 0.01 ms/sample**

Model saved: `models/xgboost_severity.pkl`

---

## 3. SecBERT CWE Classifier — 15 classes

```
Base model : jackaduma/SecBERT
Task       : CWE Classification (15 PE-relevant classes)
Device     : NVIDIA GeForce RTX 3050 Laptop GPU
Dataset    : 58,828 train | 7,836 val | 11,757 test
Time       : 6,204.3s (103.4 phút)
Epochs     : 8 (early stopping patience=3)
LR         : 1e-05  |  Batch size: 16  |  Max length: 256 tokens
```

| CWE     | Tên                          | Precision | Recall | F1     | Support |
|---------|------------------------------|-----------|--------|--------|---------|
| CWE-119 | Buffer Overflow              | 88.34%    | 85.74% | 87.02% | 1,970   |
| CWE-787 | OOB Write                    | 87.86%    | 86.69% | 87.27% | 1,495   |
| CWE-125 | OOB Read                     | 89.29%    | 88.74% | 89.01% | 1,155   |
| CWE-416 | Use After Free               | 93.67%    | 92.38% | 93.02% | 945     |
| CWE-476 | NULL Pointer Dereference     | 88.60%    | 91.79% | 90.16% | 694     |
| CWE-362 | Race Condition               | 82.84%    | 85.37% | 84.09% | 294     |
| CWE-94  | Code Injection               | 82.22%    | 82.10% | 82.16% | 676     |
| CWE-78  | OS Command Injection         | 89.39%    | 90.91% | 90.14% | 704     |
| CWE-190 | Integer Overflow             | 84.07%    | 89.08% | 86.51% | 403     |
| CWE-264 | Permissions / Access Control | 78.65%    | 79.93% | 79.28% | 802     |
| CWE-200 | Information Exposure         | 87.73%    | 86.71% | 87.22% | 1,385   |
| CWE-287 | Improper Authentication      | 78.06%    | 78.91% | 78.48% | 550     |
| CWE-798 | Hard-coded Credentials       | 85.38%    | 91.88% | 88.51% | 197     |
| CWE-400 | Uncontrolled Resource Consump| 80.56%    | 81.59% | 81.07% | 391     |
| CWE-843 | Type Confusion               | 77.45%    | 82.29% | 79.80% | 96      |
| **Macro avg** |                     | **84.94%** | **86.27%** | **85.58%** | 11,757 |

**Accuracy: 86.59% | Macro F1: 85.58%**

Model saved: `models/bert_cwe/`

**CWE bị loại khỏi model (lý do):**
- CWE-79 XSS, CWE-89 SQLi, CWE-22 Path Traversal → web-only, không liên quan PE
- CWE-399 Resource Mgmt → quá generic, overlap nhiều class
- CWE-20 Improper Input Validation → NVD catch-all, F1 chỉ 0.63
- CWE-77 Command Injection → overlap nặng với CWE-78, F1=0.64
- CWE-415 Double Free → chỉ 101 samples, overlap CWE-416
- CWE-189 Numeric Errors → 181 samples, overlap CWE-190

---

## 4. EMBER XGBoost — Malware Detection

```
Dataset  : EMBER 2017 (Elastic Security)
           600,000 train + 200,000 test PE samples
Features : 1,390 static features (headers, sections, imports, exports, strings)
Threshold: 0.51
```

| Metric   | Giá trị    |
|----------|-----------|
| ROC-AUC  | **0.9994** |
| F1-score | **0.9906** |
| Accuracy | **98.99%** |

**Phân ngưỡng output:**
```
≥ 0.80  →  CRITICAL  (MALWARE)
≥ 0.51  →  HIGH      (MALWARE)
≥ 0.35  →  MEDIUM    (SUSPICIOUS)
≥ 0.15  →  LOW       (SUSPICIOUS)
< 0.15  →  CLEAN     (BENIGN)
```

Model saved: `models/ember2017_xgb.json` (5.1MB)

---

## 5. So sánh toàn bộ approach — Severity Classification

| Model | Accuracy | Macro F1 | Inference | Ghi chú |
|-------|----------|----------|-----------|---------|
| **Fine-tuned SecBERT** | **98.13%** | **98.13%** | 106.58 ms | Mô hình chính |
| XGBoost + CVSS | 89.24% | 86.08% | **0.01 ms** | Ensemble partner |
| TF-IDF + Logistic Regression | 68.29% | 63.00% | — | Baseline cũ |
| Zero-Shot NLI (BART-MNLI) | 26.68% | 17.81% | 149.63 ms | Baseline so sánh |

**Fine-tuned SecBERT vượt Zero-Shot NLI: +71.45% accuracy**

---

## 6. Tóm tắt tất cả mô hình

| Mô hình | Nhiệm vụ | Accuracy | Macro F1 | Dataset |
|---------|----------|----------|----------|---------|
| Fine-tuned SecBERT | Severity (4 class) | **98.13%** | **98.13%** | 8,226 test |
| XGBoost + TF-IDF + CVSS | Severity (4 class) | 89.24% | 86.08% | 6,450 test |
| SecBERT CWE | CWE (15 class) | 86.59% | 85.58% | 11,757 test |
| EMBER XGBoost | Malware detection | 98.99% | F1=99.06% | 200K test |
| TF-IDF + LR (baseline) | Severity | 68.29% | 63.00% | 6,450 test |
| Zero-Shot BART-MNLI (baseline) | Severity | 26.68% | 17.81% | 8,226 test |

---

## 7. Lưu ý 

- **CRITICAL class F1 đồng đều 99.22%** ở cả BERT lẫn XGBoost → hệ thống phân loại lỗ hổng nguy hiểm nhất rất chính xác
- **LOW class F1 của XGBoost chỉ 66.22%** → lý do cần ensemble với BERT (BERT LOW F1=99.56%)
- **CWE-264 và CWE-287 F1 thấp nhất** (79–78%) vì đây là class "catch-all" trong NVD, định nghĩa rộng gây overlap
- **XGBoost inference 0.01 ms** vs BERT 106.58 ms → ensemble cho phép bù đắp khi một model không chắc
- **Training time BERT CWE: 103.4 phút** → đầu tư training lớn, thể hiện nghiên cứu nghiêm túc
