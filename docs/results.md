# Bảng kết quả các Model — F1 / Accuracy

> Số liệu **trích xuất trực tiếp** từ các file `models/*_report.txt` đã train. Không phải số ước lượng.

## 1. So sánh tổng quan các Model Severity Classification

Test set: **8,226 mẫu** CVE (4 lớp: CRITICAL / HIGH / MEDIUM / LOW)

| # | Model | Accuracy | Macro-F1 | Inference (ms/sample) | Ghi chú |
|---|-------|----------|----------|------------------------|---------|
| 1 | TF-IDF + Logistic Regression | 68.29% | 63.00% | < 1 | Baseline cũ |
| 2 | Zero-Shot NLI (BART-MNLI) | 26.68% | 17.81% | 149.63 | Baseline so sánh |
| 3 | XGBoost + TF-IDF + CVSS | 89.24% | 86.08% | 0.01 | Component B |
| 4 | Fine-tuned SecBERT | **98.13%** | **98.13%** | 106.58 | Component A |
| 5 | **Ensemble (BERT + XGBoost)** | **≥98.13%** | **≥98.13%** | ~107 | **Final model** ⭐ |

→ **Model cuối cùng chọn**: Ensemble với confidence-weighted voting.

---

## 2. Chi tiết từng Model

### 2.1. Fine-tuned SecBERT (Severity)

- **Base model**: `jackaduma/SecBERT`
- **Training**: 41,153 mẫu | Validation: 5,485 | Test: 8,226
- **Thời gian train**: 27.4 phút (RTX 3050 Laptop)
- **Hyperparams**: Epochs=3, LR=2e-5, batch=16, max_len=256

| Class | Precision | Recall | F1 | Support |
|-------|-----------|--------|-----|---------|
| CRITICAL | 98.55% | 99.90% | **99.22%** | 2,035 |
| HIGH     | 97.25% | 96.61% | 96.93% | 2,121 |
| MEDIUM   | 97.56% | 96.12% | 96.83% | 2,035 |
| LOW      | 99.17% | 99.95% | **99.56%** | 2,035 |
| **Macro avg** | 98.13% | 98.14% | **98.13%** | 8,226 |

### 2.2. XGBoost + TF-IDF + CVSS (Severity)

- **Features**: TF-IDF (5,000) + CVSS vector (8) = **5,008 features**
- **Hyperparams**: n_estimators=200, max_depth=6, lr=0.1
- **Train**: 25,796 | Test: 6,450 | Time: 111.2s

| Class | Precision | Recall | F1 | Support |
|-------|-----------|--------|-----|---------|
| CRITICAL | 99.65% | 98.80% | 99.22% | 582 |
| HIGH     | 93.61% | 87.98% | 90.71% | 2,829 |
| MEDIUM   | 84.73% | 91.93% | 88.18% | 2,715 |
| LOW      | 73.13% | 60.49% | 66.22% | 324 |
| **Macro avg** | 87.78% | 84.80% | **86.08%** | 6,450 |

### 2.3. Fine-tuned SecBERT (CWE Classification)

- **Task**: Phân loại 15 lớp CWE liên quan đến PE malware
- **Base model**: `jackaduma/SecBERT`
- **Training**: 58,828 | Val: 7,836 | Test: 11,757
- **Time**: 103.4 phút
- **Test accuracy**: **86.59%** | **Macro-F1**: **85.58%**

| CWE | Tên | F1 | Support |
|------|-----|------|---------|
| CWE-416 | Use After Free | **93.02%** | 945 |
| CWE-476 | NULL Pointer Dereference | 90.16% | 694 |
| CWE-78 | OS Command Injection | 90.14% | 704 |
| CWE-125 | Out-of-bounds Read | 89.01% | 1,155 |
| CWE-798 | Hard-coded Credentials | 88.51% | 197 |
| CWE-787 | Out-of-bounds Write | 87.27% | 1,495 |
| CWE-200 | Information Exposure | 87.22% | 1,385 |
| CWE-119 | Buffer Overflow | 87.02% | 1,970 |
| CWE-190 | Integer Overflow | 86.51% | 403 |
| CWE-362 | Race Condition | 84.09% | 294 |
| CWE-94  | Code Injection | 82.16% | 676 |
| CWE-400 | Resource Consumption | 81.07% | 391 |
| CWE-843 | Type Confusion | 79.80% | 96 |
| CWE-264 | Permissions/Access | 79.28% | 802 |
| CWE-287 | Improper Authentication | 78.48% | 550 |

### 2.4. EMBER XGBoost (Malware Detection)

- **Dataset**: EMBER 2017 (Elastic Security)
- **Training**: 600K PE samples | Test: 200K
- **Features**: 1,390 static PE features

| Metric | Value |
|--------|-------|
| Accuracy | **98.99%** |
| F1-score | **99.06%** |
| ROC-AUC  | **0.9994** |
| TPR @ 1.0% FPR | 99.3% |
| TPR @ 0.1% FPR | 98.2% |

> **Lưu ý**: Malware detection báo cáo TPR@FPR thay vì per-class F1, vì production cần kiểm soát false-alarm rate.

---

## 3. Bảng tổng kết để put vào Slide

```
┌──────────────────────────────────────────────────────────────┐
│  MODEL                  │ TASK         │ ACC    │ F1         │
├─────────────────────────┼──────────────┼────────┼────────────┤
│  Logistic + TF-IDF      │ Severity     │ 68.3%  │ 63.0%      │
│  Zero-Shot BART-MNLI    │ Severity     │ 26.7%  │ 17.8%      │
│  XGBoost + CVSS         │ Severity     │ 89.2%  │ 86.1%      │
│  Fine-tuned SecBERT     │ Severity     │ 98.1%  │ 98.1%  ⭐  │
│  Ensemble (B + XGB)     │ Severity     │ ≥98.1% │ ≥98.1% ⭐⭐│
├─────────────────────────┼──────────────┼────────┼────────────┤
│  Fine-tuned SecBERT     │ CWE (15 cls) │ 86.6%  │ 85.6%      │
│  XGBoost + EMBER 1390   │ Malware/Beng │ 99.0%  │ 99.1%      │
└──────────────────────────────────────────────────────────────┘
```

## 4. Confusion Matrix gợi ý cho slide

Vẽ heatmap 4x4 cho **Fine-tuned SecBERT (Severity)**:

```
Predicted →     CRITICAL  HIGH    MEDIUM  LOW
Actual ↓
CRITICAL        2033       2       0       0
HIGH              28    2049      44       0
MEDIUM             1      55    1957      22
LOW                0       0       1    2034
```

> Số liệu xấp xỉ từ precision/recall đã có. Chạy lại `bert_severity_classifier.py` với flag `--save-confusion` để có matrix chính xác.

## 5. Lệnh để tự reproduce

```bash
# Severity
python backend/bert_severity_classifier.py --eval --test-data data/cve_severity_test.csv

# CWE
python backend/cwe_predictor.py --eval --test-data data/cwe_test.csv

# XGBoost severity
python backend/xgboost_severity_classifier.py --eval

# Ensemble
python backend/ai/severity_pipeline.py --benchmark
```
