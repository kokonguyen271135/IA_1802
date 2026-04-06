# Cách Hoạt Động Của Hệ Thống

## Tổng Quan

Hệ thống là công cụ đánh giá lỗ hổng phần mềm kết hợp AI và cơ sở dữ liệu CVE (NVD).
Người dùng upload file PE (exe/dll) hoặc file manifest (requirements.txt, package.json...),
hệ thống phân tích và trả về báo cáo bảo mật tự động.

---

## Các Thành Phần Chính

### 1. EMBER XGBoost — Phát Hiện Malware
- Model XGBoost được train trên 600,000 file PE (EMBER 2017 dataset)
- Trích xuất 1,390 đặc trưng từ file PE: header, sections, imports, exports, strings
- Output: xác suất malware 0-100%, label BENIGN / MALWARE, AUC = 0.9994
- Đây là lớp phòng thủ đầu tiên — quyết định file có nguy hiểm không

### 2. Static Analyzer — Phân Tích Tĩnh PE
- Phân tích cấu trúc file PE mà không cần chạy file
- Phát hiện suspicious API theo categories:
  - Process Injection (VirtualAlloc, WriteProcessMemory...)
  - Keylogging (GetKeyState, CallNextHookEx...)
  - Code Execution (WinExec, ShellExecute...)
  - Privilege Escalation, Network Communication, Anti-Debugging...
- Risk level: CRITICAL / HIGH / MEDIUM / LOW cho từng category

### 3. CPE Extractor + NVD API — Tra Cứu CVE
- Trích xuất thông tin phần mềm từ PE file (vendor, product, version)
- Build CPE string (Common Platform Enumeration): cpe:2.3:a:vendor:product:version:...
- Query NVD API v2 để lấy CVE liên quan đến phần mềm đó
- Rate limit: 50 requests/30s với API key

### 4. SecBERT Severity Pipeline — Phân Loại Mức Độ Nguy Hiểm
- Ensemble 2 model:
  - Fine-tuned SecBERT (jackaduma/SecBERT, 97.94% accuracy)
  - XGBoost + CVSS features (92-96% accuracy)
- Input: CVE description text + CVSS vector string
- Output: CRITICAL / HIGH / MEDIUM / LOW với confidence score

### 5. SecBERT Relevance Scorer — Lọc CVE Liên Quan
- Dùng sentence-transformers (all-MiniLM-L6-v2) tính cosine similarity
- So sánh behavior profile của file với description của từng CVE
- Threshold: CRITICAL >= 0.72, HIGH >= 0.55, MEDIUM >= 0.50, LOW >= 0.30
- Filter: bỏ CVE có relevance LOW/MINIMAL khi SecBERT active

### 6. CWE Predictor — Hướng 3 (Behavior-based CVE)
- Kích hoạt khi EMBER >= 50% HOẶC có HIGH/CRITICAL suspicious API
- Fine-tuned SecBERT CWE classifier (15 classes, 86.59% accuracy)
- Predict CWE từ behavior profile → query NVD theo CWE + behavior keyword
- Behavior keywords: "keylogger windows", "process injection", "remote code execution"...

### 7. Semantic CPE Matcher (FAISS)
- Khi không trích xuất được CPE chính xác, dùng FAISS vector search
- So sánh tên phần mềm với 109 CPE vector đã index
- Confidence: high / medium / low

---

## Luồng Xử Lý File PE

```
Upload file PE
    |
    v
[Static Analysis] -- Sections, Imports, Strings, Risk Score
    |
    v
[EMBER XGBoost] -- Malware probability (0-100%)
    |
    v
[CPE Extraction] -- Vendor, Product, Version
    |
    +-- CPE found --> [NVD CVE Lookup] --> [Severity + Relevance Scoring]
    |
    +-- No CPE --> (skip CVE lookup)
    |
    v
[CWE Gate] -- EMBER >= 50% OR HIGH/CRITICAL API?
    |
    +-- YES --> [CWE Prediction] --> [Behavior Keyword Search] --> [Top-10 CVE]
    |
    +-- NO --> Skip (file clean, no CVE output)
    |
    v
[Final Result] -- Risk level, CVEs, Behavior report
```

---

## Luồng Xử Lý Package Manifest

```
Upload requirements.txt / package.json / pom.xml...
    |
    v
[Package Parser] -- Extract package name + version
    |
    v
[CPE Lookup per package] -- FAISS fallback nếu không có CPE hint
    |
    v
[NVD CVE Lookup per package] -- max 20 CVE/package
    |
    v
[Severity Scoring] -- BERT + XGBoost ensemble
    |
    v
[Result] -- Per-package CVE list + global statistics
```
