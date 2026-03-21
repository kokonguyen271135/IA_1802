# Thuyết Trình Đồ Án — Hội Đồng
## "Nghiên cứu và Phát triển Công cụ Đánh giá Lỗ hổng Phần mềm kết hợp AI và Cơ sở Dữ liệu CVE"

---

## SLIDE 1 — Giới thiệu đề tài

**Vấn đề thực tế:**
- Mỗi năm NVD công bố hàng chục nghìn CVE mới
- Lập trình viên / quản trị viên không có thời gian đọc thủ công
- Cần biết: "File .exe này có lỗ hổng nào không? Nguy hiểm tới đâu?"

**Giải pháp đề xuất:**
> Công cụ tự động — upload file → hệ thống phân tích, tra NVD, và đưa ra đánh giá rủi ro bằng AI.

**3 loại đầu vào hỗ trợ:**
1. PE binary (.exe / .dll / .sys)
2. Package manifest (requirements.txt, package.json, pom.xml...)
3. Tên phần mềm + version (search thủ công)

---

## SLIDE 2 — Kiến trúc tổng thể

```
[ Người dùng ]
      │  Upload file / nhập tên
      ▼
[ Frontend — HTML + JavaScript ]
      │  HTTP POST
      ▼
[ Flask Backend — app.py ]
      │
      ├── static_analyzer.py      → phân tích PE binary
      ├── package_analyzer.py     → phân tích manifest
      ├── cpe_extractor.py        → nhận dạng CPE
      ├── nvd_api_v2.py           → tra cơ sở dữ liệu NVD
      ├── cwe_predictor.py        → dự đoán lỗ hổng từ hành vi
      └── ai/
          ├── severity_pipeline.py → phân loại mức độ nguy hiểm
          └── relevance_scorer.py  → đo độ liên quan CVE ↔ file

[ Nguồn dữ liệu bên ngoài ]
  - NVD API v2 (nvd.nist.gov)
  - Anthropic Claude API
  - HuggingFace: jackaduma/SecBERT
```

---

## SLIDE 3 — Hướng 1: Phân tích PE Binary (Hướng chính)

**Luồng xử lý:**

```
Upload file .exe/.dll/.sys
         │
         ▼
  [BƯỚC 1] Static Analysis
    • Đọc PE headers, import table, section headers
    • Phân loại hành vi theo API: Process Injection,
      Keylogging, Network, Anti-Debugging, Cryptography...
    • Tính entropy từng section (phát hiện packing/mã hóa)
    • Quét strings: URL, IP, Base64, lệnh hệ thống
    • Nhận dạng component nhúng: OpenSSL, Python, libcurl...
         │
         ▼
  [BƯỚC 2] CPE Resolution — 3 lớp
    Lớp 1: Rule-based   → đọc PE VersionInfo, so KNOWN_PATTERNS
    Lớp 2: Claude AI    → gửi metadata, Claude trả về vendor/product
    Lớp 3: FAISS Index  → vector search trong 200k+ CPE entries
         │
         ▼
  [BƯỚC 3] Tra NVD
    • search_by_cpe(cpe)
    • Fallback: search_by_keyword(product + version)
         │
         ▼
  [BƯỚC 4] AI Enrichment
    • Phân loại severity: Ensemble (SecBERT + XGBoost + TF-IDF)
    • Tính relevance: SecBERT cosine similarity
    • Tính AI Risk Score tổng hợp
    • Claude sinh narrative mô tả rủi ro
         │
         ▼
  Kết quả hiển thị trên dashboard
```

---

## SLIDE 4 — Hướng 2: Phân tích Package Manifest

**Mục tiêu:** Audit toàn bộ dependency của một project một lần.

**Hỗ trợ:**
| File | Ecosystem |
|------|-----------|
| requirements.txt, Pipfile | Python |
| package.json, yarn.lock | Node.js |
| pom.xml, build.gradle | Java/Maven |
| composer.json | PHP |
| go.mod | Go |
| Cargo.toml | Rust |

**Luồng:**
```
Manifest file
    │
    ▼
PackageAnalyzer nhận diện ecosystem
    │
    ▼
Trích xuất danh sách (tên package, version)
    │
    ▼
Với MỖI package:
    ├─ Tìm CPE (hints → Claude AI → FAISS)
    └─ Tra NVD → enrich severity
    │
    ▼
Tổng hợp: thống kê toàn project
```

**Điểm mạnh:** Phát hiện supply chain vulnerability — 1 thư viện có CVE ảnh hưởng cả project.

---

## SLIDE 5 — Hướng 3: CWE Behavior Prediction (Fallback thông minh)

**Khi nào kích hoạt:** Không xác định được CPE **hoặc** CPE không trả về CVE nào.

**Ý tưởng cốt lõi:**
> Không biết phần mềm là gì → nhưng **biết nó làm gì** → suy ra loại lỗ hổng (CWE) → tìm CVE theo CWE.

**Luồng:**
```
PE Analysis (imports, strings, entropy)
         │
         ▼
  [CWE Prediction]
    Phương án 1: SecBERT ML classifier (nếu đã train)
      → Input: behavior profile text
      → Output: Top-5 CWE + confidence score
    Phương án 2: Rule-based mapping
      → Process Injection → CWE-94 (Code Injection)
      → Keylogging       → CWE-200 (Info Exposure)
      → High entropy     → CWE-506 (Packed binary)
         │
         ▼
  [Target Detection]
    Phân tích DLL imports, registry strings, file paths
    → Nhận dạng phần mềm mục tiêu (Office, Firefox, Adobe...)
         │
         ▼
  [NVD Query by CWE]
    search_by_cwe(CWE-ID, keyword=target)
         │
         ▼
  [Relevance Filtering]
    Lọc CVE phù hợp Windows/native (loại bỏ web-only)
    Sort: relevance + CWE confidence + CVSS
```

**Điểm mạnh:** Hệ thống **không bao giờ trả về tay không**.

---

## SLIDE 6 — Các Model AI sử dụng

| # | Model | Nhiệm vụ | Accuracy |
|---|-------|----------|----------|
| 1 | **SecBERT Severity** (fine-tuned) | Phân loại CVE: CRITICAL/HIGH/MEDIUM/LOW | 97.94% |
| 2 | **XGBoost Severity** | Phân loại severity (text + CVSS metrics) | 92–96% |
| 3 | **TF-IDF + LogReg** | Phân loại severity (baseline) | 86.83% |
| 4 | **SecBERT CWE** (fine-tuned) | Dự đoán CWE từ behavior PE | — |
| 5 | **FAISS CPE Index** | Tìm CPE bằng vector search | — |
| 6 | **Claude claude-sonnet-4-6** | CPE matching + Risk narrative | — |
| 7 | **SecBERT Relevance** (pretrained) | Tính độ liên quan CVE ↔ PE file | — |

---

## SLIDE 7 — Ensemble Severity Classification

**3 model chạy song song, kết quả gộp bằng weighted voting:**

```
CVE description
      │
      ├──► SecBERT (BERT 12 layers, 768-dim)  → prob[CRITICAL,HIGH,MEDIUM,LOW] × 1.00
      ├──► XGBoost (TF-IDF + CVSS metrics)    → prob[CRITICAL,HIGH,MEDIUM,LOW] × 0.85
      └──► TF-IDF + LogReg (baseline)         → prob[CRITICAL,HIGH,MEDIUM,LOW] × 0.70
                    │
                    ▼
      weighted_probs = Σ(prob × weight) / Σ(weight)
                    │
                    ▼
      predicted_severity = argmax(weighted_probs)
```

**Lý do ensemble:** Mỗi model có điểm mạnh riêng:
- SecBERT hiểu ngữ nghĩa bảo mật sâu
- XGBoost tận dụng cả CVSS numeric features
- TF-IDF nhanh, ổn định khi model khác lỗi

---

## SLIDE 8 — AI Risk Score

**Công thức:**

```
AI Risk Score = CVSS Component + Relevance Component

CVSS Component      = (avg_CVSS / 10) × 20      [tối đa 20 điểm]
Relevance Component = harmonic_weighted_rel × 80  [tối đa 80 điểm]
```

**Harmonic Weighted Relevance:**
```
Lấy top-5 CVE có relevance cao nhất
raw = score[0]/1 + score[1]/2 + score[2]/3 + score[3]/4 + score[4]/5
rel = raw / (1 + 1/2 + 1/3 + 1/4 + 1/5)   → normalize về [0,1]
```

**Phân loại level:**
```
≥ 70 → CRITICAL
≥ 40 → HIGH
≥ 20 → MEDIUM
>  0 → LOW
=  0 → CLEAN
```

**Ví dụ thực tế:**
```
9 CVE MEDIUM relevance (cosine ≈ 0.46) + CVSS avg 7.5
→ rel_component  = 0.46 × 80 = ~39 pts
→ cvss_component = 7.5/10 × 20 = 15 pts
→ Score = 54 → HIGH
```

---

## SLIDE 9 — SecBERT Relevance Scoring

**Câu hỏi trả lời:** "CVE này có liên quan đến FILE CỤ THỂ này không?" (không chỉ là "CVE này nguy hiểm không?")

```
PE file behavior                    CVE description
"Process injection using            "Exploiting improper memory
 SuspendThread, VirtualProtect,      boundary check allows attacker
 high entropy section..."            to inject code into process..."
        │                                    │
        ▼                                    ▼
  SecBERT.encode()              SecBERT.encode()
        │                                    │
  768-dim vector                      768-dim vector
        │                                    │
        └──────── cosine_similarity ─────────┘
                         │
                   score ∈ [0, 1]
                         │
          ≥ 0.72 → CRITICAL
          ≥ 0.55 → HIGH
          ≥ 0.38 → MEDIUM
          ≥ 0.22 → LOW
          < 0.22 → MINIMAL
```

**Điểm mới:** Hai file khác nhau (dù cùng phần mềm) nhận **relevance score khác nhau** cho cùng 1 CVE, vì behavior profile của chúng khác nhau.

---

## SLIDE 10 — Demo / Kết quả thực tế

**Kịch bản demo đề xuất:**

1. **Upload file PE malware mẫu**
   → Hệ thống phát hiện: Process Injection, Keylogging, Anti-Debug
   → CWE prediction: CWE-94, CWE-200, CWE-506
   → Risk Score: CRITICAL (≥70)

2. **Upload requirements.txt có thư viện cũ**
   → Hệ thống tìm ra package có CVE CRITICAL
   → Hiển thị danh sách lỗ hổng từng thư viện

3. **Search "WinRAR 6.21"**
   → Tìm CPE, tra NVD
   → Relevance scoring theo behavior
   → Risk Score: HIGH (54/100)

---

## SLIDE 11 — Điểm mới của đề tài

| Đóng góp | Mô tả |
|----------|-------|
| **Hướng 3 — CWE Behavior** | Không cần biết tên phần mềm vẫn tìm được CVE dựa trên hành vi thực tế của PE |
| **SecBERT Relevance** | Đánh giá CVE có liên quan đến **file cụ thể** này không, thay vì chỉ xếp theo CVSS chung |
| **Ensemble Severity** | 3 model kết hợp (Transformer + Gradient Boosting + Statistical) → accuracy cao hơn từng model đơn lẻ |
| **3 lớp CPE Resolution** | Rule-based → Claude AI → FAISS — đảm bảo nhận dạng phần mềm dù tên file lạ |
| **Unified Pipeline** | PE binary + Package manifest + Search trong cùng 1 công cụ |

---

## SLIDE 12 — Hạn chế & Hướng phát triển

**Hạn chế hiện tại:**
- SecBERT behavior profile dùng template cứng → embedding các file cùng behavior category bị tương tự nhau
- FAISS CPE index phụ thuộc vào dữ liệu NVD, không tự cập nhật
- Hướng 3 chỉ hoạt động tốt với PE Windows, chưa hỗ trợ ELF (Linux)

**Hướng phát triển:**
- Fine-tune SecBERT riêng cho từng loại API behavior → relevance chính xác hơn
- Tích hợp thêm OSV database, GitHub Advisory
- Mở rộng sang ELF binary (Linux), APK (Android)
- Xây dựng CI/CD plugin (scan tự động mỗi khi build)

---

## Câu hỏi thường gặp từ hội đồng

**Q: Tại sao dùng SecBERT thay vì BERT thường?**
> SecBERT được pre-train trên corpus bảo mật (CVE descriptions, security advisories, threat intel) → hiểu ngữ nghĩa chuyên ngành bảo mật tốt hơn BERT-base.

**Q: Ensemble 3 model có thực sự tốt hơn 1 model không?**
> Có. SecBERT tốt nhất về ngữ nghĩa (97.94%) nhưng không tận dụng được CVSS numeric features. XGBoost bổ sung điều đó (92-96%). TF-IDF là fallback ổn định. Weighted voting tránh sai số từ model đơn lẻ.

**Q: Hướng 3 có thể nhầm không?**
> Có — kết quả là gián tiếp (qua CWE, không qua CPE). Đây là **fallback**, không phải hướng chính. Hệ thống luôn ưu tiên Hướng 1, chỉ dùng Hướng 3 khi không có lựa chọn nào khác.

**Q: NVD API có giới hạn không?**
> Có — không có API key: 5 req/30s. Với API key: 50 req/30s. Hệ thống xử lý rate limit bằng cơ chế retry + sleep tự động.

**Q: Điểm khác biệt so với Snyk / OWASP Dependency Check?**
> Các tool đó chỉ quét package manifest. Đồ án này còn phân tích **PE binary trực tiếp** và dùng **AI đánh giá relevance** thay vì chỉ tra CVE theo tên thư viện.
