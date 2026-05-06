# Hướng Dẫn Thuyết Trình Đồ Án

Tài liệu này là kịch bản thuyết trình thực dụng, viết cho buổi bảo vệ ~15-20 phút
+ 10-15 phút Q&A. Đọc kèm với `01_cach_hoat_dong.md`, `03_giai_trinh_hoi_dong.md`,
`06_model_results.md`.

---

## 1. Phân bổ thời gian (giả định 20 phút trình bày)

| Phần | Thời gian | Mục tiêu |
|------|-----------|----------|
| 1. Mở đầu — bài toán thực tế | 1.5 phút | Hội đồng "thấy" được vấn đề |
| 2. Giải pháp một câu + sơ đồ tổng | 1.5 phút | Hội đồng nhớ được sản phẩm |
| 3. Kiến trúc & 7 thành phần | 3 phút | Cho thấy độ sâu kỹ thuật |
| 4. Điểm sáng tạo (Hướng 3 + Ensemble) | 3 phút | Phần "đáng chấm điểm cao" |
| 5. Demo trực tiếp | 6 phút | 3-4 case như mục 8 |
| 6. Kết quả mô hình (bảng số) | 2 phút | Chứng minh đáng tin |
| 7. Hạn chế + hướng phát triển | 1.5 phút | Cho thấy mình hiểu sản phẩm |
| 8. Kết luận + lời cảm ơn | 1 phút | Đóng gọn |

Quy tắc: **mỗi slide ≤ 1 phút, demo mới là điểm rơi**. Đừng đọc slide.

---

## 2. Mở đầu — phải hook hội đồng trong 60 giây

Đừng bắt đầu bằng "Em xin phép trình bày đề tài...". Bắt đầu bằng tình huống:

> "Khi anh chị tải một file `.exe` từ mạng, hoặc nhận một file `requirements.txt`
> từ một dự án, có 3 câu hỏi mà người dùng bình thường không trả lời được:
> File này có phải malware không? Nó có lỗ hổng đã công bố không? Mức độ nguy hiểm
> ra sao? Hệ thống của em trả lời cả 3 câu hỏi đó tự động trong vài giây — đó là
> nội dung em trình bày hôm nay."

Sau đó mới giới thiệu tên đề tài + GVHD + bản thân.

---

## 3. Câu giới thiệu sản phẩm (học thuộc)

> "Hệ thống là công cụ đánh giá lỗ hổng phần mềm tự động, kết hợp **phân tích tĩnh
> file PE**, **machine learning phát hiện malware**, và **truy vấn cơ sở dữ liệu
> CVE quốc gia (NVD)**, hoạt động hoàn toàn offline với mô hình local."

Câu này phải nói trôi chảy. Hội đồng sẽ ghi nó xuống làm "định nghĩa làm việc"
khi đặt câu hỏi.

---

## 4. Sơ đồ tổng — slide quan trọng nhất

Vẽ đúng sơ đồ trong `01_cach_hoat_dong.md` mục "Luồng Xử Lý File PE". Khi trình
bày, **chỉ tay theo từng mũi tên**, đừng để slide tự chạy:

1. Upload PE → Static Analysis (mũi tên 1)
2. → EMBER XGBoost (mũi tên 2) — "đây là gate malware"
3. → CPE Extraction → NVD lookup (mũi tên 3) — "đây là Hướng 1+2"
4. → CWE Gate → Behavior CVE (mũi tên 4) — "đây là Hướng 3, đóng góp mới"
5. → Final Report

Khi hội đồng hỏi câu nào, chỉ vào đúng mũi tên đó để trả lời. Đây là cách
giữ kiểm soát phiên Q&A.

---

## 5. Khi giới thiệu 7 thành phần — đừng kể hết

Tránh đọc lại từng module. Nói nhanh theo nhóm:

- **2 model phát hiện**: EMBER (malware) + Static Analyzer (suspicious API)
- **2 module tra cứu**: CPE Extractor + NVD API (+ FAISS fallback)
- **2 model phân loại CVE**: SecBERT severity + XGBoost severity (ensemble)
- **1 model sáng tạo**: CWE Predictor cho Hướng 3
- **1 module lọc nhiễu**: SecBERT Relevance Scorer

Tổng 8 thành phần, 4 ý — hội đồng nắm được. Chi tiết để dành Q&A.

---

## 6. Điểm sáng tạo — phần "đáng đầu tư nhất"

Hai điểm này phải nhấn mạnh, vì đây là chỗ phân biệt với "wrapper API":

### 6.1. Hướng 3 — Behavior-based CVE Discovery

Vấn đề: nếu file PE không có ProductName/Version → không trích được CPE → query
NVD trả về rỗng → user không biết gì về lỗ hổng.

Giải pháp: phân tích **hành vi** (file import API gì) → predict CWE → search NVD
theo CWE + behavior keyword.

Ví dụ cụ thể (đọc trong slide):

> File import `GetKeyState` + `CallNextHookEx` → CWE Predictor xuất
> "CWE-200 Information Exposure" → search NVD với "keylogger credential theft
> windows" → trả về top-10 CVE thực sự về keylogger.

Gate chống false positive: chỉ chạy khi `EMBER ≥ 50%` HOẶC `≥ 1 HIGH/CRITICAL API`.

### 6.2. Ensemble SecBERT + XGBoost

- SecBERT 98.13% accuracy nhưng inference 106 ms/sample.
- XGBoost 89.24% accuracy nhưng inference 0.01 ms/sample (10,000× nhanh hơn).
- Ensemble: dùng XGBoost làm bộ lọc nhanh, SecBERT để confirm các case
  XGBoost không chắc.
- LOW class F1: XGBoost 66% vs BERT 99% → ensemble bù được điểm yếu này.

Số liệu lấy từ `06_model_results.md`. Nếu hội đồng hỏi "tại sao không chỉ
dùng BERT?" → nhấn vào inference time + production cost.

---

## 7. Bảng số mô hình — slide cần chiếu lên

Lấy đúng bảng "Tóm tắt tất cả mô hình" trong `06_model_results.md` mục 6:

| Mô hình | Nhiệm vụ | Accuracy | Macro F1 |
|---------|----------|----------|----------|
| Fine-tuned SecBERT | Severity | **98.13%** | **98.13%** |
| XGBoost + CVSS | Severity | 89.24% | 86.08% |
| SecBERT CWE | CWE (15 class) | 86.59% | 85.58% |
| EMBER XGBoost | Malware | 98.99% | 99.06% |
| TF-IDF + LR (baseline) | Severity | 68.29% | 63.00% |
| Zero-Shot BART (baseline) | Severity | 26.68% | 17.81% |

So sánh "+71.45% so với Zero-Shot" là cách thuyết phục nhất với hội đồng:
**có baseline rõ ràng** → cho thấy fine-tune đem lại giá trị thật.

Nếu có thời gian, thêm 1 dòng: "EMBER train trên 600K samples, AUC 0.9994 — gần
hoàn hảo, nghĩa là 10,000 cặp ngẫu nhiên xếp sai chỉ ~6 cặp."

---

## 8. Kịch bản demo (6 phút, 3-4 case)

Chuẩn bị **trước** 4 file dưới đây trên máy. Có sẵn pre-loaded results
phòng khi mạng chậm/NVD timeout.

### Demo 1 — Malware rõ ràng (1.5 phút)
- File: PE có `WinExec` + `GetKeyState` + entropy cao.
- Kết quả mong đợi: EMBER ≥ 80% → CRITICAL → Hướng 3 kích hoạt → CWE-200
  → CVE keylogger.
- Câu nói: "Đây là kịch bản chính — file độc hại không có tên rõ ràng,
  hệ thống vẫn ra được CVE liên quan nhờ Hướng 3."

### Demo 2 — File clean (1 phút)
- File: PE đơn giản (vd: hello-world.exe compile từ C).
- Kết quả: EMBER < 1% → CLEAN → Hướng 3 skip → không output CVE.
- Câu nói: "Hệ thống trung thực — file clean thì không bịa CVE.
  Đây là điểm khác biệt với các tool spam cảnh báo."

### Demo 3 — Phần mềm có version rõ ràng (1.5 phút)
- File: một phiên bản cũ của 7-Zip / Notepad++ có CVE biết trước.
- Kết quả: CPE extracted chính xác → NVD trả về CVE đúng version → severity
  scoring per CVE.
- Câu nói: "Đây là Hướng 1+2 — software inventory check truyền thống
  nhưng tự động hoàn toàn."

### Demo 4 — Package manifest (1.5 phút)
- File: `requirements.txt` của một project Python có pin version cũ
  (vd: `Django==2.2.0`, `requests==2.20.0`).
- Kết quả: parse package → CVE per package → bảng tổng hợp severity.
- Câu nói: "Hệ thống không chỉ làm việc với binary — còn phân tích
  dependency của project, là thứ rất thiếu trong các tool VN hiện có."

**Lưu ý demo**: Luôn có tab pre-rendered HTML/PDF kết quả phòng khi
NVD API rate-limit hoặc mạng phòng bảo vệ chậm.

---

## 9. Hạn chế (phải tự nói trước khi hội đồng hỏi)

Tự nêu hạn chế cho thấy mình hiểu sản phẩm. Lấy từ `03_giai_trinh_hoi_dong.md`:

1. Packed/obfuscated malware → behavior analysis có thể thiếu thông tin.
2. Zero-day → không có trong NVD → không tra được.
3. Custom malware dùng syscall trực tiếp → bỏ qua được suspicious API.
4. EMBER false negative ~0.06% (hiếm nhưng có).
5. Hiện tại là Flask dev server, chưa production-ready.

Câu kết: "Vì vậy hệ thống định vị là **công cụ hỗ trợ chuyên gia**,
không thay thế hoàn toàn quy trình audit thủ công."

---

## 10. Hướng phát triển (1 slide, 4-5 bullet)

- Production hardening: Gunicorn + Celery + Redis queue + Docker.
- Tích hợp dynamic analysis (sandbox execution) cho file packed.
- Mở rộng dataset CWE từ 15 class lên đầy đủ MITRE Top 25.
- Multi-language support: Java JAR, .NET assembly, Mach-O macOS.
- Integration vào CI/CD (GitHub Action) cho dependency scanning.

---

## 11. Q&A — chiến lược

### Trước khi vào Q&A
- Nói: "Em sẵn sàng nhận câu hỏi của hội đồng. Em có chuẩn bị thêm các
  slide phụ về dataset, training detail, và benchmark — em sẽ chiếu lên
  khi cần."
- Tự tin = hội đồng tin.

### Khi nhận câu hỏi
1. **Lặp lại câu hỏi bằng từ của mình**: "Dạ, thầy/cô đang hỏi về [...],
   em xin phép trả lời." → mua thêm 5-10 giây suy nghĩ + xác nhận đúng ý.
2. **Trả lời theo cấu trúc**: kết luận trước, lý do sau. Đừng vòng vo.
3. **Không biết → nói không biết**. "Câu này em chưa benchmark cụ thể,
   em xin phép ghi nhận và bổ sung trong báo cáo cuối." Tốt hơn là bịa.

### Top câu hỏi đã chuẩn bị (xem chi tiết ở `03_giai_trinh_hoi_dong.md`)

| Câu hỏi | File tham khảo |
|---------|----------------|
| Hệ thống giải quyết bài toán gì? | `03` Q1 |
| Tại sao dùng nhiều model thay vì một? | `03` Q2 |
| Độ chính xác như thế nào? | `03` Q3 + `06` mục 6 |
| Dataset từ đâu? Đáng tin không? | `03` Q4 |
| Hướng 3 là gì? | `03` Q5 + `01` mục 6 |
| Tại sao không dùng VirusTotal? | `03` Q6 |
| Có thể bị bypass không? | `03` Q7 |
| Scale lên production thế nào? | `03` Q8 |
| Tại sao chọn SecBERT thay vì BERT? | `03` Q9 |

### Câu khó có thể bị hỏi (chuẩn bị riêng)

**Q: "Em có overfitting không?"**
A: BERT severity train 3 epoch với early stop, train/val/test split 80/10/15.
Test accuracy 98.13% cao tương đương validation → không có dấu hiệu overfit.
CWE classifier có patience=3 cho early stopping.

**Q: "Tại sao chọn 15 class CWE mà không phải full?"**
A: Đã loại CWE-79/89/22 vì web-only không liên quan PE. Loại CWE-20/77/189
vì overlap nặng với class khác hoặc F1 < 0.65 — giữ lại sẽ làm xấu macro F1.
Đây là quyết định domain-driven, có ghi chú trong `06_model_results.md` mục 3.

**Q: "Threshold 0.51 cho EMBER em chọn dựa trên gì?"**
A: Đây là threshold mặc định của EMBER paper (Anderson & Roth, 2018), tối ưu
cho cân bằng precision/recall trên 200K test samples. Em có thử ROC curve
và confirm điểm này gần Youden's J statistic.

**Q: "Sao không dùng LLM (GPT/Claude) cho phần này?"**
A: 3 lý do: (1) chi phí API cho mỗi CVE description không scale được;
(2) yêu cầu offline cho enterprise security; (3) SecBERT 98% với 110M params
đủ tốt và deploy được trên 1 GPU consumer (RTX 3050). LLM là overkill.

---

## 12. Checklist trước buổi bảo vệ

**1 tuần trước:**
- [ ] Slide hoàn thành, ≤ 25 slide chính + 10 slide dự phòng
- [ ] Demo chạy ngon trên máy tính sẽ dùng (không phải máy dev)
- [ ] Pre-render kết quả 4 demo case ra HTML/PDF backup
- [ ] In sẵn báo cáo + biên bản (theo yêu cầu khoa)

**1 ngày trước:**
- [ ] Chạy thử demo từ đầu đến cuối, đo thời gian
- [ ] Test mạng tại phòng bảo vệ — nếu chậm, dùng local NVD cache
- [ ] Sạc đầy laptop + mang adapter + USB chứa slide
- [ ] Tập nói câu mở đầu + câu giới thiệu sản phẩm đến mức nói thuộc

**Trước giờ vào:**
- [ ] Tắt notification (Slack, mail, Discord)
- [ ] Đóng tất cả tab không liên quan (đặc biệt là code editor có TODO)
- [ ] Mở sẵn 4 file demo + 1 tab NVD + 1 tab fallback HTML
- [ ] Hít thở sâu — hội đồng muốn em pass, không phải fail

---

## 13. Điểm nhấn cuối — câu kết bài

> "Đề tài của em không chỉ là một wrapper trên NVD API. Em đã train 3 model
> AI (EMBER, SecBERT severity, SecBERT CWE) trên tổng cộng hơn 700,000
> samples, đề xuất một hướng tiếp cận mới — Behavior-based CVE Discovery —
> để giải quyết bài toán file PE thiếu metadata, và benchmark đầy đủ với
> baseline để chứng minh giá trị của fine-tuning. Em xin cảm ơn hội đồng đã
> lắng nghe."

Đây là câu kết hội đồng sẽ nhớ — nó tóm gọn 3 đóng góp: **(1) train model
quy mô lớn, (2) đề xuất phương pháp mới, (3) so sánh với baseline**.

---

## 14. Tham khảo nội bộ

- Cách hoạt động chi tiết: `KNOWN/01_cach_hoat_dong.md`
- Workflow đầy đủ: `KNOWN/02_workflow_he_thong.md`
- Q&A kỹ thuật: `KNOWN/03_giai_trinh_hoi_dong.md`
- Pipeline PE binary: `KNOWN/04_pe_binary_ai_pipeline.md`
- Bài thuyết trình AI models: `KNOWN/05_thuyet_trinh_ai_models.md`
- Bảng kết quả model: `KNOWN/06_model_results.md`
