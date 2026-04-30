# Giải Trình Hệ Thống Cho Hội Đồng

## Giới Thiệu Một Câu

> "Hệ thống là công cụ đánh giá lỗ hổng phần mềm tự động, kết hợp phân tích tĩnh file PE,
> machine learning phát hiện malware, và truy vấn cơ sở dữ liệu CVE quốc gia (NVD),
> giúp người dùng đánh giá mức độ nguy hiểm của một file phần mềm mà không cần chạy nó."

---

## Câu Hỏi Thường Gặp Từ Hội Đồng

---

### Q: Hệ thống giải quyết bài toán gì?

**Trả lời:**
Trong thực tế, khi nhận được một file phần mềm (exe, dll) hoặc một project có dependencies,
người dùng thường không biết:
1. File đó có phải malware không?
2. Phần mềm đó có lỗ hổng bảo mật đã được công bố không?
3. Mức độ nguy hiểm của các lỗ hổng đó là gì?

Hệ thống trả lời cả 3 câu hỏi này tự động trong vài giây, không cần chuyên gia bảo mật.

---

### Q: Tại sao dùng nhiều AI model thay vì một model?

**Trả lời:**
Mỗi model có điểm mạnh khác nhau:

- **EMBER XGBoost**: Train trên 600K PE samples, rất nhanh, hiệu quả cho malware detection
  dựa trên đặc trưng cấu trúc file. Không cần hiểu ngôn ngữ tự nhiên.

- **SecBERT (BERT)**: Hiểu ngữ nghĩa của CVE description. "Use-after-free vulnerability
  in the rendering engine allows remote code execution" — BERT hiểu đây là HIGH/CRITICAL,
  TF-IDF đơn thuần không hiểu được ngữ cảnh.

- **XGBoost + CVSS**: Khai thác thông tin có cấu trúc từ CVSS vector (AV:N/AC:L/PR:N...)
  — thông tin này không có trong text description nhưng rất quan trọng cho severity.

Ensemble các model → kết quả ổn định hơn, giảm single-point-of-failure.

---

### Q: Độ chính xác của hệ thống như thế nào?

**Trả lời:**

| Thành phần | Metric | Giá trị |
|------------|--------|---------|
| EMBER malware detection | AUC-ROC | 0.9994 |
| SecBERT severity classifier | Test Accuracy | 97.94% |
| XGBoost severity | Accuracy | 92-96% |
| CWE classifier | Test Accuracy | 86.59% |
| CWE classifier | Macro F1 | 85.58% |

Giải thích: AUC = 0.9994 nghĩa là với 10,000 cặp (malware, benign) ngẫu nhiên,
model xếp hạng đúng 9,994 cặp — gần hoàn hảo.

---

### Q: Dữ liệu train từ đâu? Có đáng tin cậy không?

**Trả lời:**

- **EMBER dataset**: Endgame Inc. công bố năm 2017, 600,000 file PE đã được phân loại
  bởi VirusTotal (anti-virus consensus). Đây là benchmark chuẩn trong nghiên cứu malware detection.

- **NVD (National Vulnerability Database)**: Cơ sở dữ liệu lỗ hổng của NIST (Mỹ),
  cập nhật liên tục, hiện có ~342,000 CVE. Đây là nguồn dữ liệu chuẩn quốc tế.

- **SecBERT**: Jackaduma (2022), pre-trained trên corpus bảo mật, fine-tuned thêm trên
  ~41,000 CVE descriptions để classify severity.

- **CWE classifier**: Fine-tuned SecBERT trên ~78,000 CVE-CWE pairs từ NVD,
  sau khi deduplicate và lọc theo domain PE-relevant.

---

### Q: Hướng 3 (CWE Behavior Prediction) là gì? Tại sao cần?

**Trả lời:**
Khi phân tích file PE không rõ tên/version (không tra được CPE), hệ thống không thể
query NVD theo sản phẩm cụ thể. Hướng 3 giải quyết bằng cách:

1. Phân tích behavior của file: file import những API gì? (VirtualAlloc → memory injection,
   GetKeyState → keylogging, WinExec → code execution...)

2. Predict CWE (loại lỗ hổng) từ behavior profile bằng SecBERT fine-tuned

3. Dùng CWE + behavior keywords để query NVD → lấy CVE liên quan đến kỹ thuật tấn công đó

Ví dụ: File có GetKeyState + CallNextHookEx → predict Keylogging →
search "keylogger credential theft windows" → CVE về keylogger thực sự.

**Gate để tránh false positive**: Hướng 3 chỉ chạy khi EMBER >= 50% HOẶC
có ít nhất 1 HIGH/CRITICAL suspicious API. File bình thường không kích hoạt.

---

### Q: Tại sao không dùng VirusTotal API thay vì tự build?

**Trả lời:**
VirusTotal chỉ cho biết file có phải malware không (yes/no từ nhiều AV engine).
Hệ thống này làm nhiều hơn:
- Giải thích **tại sao** nguy hiểm (behavior analysis)
- Liên kết với **CVE cụ thể** đã được công bố
- Đánh giá **mức độ** nguy hiểm của từng lỗ hổng (CVSS score)
- Phân tích **package dependencies** (không phải chỉ file PE)
- Hoạt động **offline** với local model (không gửi file ra ngoài)

---

### Q: Hệ thống có thể bị bypass không?

**Trả lời:**
Mọi hệ thống bảo mật đều có giới hạn. Các trường hợp hệ thống có thể miss:

1. **Packed/obfuscated malware**: EMBER vẫn detect được qua byte entropy patterns,
   nhưng behavior analysis có thể không đủ thông tin.

2. **Zero-day exploit**: CVE chưa được công bố → không có trong NVD → không tra được.

3. **Custom malware không dùng WinAPI**: Syscall trực tiếp → không detect suspicious API.

4. **False negative rate**: EMBER ~0.06% miss rate trên test set.

Đây là lý do hệ thống được thiết kế là **công cụ hỗ trợ** chuyên gia, không thay thế hoàn toàn.

---

### Q: Hệ thống có thể scale lên production không?

**Trả lời:**
Hiện tại là prototype/thesis demo. Để production cần:
- Thay Flask development server bằng Gunicorn/uWSGI
- Queue system (Celery + Redis) cho file lớn
- Rate limiting và authentication
- Model serving với TorchServe hoặc ONNX Runtime
- Docker containerization

Tuy nhiên kiến trúc hiện tại đã tách biệt rõ ràng các module,
việc scale up là feasible.

---

### Q: Tại sao chọn SecBERT thay vì BERT/RoBERTa thông thường?

**Trả lời:**
SecBERT (Aghaei et al., 2022) được pre-trained trên corpus bảo mật gồm:
- CVE descriptions
- Security advisories
- Malware analysis reports
- Cybersecurity documentation

Các từ chuyên ngành như "heap overflow", "use-after-free", "privilege escalation"
được SecBERT hiểu đúng ngữ cảnh bảo mật, trong khi BERT thông thường có thể
hiểu nhầm hoặc thiếu context domain-specific.

Test thực tế: SecBERT đạt 97.94% vs BERT-base ~94% trên cùng tập CVE severity classification.

---

## Cách Demo Cho Hội Đồng

### Demo 1: File malware rõ ràng
Upload file có WinExec + keylogging APIs → EMBER 80%+ → CRITICAL
→ CWE prediction → CVE về kỹ thuật tương ứng

### Demo 2: File clean
Upload file code toán đơn giản → EMBER < 1% → CLEAN
→ Không ra CVE (gate skip Hướng 3)
→ Kết quả trung thực: không có gì đáng lo ngại

### Demo 3: Phần mềm có tên rõ ràng
Upload file có ProductName/Version rõ ràng trong PE header
→ CPE extracted → NVD query → CVE chính xác theo version
→ Severity scoring → kết quả theo từng CVE

### Demo 4: Package manifest
Upload requirements.txt của một project Python
→ Parse packages → CVE per package → statistics tổng hợp

---

## Điểm Nhấn Khi Trình Bày

1. **Tính thực tiễn**: Không cần chạy file, phân tích tĩnh hoàn toàn an toàn
2. **Đa nguồn dữ liệu**: NVD (342k CVE) + EMBER (600k PE) = ground truth đáng tin cậy
3. **Ensemble AI**: Không phụ thuộc một model duy nhất, tăng độ ổn định
4. **Tự động hóa**: Thay thế quy trình thủ công mất hàng giờ xuống còn vài giây
5. **Giải thích được**: Không chỉ ra kết quả, còn giải thích lý do (behavior factors, CVE links)
