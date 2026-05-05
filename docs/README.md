# IA_1802 — Tài liệu cho buổi bảo vệ

> Toàn bộ tài liệu này được tạo dựa trên feedback của thầy hướng dẫn (ngày 04/05/2026):
>
> 1. Bổ sung slide giới thiệu member
> 2. In bảng tên
> 3. Demo chia theo ngữ cảnh tình huống: từ basic tới nâng cao trong doanh nghiệp
> 4. Kiến thức lý thuyết và source code phải chia sẻ cho các thành viên
> 5. Phần AI phải chú ý tới các đặc trưng (features)
> 6. Cần show bảng kết quả so sánh trong việc chọn dataset
> 7. Các chỉ số F1, Accuracy

## Bản đồ tài liệu

| Feedback của thầy | File trong repo |
|--------------------|-----------------|
| 1. Slide giới thiệu member | [`members.md`](members.md) |
| 2. In bảng tên | [`nametags.md`](nametags.md) |
| 3. Demo theo ngữ cảnh tình huống | [`demo_scenarios.md`](demo_scenarios.md) |
| 4. Chia sẻ lý thuyết + source code | [`modules.md`](modules.md) |
| 5. Đặc trưng các model AI | [`ai_features.md`](ai_features.md) |
| 6. Bảng so sánh dataset | [`dataset_comparison.md`](dataset_comparison.md) |
| 7. Chỉ số F1, Accuracy | [`results.md`](results.md) |

## Lịch trình chuẩn bị (đề xuất 7 ngày)

| Ngày | Việc cần làm | Người phụ trách |
|------|---------------|------------------|
| Day 1 | Chốt template slide + ảnh thẻ tất cả member | Member 6 (Frontend/QA) |
| Day 2 | In bảng tên + lanyard | Member 4 |
| Day 3 | Tạo file demo cho 3 kịch bản trong `tests/demo_*` | Member 1 + Member 6 |
| Day 4 | Pre-warm NVD cache + record video backup | Member 5 |
| Day 5 | Tập thuyết trình lần 1 (full run) | Cả nhóm |
| Day 6 | Tập thuyết trình lần 2 + Q&A drill | Cả nhóm |
| Day 7 | Buffer / sửa nhanh phát hiện vấn đề | Cả nhóm |

## Cấu trúc slide đề xuất (~25 slides, 20 phút)

1. **Title slide** — Tên đề tài, GVHD, nhóm IA_1802
2. **Members** ([`members.md`](members.md)) — Slide 4 ảnh
3. **Phân công** — Bảng đóng góp %
4. **Vấn đề & Mục tiêu** — Tại sao cần AI cho vulnerability scan
5. **Pipeline tổng quan** — Diagram architecture
6. **Module 1: Static Analyzer** — Demo nhanh
7. **Module 2: Package + CPE Matcher**
8. **Module 3: NVD API + Cache**
9. **AI Component 1: SecBERT (Severity)** — Đặc trưng + F1 98.13%
10. **AI Component 2: SecBERT (CWE)** — 15 class, F1 85.58%
11. **AI Component 3: XGBoost EMBER (Malware)** — F1 99.06%
12. **AI Component 4: Ensemble** — Confidence-weighted voting
13. **Đặc trưng AI** ([`ai_features.md`](ai_features.md)) — Feature importance
14. **Dataset Comparison** ([`dataset_comparison.md`](dataset_comparison.md)) — Tại sao chọn NVD + EMBER
15. **Kết quả** ([`results.md`](results.md)) — Bảng so sánh model + Confusion matrix
16. **Demo 1: Basic (Dev cá nhân)** ([`demo_scenarios.md#kịch-bản-1`])
17. **Demo 2: SME (DevOps)**
18. **Demo 3: Enterprise (Security team)**
19. **Contextual Scoring** — Asset criticality
20. **Hạn chế hiện tại** — Honest limits
21. **Hướng phát triển** — Future work
22. **Đóng góp & Kết luận**
23. **Q&A**
24. **Tài liệu tham khảo**
25. **Cảm ơn**

## Quy tắc trình bày

- Mỗi slide ≤ 7 dòng chữ
- Mỗi member nói ≥ 1 phần (chia đều thời gian)
- Mỗi đoạn dài ≤ 2 phút (đổi người liên tục để giữ năng lượng)
- Demo dùng video backup ≤ 30s + live demo nếu mạng ổn
- Có sẵn `print_friendly.pdf` của báo cáo enterprise scan để phát cho hội đồng

## Tài nguyên đính kèm

| File | Vị trí | Mục đích |
|------|--------|----------|
| Template Canva | <link drive nhóm> | Slide design |
| Video demo backup | <link drive nhóm> | Backup khi mạng lỗi |
| File mẫu basic | `tests/demo_basic_login.py` | Demo kịch bản 1 |
| File mẫu SME | `tests/demo_intermediate_requirements.txt` | Demo kịch bản 2 |
| File mẫu enterprise | `tests/demo_enterprise/` | Demo kịch bản 3 |
| Báo cáo PDF mẫu | `docs/sample_report.pdf` | Phát hội đồng |

## Liên hệ

| Vai trò | Member | Liên hệ |
|---------|--------|---------|
| Team lead | Lê Tiến Dũng | <email/zalo> |
| GVHD | <Tên thầy> | <email> |
