# Slide giới thiệu thành viên — Nhóm IA_1802

> Mỗi thành viên đảm nhận một module trong pipeline. Khi trình bày, mỗi người tự nói về phần của mình (1–2 phút).

## Template slide (PowerPoint / Canva)

```
┌─────────────────────────────────────────────────────────────┐
│  NHÓM IA_1802 — AI VULNERABILITY SCANNER                    │
│  Đề tài: Hệ thống quét lỗ hổng bảo mật ứng dụng AI          │
│  GVHD: <Tên thầy hướng dẫn>                                 │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ [Ảnh thẻ]    │   │ [Ảnh thẻ]    │   │ [Ảnh thẻ]    │   │ [Ảnh thẻ]    │
│              │   │              │   │              │   │              │
│ Họ tên       │   │ Họ tên       │   │ Họ tên       │   │ Họ tên       │
│ MSSV         │   │ MSSV         │   │ MSSV         │   │ MSSV         │
│ Vai trò      │   │ Vai trò      │   │ Vai trò      │   │ Vai trò      │
│ Module phụ   │   │ Module phụ   │   │ Module phụ   │   │ Module phụ   │
│ trách        │   │ trách        │   │ trách        │   │ trách        │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

## Bảng phân công (điền tên thật vào)

| # | Họ tên | MSSV | Vai trò | Module / file phụ trách |
|---|--------|------|---------|-------------------------|
| 1 | <Tên 1> | <MSSV> | Team Lead + AI Severity | `backend/bert_severity_classifier.py`, `backend/ai/severity_pipeline.py` |
| 2 | <Tên 2> | <MSSV> | AI CWE Classification | `backend/cwe_predictor.py`, `models/bert_cwe/` |
| 3 | <Tên 3> | <MSSV> | Malware Detection (XGBoost) | `backend/xgboost_severity_classifier.py`, `backend/ai/ember1390_encoder.py` |
| 4 | <Tên 4> | <MSSV> | Static Analyzer + CPE | `backend/static_analyzer.py`, `backend/cpe_extractor.py`, `backend/cpe_semantic_matcher.py` |
| 5 | <Tên 5> | <MSSV> | NVD API + Backend Flask | `backend/app.py`, `backend/nvd_api_v2.py`, `backend/package_analyzer.py` |
| 6 | <Tên 6> | <MSSV> | Frontend + Demo + Test | `frontend/`, `tests/`, video demo, slide |

> Nếu nhóm dưới 6 người: gộp các vai trò gần nhau (vd: AI Severity + AI CWE; Static + CPE + NVD).

## Checklist chuẩn bị slide member

- [ ] Ảnh thẻ rõ mặt (3x4, nền trắng), kích thước đồng đều
- [ ] Font chữ thống nhất, cỡ chữ ≥ 18pt
- [ ] Logo trường + logo nhóm (nếu có)
- [ ] 1 slide tổng (4–6 ảnh) + 1 slide riêng cho team lead nếu cần
- [ ] Mỗi người chuẩn bị 1 câu giới thiệu ngắn (10s): "Em là X, em phụ trách module Y, đóng góp chính là Z"

## Slide tổng quan đóng góp (kèm theo)

| Thành viên | % đóng góp | Đóng góp chính |
|------------|------------|----------------|
| Tên 1 | 20% | Pipeline ensemble BERT+XGBoost, đạt 98.13% F1 |
| Tên 2 | 18% | Fine-tune SecBERT cho 15 lớp CWE, đạt 85.58% macro-F1 |
| Tên 3 | 18% | Tích hợp EMBER 2017 (1390 features), đạt 99.06% F1 |
| Tên 4 | 16% | Static analyzer + CPE matcher (rapidfuzz + semantic) |
| Tên 5 | 14% | Backend Flask, NVD API v2, cache layer |
| Tên 6 | 14% | UI, integration tests, demo video |

> **Lưu ý**: Tổng phải = 100%. Điền số thật theo thoả thuận nhóm.
