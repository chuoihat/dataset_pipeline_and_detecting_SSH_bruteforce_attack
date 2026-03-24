# Thí nghiệm scenario tỉ lệ Benign : Attack

## 1. Mục đích

Trả lời câu hỏi báo cáo: *với cùng log attack và cùng quy trình expert (3A–3C), việc chọn **mục tiêu số phiên benign** (và synthetic bootstrap) ở các tỉ lệ khác nhau so với **tham chiếu attack** từ Step 3A ảnh hưởng thế nào tới dataset và tới metric học máy?*

Đây là **ablation có kiểm soát**: giữ nguyên `attack_selected.json`, chỉ đổi mục tiêu upscale/subsample ở Step 3B.

---

## 2. Vì sao chọn **5** scenario?


| #   | Scenario       | Tỉ lệ (benign:attack)             | Lý do thiết kế                                                                                                       |
| --- | -------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| 1   | **S0_natural** | `natural` (893 thực, 0 synthetic) | **Baseline độ lệch thật** — không can thiệp sampling; so sánh với mọi scenario có upscale.                           |
| 2   | **S1_1to2**    | 1:2                               | **Train thiên về attack** — kiểm tra hành vi khi benign trong train hiếm hơn tham chiếu attack.                      |
| 3   | **S2_1to1**    | 1:1                               | **Điểm làm việc mặc định** của pipeline (khớp `estimated_attack_feature_vectors`).                                   |
| 4   | **S3_2to1**    | 2:1                               | **Benign gấp đôi** — kiểm tra độ nhạy khi tăng trọng benign / synthetic.                                             |
| 5   | **S4_3to1**    | 3:1                               | **Stress synthetic** — tỉ lệ benign mục tiêu cao, nhiều bootstrap hơn; xem độ bền metric và rủi ro pattern artifact. |


**Cơ sở khoa học (tổng quát):**

- **He & Garcia (2009):** học từ dữ liệu lệch lớp — so sánh nhiều **training prior** là hợp lệ; không có định lý “chỉ được 1:1”.
- **Cochran (1977):** phân bổ theo archetype **tỷ lệ** (bootstrap trong Step 3B) giữ cấu trúc phân phối khi tăng/giảm quy mô.
- **Arp et al. (2022):** khi **temporal test** suy biến (một lớp), metric test phải đọc kèm hạn chế; bổ sung **train_macro_f1**, **leakage audit** để so sánh scenario.

Năm điểm là **đủ** cho báo cáo cử nhân / thạc sĩ ngắn: hai đầu (tự nhiên + stress 3:1), một điểm giữa (1:1), hai điểm giữa–lệch (1:2, 2:1). Thêm scenario thứ 6+ chỉ hữu ích nếu có **cost FN/FP** cụ thể hoặc dữ liệu triển khai mới.

---

## 3. Cơ chế kỹ thuật

1. **Tham chiếu attack:** `output/step3a/pipeline_feature_config.json` → `estimated_attack_feature_vectors`.
2. **Mục tiêu phiên benign:** `target_sessions = round(attack_ref × a / b)` với tỉ lệ `a:b`.
3. **Subsample:** nếu `target_sessions < |sessions thực|`, lấy ngẫu nhiên có seed cố định (`--seed`) để **tái lập được**.
4. **Upscale:** nếu `target_sessions > |sessions thực|`, giữ toàn bộ thực + synthetic theo kế hoạch archetype (như cũ).
5. **Merge / feature / train:** giống pipeline chính; mỗi scenario ghi ra thư mục riêng.

**Script điều phối:** `src/run_ratio_scenarios.py`  
**Tích hợp vào pipeline chính:** `src/step5_train.py --train` tự động gọi `run_ratio_scenarios.py` (trừ khi dùng `--skip-scenarios`). Kết quả so sánh được nhúng trực tiếp vào `evaluation_report.html` của Step 5.

**Output tổng hợp:**

- `output/ratio_study/scenario_comparison.json` — bảng metric gộp + dataset quality per scenario
- `output/ratio_study/scenario_comparison.html` — báo cáo HTML so sánh (biểu đồ + bảng + expert commentary)
- `output/ratio_study/EXPERT_SCENARIO_COMPARISON.md` — bảng Markdown tóm tắt
- `output/step5/reports/evaluation_report.html` — **cũng chứa** bảng so sánh scenario, dataset quality comparison, và ML expert evaluation

---

## 4. Metric nên đọc khi so sánh


| Metric                      | Ghi chú                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `train_benign_share`        | Phản ánh độ lệch **thực tế trong train** (theo vector cửa sổ).                                   |
| `train_macro_f1`            | So sánh công bằng giữa lớp khi train có đủ 2 lớp.                                                |
| `test_macro_f1` / `test_f1` | Chỉ diễn giải khi test có **cả** attack và benign; nếu `null`/thiếu lớp → xem cảnh báo temporal. |
| `label_agreement`           | Tỉ lệ đồng thuận final_label ↔ weak_label — giảm mạnh nếu synthetic distort pattern.            |
| Dataset quality per scenario | Bảng "Chất lượng Dataset theo scenario" trong Step 5 report: tổng mẫu, attack/benign, missing.   |


---

## 5. Hạn chế (cần nêu trong báo cáo)

- Tỉ lệ được áp ở mức **mục tiêu phiên benign** vs **scalar tham chiếu attack**; sau Step 4, tỉ lệ **feature vector** có thể lệch nhẹ do gom `(ip, window)`.
- **Temporal split** có thể làm tập val/test không đại diện cho cả hai lớp — không phải lỗi scenario, mà là đặc tả dữ liệu (attack ngắn, benign dài).
- **Synthetic** tăng theo S3/S4 — tăng rủi ro **domain shift** so với benign thực; cần trích dẫn bootstrap + hạn chế external validity.

---

## Tài liệu tham khảo

- He, H., & Garcia, E. A. (2009). *Learning from Imbalanced Data.* IEEE TKDE.
- Cochran, W. G. (1977). *Sampling Techniques.*
- Efron, B., & Tibshirani, R. (1993). *An Introduction to the Bootstrap.*
- Arp, D., et al. (2022). *Dos and Don'ts of Machine Learning in Computer Security.* USENIX Security.
- Sommer, R., & Paxson, V. (2010). *Outside the Closed World.* IEEE S&P.

