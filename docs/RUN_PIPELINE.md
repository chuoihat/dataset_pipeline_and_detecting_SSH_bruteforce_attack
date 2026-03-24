# Hướng dẫn chạy pipeline hoàn chỉnh (Step 1 → 6)

Làm việc từ thư mục gốc dự án:

```bash
cd /path/to/Code-Full
```

**Yêu cầu môi trường:** Python 3 với các gói: `numpy`, `pandas`, `scikit-learn`, `matplotlib` (và tùy chọn `shap` cho Step 5 đầy đủ).

---

## Luồng tổng quan

| Bước | Script | Mô tả ngắn |
|------|--------|------------|
| **1** | `src/step1_parse_sshd.py` | Parse log RHEL OpenSSH → JSON |
| **2** | `src/step2_build_benign.py` | Sinh Cowrie benign từ Step 1 |
| **3A** | `src/step3a_attack_expert.py` | Phân tích attack, bias, chọn event attack |
| **3B** | `src/step3b_benign_expert.py` | Phân tích benign, upscale (mặc định 1:1) |
| **3C** | `src/step3c_merge.py` | Ghép attack + benign, neutralize |
| **4** | `src/step4_feature_extraction.py` | Trích feature, DBSCAN, nhãn |
| **5** | `src/step5_train.py` | Huấn luyện RF, đánh giá dataset (6 khía cạnh), **tự động chạy scenario (RQ8)**, báo cáo HTML |
| **6** | `src/run_ratio_scenarios.py` | **Standalone (tùy chọn):** chạy scenario riêng lẻ nếu không muốn dùng tự động từ Step 5 |

**Step 5 `--train` tự động gọi Step 6** (5 scenario ablation study). Kết quả scenario + đánh giá chất lượng dataset được nhúng trong `evaluation_report.html`. Dùng `--skip-scenarios` để bỏ qua.

---

## Pipeline chính (Step 1 → 5)

Chạy **theo thứ tự** (mỗi lệnh một dòng):

```bash
# 1 — Parse SSHD
python3 src/step1_parse_sshd.py

# 2 — Cowrie benign từ OpenSSH đã parse
python3 src/step2_build_benign.py

# 3A — Attack expert (bắt buộc trước 3B nếu dùng cùng attack reference)
python3 src/step3a_attack_expert.py

# 3B — Benign expert + upscale (mặc định ghi output/step3b/)
python3 src/step3b_benign_expert.py

# 3C — Merge
python3 src/step3c_merge.py

# 4 — Feature extraction (đọc merged trong output/step3c/)
python3 src/step4_feature_extraction.py

# 5 — Train + evaluation + dataset quality + scenario study (RQ8)
python3 src/step5_train.py --train

# Nếu muốn bỏ qua scenario study (nhanh hơn ~3 phút):
# python3 src/step5_train.py --train --skip-scenarios
```

**Đầu vào dữ liệu thô:** đặt log RHEL trong `logs/8.68/`, `logs/8.69/` và log Cowrie attack trong `logs/cowrie_*.json` (theo mặc định trong từng script).

**Đầu ra chính:**

- `output/step3a/attack_selected.json` — Attack log đã lọc + sửa bias
- `output/step3a/pipeline_feature_config.json` — 13 active features, IP campaign dist.
- `output/step3b/benign_upscaled.json` — Benign log + synthetic
- `output/step3c/cowrie_merged.json` — Merged + neutralized dataset
- `output/step4/ml_features.json` — 13 feature vectors per (IP, 60-min window)
- `output/step5/reports/evaluation_report.html` — **Report tổng hợp:**
  - Kết quả huấn luyện (Accuracy, F1, AUC, ...)
  - Feature Importance (Gini + SHAP)
  - Đánh giá chất lượng Dataset (6 khía cạnh: Statistical Validity, Class Balance, Fisher Ratio, Label Consistency, Separability, Temporal Stability)
  - So sánh 5 scenario thực nghiệm tỉ lệ (RQ8) + ML expert evaluation
  - Robustness tests, Rolling CV, Debug log
- `output/ratio_study/` — Output riêng từng scenario (step3b/3c/4/5)

---

## Step 6 — Thực nghiệm tỉ lệ (RQ8)

### Step 6 làm gì?

- **Tự động chạy khi** `python3 src/step5_train.py --train` (trừ khi dùng `--skip-scenarios`)
- Đọc **`output/step3a/attack_selected.json`** (phải chạy Step 3A trước).
- Với **mỗi scenario** (mặc định 5: natural, 1:2, 1:1, 2:1, 3:1):
  - Chạy **Step 3B** với `--benign-attack-ratio` tương ứng
  - **Step 3C** merge
  - **Step 4** feature extraction
  - **Step 5** train (có `--skip-demo --skip-shap --skip-scenarios` để nhanh)
- Ghi kết quả theo thư mục **`output/ratio_study/<scenario_id>/`**
- Tổng hợp: **`scenario_comparison.html`**, `scenario_comparison.json`, `EXPERT_SCENARIO_COMPARISON.md`
- Kết quả được **nhúng vào** `evaluation_report.html` (Step 5) gồm: bảng so sánh, biểu đồ, chất lượng dataset per scenario, ML expert evaluation

### Cách chạy Step 6 (standalone — nếu cần chạy lại riêng)

```bash
cd /path/to/Code-Full

# Đảm bảo đã có attack_selected.json
python3 src/run_ratio_scenarios.py
```

Chỉ chạy một vài scenario:

```bash
python3 src/run_ratio_scenarios.py --scenarios S0_natural,S2_1to1
```

Đổi thư mục gốc output (mặc định `output/ratio_study`):

```bash
python3 src/run_ratio_scenarios.py --out-root output/my_ratio_run
```

### Đầu ra Step 6 (quan trọng)

| File / thư mục | Ý nghĩa |
|----------------|---------|
| `output/ratio_study/scenario_comparison.html` | Báo cáo HTML so sánh **tất cả** scenario (biểu đồ + bảng) |
| `output/ratio_study/scenario_comparison.json` | Metric từng scenario (train/val/test split, F1, AUC, dataset quality, …) |
| `output/ratio_study/EXPERT_SCENARIO_COMPARISON.md` | Bảng Markdown tóm tắt |
| `output/ratio_study/S2_1to1/step5/reports/evaluation_report.html` | Step 5 **riêng** cho scenario S2 (ví dụ) |

Mỗi scenario có đủ: `step3b/`, `step3c/`, `step4/`, `step5/` như một pipeline thu nhỏ.

---

## Pipeline đầy đủ (bao gồm scenario study)

```bash
cd /path/to/Code-Full

python3 src/step1_parse_sshd.py
python3 src/step2_build_benign.py
python3 src/step3a_attack_expert.py
python3 src/step3b_benign_expert.py
python3 src/step3c_merge.py
python3 src/step4_feature_extraction.py
python3 src/step5_train.py --train    # ← tự động chạy 5 scenario (RQ8)
```

**Lưu ý:**
- `--train` tự động gọi `run_ratio_scenarios.py` → thêm ~3 phút cho 5 scenario.
- Để bỏ qua scenario: `python3 src/step5_train.py --train --skip-scenarios`
- Các file trong `output/step3b`, `output/step3c`, `output/step4`, `output/step5` là kết quả **pipeline chính** — không bị scenario ghi đè (scenario chỉ ghi vào `output/ratio_study/`).

---

## Xử lý lỗi thường gặp

| Lỗi | Cách xử lý |
|-----|------------|
| `Missing ... attack_selected.json` | Chạy `step3a_attack_expert.py` trước |
| `ModuleNotFoundError: numpy` | Cài deps: `pip install numpy pandas scikit-learn matplotlib` |
| Step 5 chạy lâu (do scenario) | Dùng `--skip-scenarios` hoặc `--scenario-ids S2_1to1` |
| Scenario study bị loop vô hạn | Đã fix: `run_ratio_scenarios.py` luôn truyền `--skip-scenarios` cho Step 5 con |

---

*Tài liệu liên quan: `docs/00_pipeline_overview.md`, `docs/03_ratio_scenario_study.md`, `docs/01_repo_structure.md`.*
