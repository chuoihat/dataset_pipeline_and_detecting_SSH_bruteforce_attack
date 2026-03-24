# SSH Brute-Force Detection — ML Data Pipeline Overview

## Pipeline Architecture

```
 ┌─────────────────┐     ┌──────────────────┐
 │ RHEL Secure Logs │     │ Cowrie Attack Logs│
 │ (8.68, 8.69)    │     │ (cowrie_*.json)   │
 └────────┬────────┘     └────────┬──────────┘
          │                       │
   ┌──────▼──────┐               │
   │  Step 1     │               │
   │  Parse SSHD │               │
   └──────┬──────┘               │
          │                       │
   ┌──────▼──────────┐           │
   │  Step 2         │           │
   │  Build Benign   │           │
   │  Cowrie Logs    │           │
   └──────┬──────────┘           │
          │                       │
   ┌──────▼──────────┐   ┌──────▼──────────┐
   │  Step 3B        │   │  Step 3A        │
   │  Benign Expert  │   │  Attack Expert  │
   │  Analyze+Upscale│   │  Analyze+Score  │
   └──────┬──────────┘   └──────┬──────────┘
          │                       │
          └─────────┬─────────────┘
                    │
             ┌──────▼──────┐
             │  Step 3C    │
             │  Merge &    │
             │  Neutralize │
             └──────┬──────┘
                    │
             ┌──────▼──────────┐
             │  Step 4         │
             │  Feature        │
             │  Extraction     │
             └──────┬──────────┘
                    │
             ┌──────▼──────────┐
             │  Step 5         │
             │  Train & Eval   │
             │  Random Forest  │
             └─────────────────┘
```

---

## Step 1 — Parse RHEL SSHD Logs

**Script:** `src/step1_parse_sshd.py`

**Purpose:** Parse raw RHEL `/var/log/secure` syslog files into structured JSON events. Auto-discovers server folders (e.g., `8.68/`, `8.69/`), merges rotated log files, and extracts authentication events.

**Input:**
| File | Path | Format |
|------|------|--------|
| RHEL secure logs | `logs/8.68/secure*`, `logs/8.69/secure*` | Syslog text |

**Output:**
| File | Path | Description |
|------|------|-------------|
| Parsed events (JSON) | `output/step1/{server}/{server}_parsed_events.json` | Structured events with timestamp, host, username, src_ip, event_type |
| Parsed events (CSV) | `output/step1/{server}/{server}_parsed_events.csv` | Same as JSON, tabular format |
| Analysis report | `output/step1/{server}/{server}_analysis.json` | Per-server analytics: brute-force candidates, IP rankings, hourly activity |
| HTML report | `output/step1/{server}/{server}_analysis.html` | Visual analytics dashboard |
| Global summary | `output/step1/global_summary.json` | Cross-server aggregated statistics |
| Merged logs | `output/step1/merged/{server}_secure_merged.log` | Chronologically merged raw log lines |

**Key events extracted:** `accepted_password`, `accepted_publickey`, `failed_password`, `invalid_user`, `auth_failure`, `max_auth_exceeded`, `session_opened`, `session_closed`, `disconnect_received`, `disconnected_auth_user`, `disconnected`

---

## Step 2 — Build Benign Cowrie Logs from Parsed OpenSSH

**Script:** `src/step2_build_benign.py`

**Purpose:** Convert parsed OpenSSH events (Step 1 output) into Cowrie JSONL format. This creates benign ground-truth data in the same schema as the attack logs, enabling direct comparison.

**Input:**
| File | Path | Format |
|------|------|--------|
| Parsed events (8.68) | `output/step1/8.68/8.68_parsed_events.json` | JSON array |
| Parsed events (8.69) | `output/step1/8.69/8.69_parsed_events.json` | JSON array |
| Vietnamese IP pool | `logs/IPvn.log` | Text, one IP per line |

**Output:**
| File | Path | Description |
|------|------|-------------|
| Benign Cowrie log | `output/step2/cowrie_benign_corp.json` | NDJSON, full Cowrie-format benign events |
| Normal-login subset | `output/step2/corp_ssh_benign_cowrie.normal_login.json` | NDJSON, only login-related events |

**Key transformations:**
- OpenSSH PID-based sessions → Cowrie session IDs (SHA1-based)
- Real internal IPs → Remapped Vietnamese IPs (prevents IP leakage)
- OpenSSH event types → Cowrie eventid format (`cowrie.login.failed`, `cowrie.login.success`, etc.)
- Assigns enterprise SSH client versions with realistic weight distribution
- Fixed `dst_ip=10.0.0.4`, `dst_port=22` to match attack log format

---

## Step 3A — Attack Expert Analysis

**Script:** `src/step3a_attack_expert.py`

**Purpose:** Comprehensive analysis of Cowrie attack logs. Scores sessions for training suitability, corrects Cowrie UserDB bias, and generates feature recommendations for the downstream pipeline.

**Input:**
| File | Path | Format |
|------|------|--------|
| Cowrie attack logs | `logs/cowrie_*.json` (excluding benign/merged/selected) | NDJSON |

**Output:**
| File | Path | Description |
|------|------|-------------|
| Selected attack events | `output/step3a/attack_selected.json` | NDJSON, filtered and bias-corrected events |
| Feature config | `output/step3a/pipeline_feature_config.json` | JSON, active/dropped/shortcut features for downstream |
| Analysis report (JSON) | `output/step3a/attack_expert_report.json` | Full statistics with session timelines |
| Analysis report (HTML) | `output/step3a/attack_expert_report.html` | Visual report with decision reasoning |

**Key decisions made by the expert:**

1. **Session scoring:** Select sessions with SSH login events (score=1), discard scan-only/telnet (score=0)
2. **Cowrie UserDB bias correction:** Smart relabeling — 97% of `root:login.success` → `login.failed` (keep 3% to preserve realistic 1-8% success rate). Cite: Owezarski (2015), Hofstede et al. (2014)
3. **IP-level campaign classification:** Aggregate all sessions per source IP, compute total `fc` (failed count), unique failed usernames, inter-login intervals. Classify each IP (priority order): `spraying` (unique_fail/fc ≥ 0.5, fc ≥ 5), `bursty` (fc ≥ 5, avg_interval < 3s), `low_and_slow` (avg_interval ≥ 30s), `hit_and_run` (fc ≤ 2), `success_only` (fc=0). This IP-level approach correctly captures distributed botnet campaigns where each session has low fc but the IP aggregate reveals the attack pattern.
4. **Feature recommendation:**
   - Drop `time_of_day_avg` if attack data < 24 hours (temporal artifact)
   - Drop `num_failed_days` if attack data < 2 days (IP rotation makes it unreliable)
   - Flag `success_ratio` as shortcut if no bias correction applied
   - Monitor `client_version_category` if one version dominates >80%
   - Exclude `num_failed_ports`, `ip_entropy` as shortcut features

**Report sections:** Data summary, session scoring criteria, bias detection/correction, EventID distribution, event transitions, IP-level campaign classification, IP analysis, client versions, top failed usernames, session timeline summary, feature recommendations with scientific citations, decision summary table.

---

## Step 3B — Benign Expert Analysis & Upscale

**Script:** `src/step3b_benign_expert.py`

**Purpose:** Analyze the Cowrie-format benign logs (Step 2 output), verify against original OpenSSH data, measure empirical distributions, and generate synthetic benign sessions to achieve 1:1 balance with attack feature vectors.

**Input:**
| File | Path | Format |
|------|------|--------|
| Benign Cowrie log | `output/step2/cowrie_benign_corp.json` | NDJSON |
| OpenSSH parsed events | `output/step1/8.{68,69}/8.{68,69}_parsed_events.json` | JSON array |
| Vietnamese IP pool | `logs/IPvn.log` | Text |
| Feature config (from 3A) | `output/step3a/pipeline_feature_config.json` | JSON |

**Output:**
| File | Path | Description |
|------|------|-------------|
| Upscaled benign events | `output/step3b/benign_upscaled.json` | NDJSON, real + synthetic benign events |
| Analysis report (JSON) | `output/step3b/benign_expert_report.json` | Full statistics with empirical distributions |
| Analysis report (HTML) | `output/step3b/benign_expert_report.html` | Visual report with decision reasoning |

**Key decisions made by the expert:**

1. **Cross-verification:** Compare Cowrie sessions against OpenSSH PID groups and usernames
2. **Archetype classification:** `clean_login` (0 fails), `typo` (1-3 fails + success), `troubleshoot` (4+ fails + success), `give_up` (only fails)
3. **Upscale plan:** Target = attack feature vectors count (1:1 ratio), proportional allocation by archetype
4. **Parametric bootstrap:** Duration from log-normal distribution, usernames/client versions from empirical frequency, timestamps from business-hour-weighted distribution (UTC+7)
5. **Session clustering:** 5% of synthetic sessions share IPs to create multi-session benign feature vectors

**Scientific basis:** Efron & Tibshirani (1993), Cochran (1977), Davison & Hinkley (1997), Robinson (1950)

---

## Step 3C — Merge & Neutralize

**Script:** `src/step3c_merge.py`

**Purpose:** Merge selected attack events (3A) with upscaled benign events (3B) and neutralize domain shortcuts to prevent data leakage.

**Input:**
| File | Path | Format |
|------|------|--------|
| Selected attack events | `output/step3a/attack_selected.json` | NDJSON |
| Upscaled benign events | `output/step3b/benign_upscaled.json` | NDJSON |

**Output:**
| File | Path | Description |
|------|------|-------------|
| Merged dataset | `output/step3c/cowrie_merged.json` | NDJSON, sorted by timestamp |
| Merge report (HTML) | `output/step3c/step3c_merge.html` | Timeline, data origin distribution, neutralization details |

**Neutralization:**
- `sensor` → `cowrie-ssh` (unified)
- `dst_port` → `22` (unified)

These prevent the model from using sensor name or port number as a shortcut to distinguish attack from benign data.

---

## Step 4 — Feature Extraction

**Script:** `src/step4_feature_extraction.py`

**Purpose:** Extract behavioral feature vectors per `(src_ip, 60-minute window)` from the merged dataset. Apply rule-based ground-truth labeling, DBSCAN clustering, and temporal train/val/test split.

**Input:**
| File | Path | Format |
|------|------|--------|
| Merged dataset | `output/step3c/cowrie_merged*.json` | NDJSON |
| Feature config | `output/step3a/pipeline_feature_config.json` | JSON (optional) |

**Output:**
| File | Path | Description |
|------|------|-------------|
| Features (CSV) | `output/step4/ml_features.csv` | Tabular feature vectors |
| Features (JSON) | `output/step4/ml_features.json` | JSON array of feature dicts |
| Features (HTML) | `output/step4/ml_features.html` | Visual feature report |

**Feature set (13 active features after expert recommendation):**

| # | Feature | Group | Description |
|---|---------|-------|-------------|
| 1 | `failed_attempts` | Frequency | Count of login.failed events in window |
| 2 | `num_unique_users` | Account | Distinct usernames attempted |
| 3 | `username_entropy` | Account | Shannon entropy of username distribution |
| 4 | `success_ratio` | Account | login.success / (success + failed) |
| 5 | `avg_time_between_attempts` | Temporal | Mean seconds between login events |
| 6 | `login_interval_variance` | Temporal | Variance of inter-login intervals |
| 7 | `client_version_category` | Meta | Integer-encoded SSH client category |
| 8 | `time_to_auth` | Inter-event | Seconds from connect to first auth event |
| 9 | `session_duration` | Inter-event | Session duration in seconds |
| 10 | `min_inter_arrival` | Inter-event | Minimum inter-arrival time between events |
| 11 | `max_inter_arrival` | Inter-event | Maximum inter-arrival time between events |
| 12 | `hour_sin` | Cyclic temporal | sin(2π × hour/24) — cyclic hour encoding |
| 13 | `hour_cos` | Cyclic temporal | cos(2π × hour/24) — cyclic hour encoding |

**Dropped features (by expert recommendation):**
- `time_of_day_avg` — Attack data spans <24h, making this a temporal artifact
- `num_failed_days` — Attack data spans <2 days, IP rotation makes it unreliable

**Shortcut features (excluded from training):**
- `num_failed_ports` — Depends on dataset assembly rather than attack behavior
- `ip_entropy` — Depends on IP assignment methodology

**Labeling:** `final_label` based on `data_origin` (attack_cowrie → 1, benign_corp* → 0). `weak_label` from rule-based heuristics for cross-validation.

**Split:** Temporal 60/20/20 (train/val/test) sorted by `window_start` to prevent temporal leakage.

---

## Step 5 — Model Training, Evaluation & Scenario Study

**Script:** `src/step5_train.py`

**Purpose:** Train a Random Forest classifier on the temporal train split, evaluate on test set, run comprehensive quality checks, and generate a detailed evaluation report. Automatically runs the ratio scenario ablation study (RQ8) unless `--skip-scenarios` is used.

**Input:**
| File | Path | Format |
|------|------|--------|
| Features (JSON) | `output/step4/ml_features.json` | JSON array |
| Feature config | `output/step3a/pipeline_feature_config.json` | JSON |

**Output:**
| File | Path | Description |
|------|------|-------------|
| Trained model | `output/step5/models/random_forest.pkl` | Pickle |
| Evaluation report (HTML) | `output/step5/reports/evaluation_report.html` | Comprehensive dashboard (see sections below) |
| Confusion matrix | `output/step5/reports/confusion_matrix.png` | Visualization |
| ROC curve | `output/step5/reports/roc_curve.png` | Visualization |
| PR curve | `output/step5/reports/pr_curve.png` | Visualization |
| Feature importance | `output/step5/reports/feature_importance.png` | Visualization |
| Probability distribution | `output/step5/reports/probability_distribution.png` | Visualization |
| SHAP plots | `output/step5/reports/shap_*.png` | SHAP summary + bar plots |

**Evaluation report contains (in order):**
1. **Tổng quan mô hình** — model architecture, split sizes, feature list
2. **Kết quả huấn luyện** — Accuracy, Precision, Recall, F1, Macro-F1, ROC-AUC, PR-AUC (with detailed metric explanations for ML expert)
3. **Phân tích Feature Importance** — Gini + embedded vector charts
4. **Đánh giá chất lượng Dataset (6 khía cạnh)** — Statistical Validity, Class Balance, Fisher's Discriminant Ratio, Label Consistency, Separability, Temporal Stability (Tukey 1977; He & Garcia 2009; Ho & Basu 2002; Northcutt et al. 2021; Tashman 2000)
5. **Thực nghiệm tỉ lệ Benign:Attack (RQ8)** — 5 scenario comparison table, charts, dataset quality per scenario, ML expert evaluation and recommendation
6. **SHAP Analysis** — Beeswarm + bar plots
7. **Rolling Time-Series CV** — expanding window cross-validation
8. **Robustness Tests** — synthetic attack/benign scenario predictions
9. **Verification checks** — unit tests, consistency checks
10. **Cơ sở khoa học** — references for all methods used
11. **Debug Log** — full Vietnamese debug output from ViLogger

**Key CLI flags:**
- `--train` — run training pipeline
- `--demo` — run near-real-time detection demo
- `--skip-scenarios` — skip ratio ablation study (faster)
- `--skip-shap` — skip SHAP analysis
- `--features-json PATH` — override default features path
- `--metrics-json PATH` — write metrics summary to JSON

---

## Utility: Session Analyzer

**Script:** `src/utils/session_analyzer.py`

**Purpose:** Standalone tool to generate detailed EventID and session statistics for any single Cowrie JSONL log file. Produces the same "Session timeline summary" format used as reference in the expert tools.

**Usage:**
```bash
python3 src/utils/session_analyzer.py logs/cowrie_1.json
python3 src/utils/session_analyzer.py output/step2/cowrie_benign_corp.json
```

**Output:** JSON + HTML reports in `output/reports/`

---

## Anti-Data-Leakage Measures

The pipeline implements a multi-layer defense against data leakage:

1. **Domain neutralization:** Unified `sensor` and `dst_port` (Step 3C)
2. **IP remapping:** Real internal IPs → Vietnamese IPs (Step 2)
3. **Cowrie bias correction:** Smart relabeling of root login.success (Step 3A)
4. **Feature dropping:** Remove temporal artifacts based on data characteristics (Step 3A)
5. **Shortcut feature exclusion:** `num_failed_ports`, `ip_entropy` excluded from training
6. **Temporal split:** 60/20/20 chronological split prevents temporal leakage (Step 4)
7. **Dynamic feature config:** `pipeline_feature_config.json` propagates expert decisions to all downstream steps

---

## Running the Full Pipeline

```bash
cd Code-Full

# Step 1: Parse RHEL secure logs
python3 src/step1_parse_sshd.py

# Step 2: Build benign Cowrie logs
python3 src/step2_build_benign.py

# Step 3A: Attack expert analysis
python3 src/step3a_attack_expert.py

# Step 3B: Benign expert analysis & upscale
python3 src/step3b_benign_expert.py

# Step 3C: Merge & neutralize
python3 src/step3c_merge.py

# Step 4: Feature extraction
python3 src/step4_feature_extraction.py

# Step 5: Train + evaluate + auto-run scenario study (RQ8)
python3 src/step5_train.py --train
```

**Note:** Step 5 with `--train` automatically runs the ratio scenario ablation study (5 scenarios). This takes ~2-3 minutes. To skip: `python3 src/step5_train.py --train --skip-scenarios`.

### Optional — Run ratio scenarios standalone

If you only want to re-run the scenario study without re-training the main model:

```bash
python3 src/run_ratio_scenarios.py
python3 src/run_ratio_scenarios.py --scenarios S0_natural,S2_1to1  # subset
```

**Documentation:** [docs/03_ratio_scenario_study.md](03_ratio_scenario_study.md)

**Step 3B CLI (single run):** `--benign-attack-ratio natural | 1:2 | 1:1 | 2:1 | 3:1`

**Step 4 / Step 5 overrides:** `step4_feature_extraction.py --log-dir … --output-dir …` · `step5_train.py --features-json … --metrics-json … --skip-demo --skip-shap --skip-scenarios`

---

## Scientific References

- **Efron & Tibshirani (1993):** *An Introduction to the Bootstrap* — parametric bootstrap methodology
- **Cochran (1977):** *Sampling Techniques* — stratified sampling and representativeness
- **Davison & Hinkley (1997):** *Bootstrap Methods and Their Application* — bootstrap validity conditions
- **Robinson (1950):** Ecological fallacy — matching aggregation structure
- **Owezarski (2015):** SSH brute-force success rate 2-8%
- **Hofstede et al. (2014):** SSH brute-force success rate 1-5%
- **Sommer & Paxson (2010):** Behavioral features over temporal for IDS evaluation
- **RFC 4253 (Ylonen & Lonvick, 2006):** SSH Transport Layer Protocol
- **He & Garcia (2009):** *Learning from Imbalanced Data* — class ratio analysis (RQ8)
- **Tukey (1977):** *Exploratory Data Analysis* — statistical validity framework
- **Ho & Basu (2002):** Dataset complexity measures — Fisher's Discriminant Ratio
- **Northcutt et al. (2021):** Confident Learning — label quality detection
- **Tashman (2000):** Rolling-origin evaluation — temporal stability
- **Arp et al. (2022):** *Dos and Don'ts of ML in Computer Security* — evaluation best practices
- **Kaufman et al. (2012):** Leakage detection framework
- **Lorena et al. (2019):** Meta-features for dataset characterization
