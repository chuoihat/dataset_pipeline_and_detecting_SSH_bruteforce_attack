# SSH Brute-Force Attack Detection using Machine Learning

Detection of SSH brute-force attacks from Cowrie honeypot logs using a Random Forest classifier with behavioral feature engineering.

## Overview

This project implements a complete ML pipeline for detecting SSH brute-force attacks:

1. **Data Collection:** Cowrie honeypot attack logs + RHEL OpenSSH server benign logs
2. **Data Processing:** Expert analysis tools that automatically analyze, filter, correct bias, and balance the dataset
3. **Feature Engineering:** 13 behavioral features extracted per (src_ip, 1-hour window)
4. **Model Training:** Random Forest with temporal train/val/test split (60/20/20)
5. **Evaluation:** Dataset quality assessment (6 aspects), 5-scenario ratio ablation study (RQ8), SHAP analysis

## Quick Start

```bash
# Requires Python 3.10+
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the full pipeline (Step 1 → 5 + auto scenario study)
python3 src/step1_parse_sshd.py
python3 src/step2_build_benign.py
python3 src/step3a_attack_expert.py
python3 src/step3b_benign_expert.py
python3 src/step3c_merge.py
python3 src/step4_feature_extraction.py
python3 src/step5_train.py --train
```

Step 5 automatically runs 5 ratio scenarios (RQ8). To skip: `python3 src/step5_train.py --train --skip-scenarios`

See [docs/RUN_PIPELINE.md](docs/RUN_PIPELINE.md) for detailed instructions.

## Pipeline

| Step | Script | Description | Key Output |
|------|--------|-------------|------------|
| **1** | `step1_parse_sshd.py` | Parse RHEL `/var/log/secure` → structured JSON | `output/step1/` |
| **2** | `step2_build_benign.py` | Convert OpenSSH → Cowrie format, remap IPs | `output/step2/cowrie_benign_corp.json` |
| **3A** | `step3a_attack_expert.py` | Attack Expert: score sessions, correct Cowrie bias, IP campaign classification, recommend features | `output/step3a/attack_selected.json`, `pipeline_feature_config.json` |
| **3B** | `step3b_benign_expert.py` | Benign Expert: verify vs OpenSSH, upscale via parametric bootstrap (893→1055 sessions) | `output/step3b/benign_upscaled.json` |
| **3C** | `step3c_merge.py` | Merge attack + benign, neutralize domain shortcuts | `output/step3c/cowrie_merged.json` |
| **4** | `step4_feature_extraction.py` | Extract 13 features per (IP, 60-min window), temporal split | `output/step4/ml_features.json` |
| **5** | `step5_train.py --train` | Train RF, dataset quality (6 aspects), scenario comparison, SHAP | `output/step5/reports/evaluation_report.html` |

Every step produces an **HTML report** with embedded charts, verification checks, and Vietnamese debug logs.

## Feature Set (13 active / 17 total)

| # | Feature | Group |
|---|---------|-------|
| 1 | `failed_attempts` | Frequency |
| 2 | `num_unique_users` | Account |
| 3 | `username_entropy` | Account |
| 4 | `success_ratio` | Account |
| 5 | `avg_time_between_attempts` | Temporal |
| 6 | `login_interval_variance` | Temporal |
| 7 | `client_version_category` | Meta |
| 8 | `time_to_auth` | Inter-event |
| 9 | `session_duration` | Inter-event |
| 10 | `min_inter_arrival` | Inter-event |
| 11 | `max_inter_arrival` | Inter-event |
| 12 | `hour_sin` | Cyclic temporal |
| 13 | `hour_cos` | Cyclic temporal |

Dropped: `time_of_day_avg`, `num_failed_days` (temporal artifacts). Excluded: `num_failed_ports`, `ip_entropy` (shortcut features).

## Project Structure

```
src/                    Pipeline source code (Step 1-5 + ratio scenarios)
  utils/                Shared HTML report builder (ViLogger) + session analyzer
logs/                   Raw Cowrie attack logs + RHEL secure logs
logs-sweetie/           Alternative Sweetie honeypot attack logs
output/                 Generated outputs (reports, features, models)
  ratio_study/          5-scenario ablation outputs (RQ8)
docs/                   Pipeline documentation (7 files)
```

See [docs/01_repo_structure.md](docs/01_repo_structure.md) for the full directory tree.

## Documentation

| Document | Content |
|----------|---------|
| [Pipeline Overview](docs/00_pipeline_overview.md) | Input/output for each step, anti-leakage measures |
| [Repository Structure](docs/01_repo_structure.md) | Directory layout, data flow, feature table |
| [Expert Tools Workflow](docs/02_expert_tools_workflow.md) | Step 3A/3B/3C diagrams, decision tables, dual expert perspective |
| [Ratio Scenario Study](docs/03_ratio_scenario_study.md) | 5-scenario design (RQ8), metrics |
| [Attack Expert Detailed](docs/04_attack_expert_detailed.md) | Step 3A analysis with exact numbers and sources |
| [Benign Expert Detailed](docs/05_benign_expert_detailed.md) | Step 3B analysis with exact numbers and sources |
| [Run Pipeline](docs/RUN_PIPELINE.md) | Step-by-step execution guide |

## Key Design Decisions

- **Cowrie Bias Correction:** 60.8% root login success rate → relabel 97% to failed (keep 3% matching real-world 1-8% rate)
- **IP-level Campaign Classification:** Aggregate metrics across all sessions per IP to detect distributed botnet campaigns (bursty, low_and_slow, spraying, scan_only, hit_and_run)
- **Parametric Bootstrap:** Upscale benign data preserving empirical distributions (archetype-stratified, log-normal duration, business-hour timestamps)
- **Anti-Data-Leakage:** 7-layer defense — domain neutralization, IP remapping, bias correction, feature dropping, shortcut exclusion, temporal split, dynamic feature config
- **Dataset Quality Evaluation:** 6 aspects — Statistical Validity, Class Balance, Fisher's Discriminant Ratio, Label Consistency, Separability, Temporal Stability

## Data Sources

| Source | Type | Volume |
|--------|------|--------|
| Cowrie honeypot | Attack (SSH brute-force) | 313K events, 47K sessions, 10 log files |
| RHEL 8.68/8.69 servers | Benign (corporate SSH) | 893 sessions, 2 months |
| Sweetie honeypot | Attack (alternative, unused) | 24 log files |

## References

- Efron & Tibshirani (1993): *An Introduction to the Bootstrap* — parametric bootstrap
- Owezarski (2015): SSH brute-force success rate 2-8%
- Hofstede et al. (2014): SSH brute-force success rate 1-5%
- Sommer & Paxson (2010): IDS evaluation — behavioral features over temporal
- He & Garcia (2009): *Learning from Imbalanced Data* — class ratio analysis
- Cochran (1977): *Sampling Techniques* — stratified allocation
- Arp et al. (2022): *Dos and Don'ts of ML in Computer Security*
- RFC 4253 (Ylonen & Lonvick, 2006): SSH Transport Layer Protocol
