# SSH Brute-Force Attack Detection using Machine Learning

Detection of SSH brute-force attacks from Cowrie honeypot logs using a Random Forest classifier with behavioral feature engineering.

## Overview

This project implements a complete ML pipeline for detecting SSH brute-force attacks:

1. **Data Collection:** Cowrie honeypot attack logs + RHEL OpenSSH server benign logs
2. **Data Processing:** Expert analysis tools that automatically analyze, filter, and balance the dataset
3. **Feature Engineering:** 9 behavioral features extracted per (IP, 1-hour window)
4. **Model Training:** Random Forest with temporal train/val/test split and comprehensive evaluation

## Quick Start

```bash
# Requires Python 3.10+ with numpy, pandas, scikit-learn
# Create virutal environment
python3 -m venv .venv

# Activate virtual environment if using one
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the full pipeline
python3 src/step1_parse_sshd.py
python3 src/step2_build_benign.py
python3 src/step3a_attack_expert.py
python3 src/step3b_benign_expert.py
python3 src/step3c_merge.py
python3 src/step4_feature_extraction.py
python3 src/step5_train.py
```

**Optional — compare 5 training-balance scenarios** (natural, 1:2, 1:1, 2:1, 3:1 benign:attack targets):

```bash
python3 src/run_ratio_scenarios.py
```

See [docs/03_ratio_scenario_study.md](docs/03_ratio_scenario_study.md).

All outputs are written to `output/` with step-specific subdirectories.

## Project Structure

```
src/                    Pipeline source code (Step 1-5 + utilities)
logs/                   Raw Cowrie attack logs + RHEL secure logs
logs-sweetie/           Alternative Sweetie honeypot attack logs
output/                 Generated outputs (reports, features, models)
docs/                   Pipeline documentation
```

See [docs/01_repo_structure.md](docs/01_repo_structure.md) for the full directory tree.

## Pipeline Documentation

- [Pipeline Overview](docs/00_pipeline_overview.md) — detailed input/output for each step
- [Repository Structure](docs/01_repo_structure.md) — directory layout and data flow
- [Expert tools workflow](docs/02_expert_tools_workflow.md) — Step 3A/3B/3C diagrams and decisions
- [Ratio scenario study](docs/03_ratio_scenario_study.md) — 5-scenario benign:attack ablation + how to run

## Key Features

- **Expert Analysis Tools:** Automated log analysis with decision reasoning and scientific citations
- **Cowrie Bias Correction:** Smart relabeling of honeypot configuration artifacts
- **Anti-Data-Leakage:** 7-layer defense including domain neutralization, temporal splitting, and dynamic feature selection
- **Balanced Dataset:** Parametric bootstrap upscaling of benign data to 1:1 ratio
- **Comprehensive Reports:** HTML reports with statistical analysis, session timelines, and decision summaries

## Data Sources

| Source | Type | Volume |
|--------|------|--------|
| Cowrie honeypot | Attack (SSH brute-force) | ~45K events, 10 log files |
| RHEL 8.68/8.69 servers | Benign (corporate SSH) | ~893 sessions, 2 months |
| Sweetie honeypot | Attack (alternative) | 24 log files |

## References

- Efron & Tibshirani (1993): *An Introduction to the Bootstrap*
- Owezarski (2015): SSH brute-force behavioral analysis
- Hofstede et al. (2014): SSH brute-force success rate studies
- Sommer & Paxson (2010): IDS evaluation methodology
- RFC 4253: SSH Transport Layer Protocol
