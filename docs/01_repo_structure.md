# Repository Structure

```
Code-Full/
│
├── src/                               # Source code — all pipeline scripts
│   ├── step1_parse_sshd.py            # Step 1: Parse RHEL /var/log/secure → JSON
│   ├── step2_build_benign.py          # Step 2: OpenSSH events → Cowrie JSONL format
│   ├── step3a_attack_expert.py        # Step 3A: Attack log analysis, scoring, bias correction,
│   │                                  #          IP-level campaign classification, feature recommendation
│   ├── step3b_benign_expert.py        # Step 3B: Benign log analysis, upscale via parametric bootstrap
│   ├── step3c_merge.py               # Step 3C: Merge attack + benign, neutralize shortcuts
│   ├── step4_feature_extraction.py    # Step 4: Feature extraction (17→13), labeling, temporal split
│   ├── step5_train.py                 # Step 5: RF training, evaluation, dataset quality (6 aspects),
│   │                                  #          scenario comparison (RQ8), SHAP, robustness
│   ├── run_ratio_scenarios.py         # Step 6: Ratio ablation study (RQ8) — 5 scenarios
│   ├── __init__.py
│   └── utils/
│       ├── __init__.py
│       ├── report_utils.py            # Shared: HTML report builder, ViLogger, chart helpers
│       └── session_analyzer.py        # Utility: single-log EventID/session statistics
│
├── logs/                              # Raw source data (READ-ONLY, do not modify)
│   ├── 8.68/                          # RHEL secure logs from server 10.x.x.68
│   │   ├── secure
│   │   ├── secure-20260201
│   │   ├── secure-20260208
│   │   ├── secure-20260215
│   │   └── secure-20260222
│   ├── 8.69/                          # RHEL secure logs from server 10.x.x.69
│   │   ├── secure
│   │   ├── secure-20260201
│   │   ├── secure-20260208
│   │   ├── secure-20260215
│   │   └── secure-20260222
│   ├── cowrie_1.json                  # Cowrie honeypot attack logs (NDJSON)
│   ├── cowrie_2.json
│   ├── ...                            # cowrie_3.json through cowrie_10.json
│   ├── cowrie_10.json
│   ├── IPvn.log                       # Vietnamese IP address pool
│   ├── 8.68.zip                       # Archive of raw secure logs
│   └── 8.69.zip
│
├── logs-sweetie/                      # Alternative attack logs from Sweetie honeypot
│   ├── cowrie.json.1                  # Sweetie Cowrie logs (NDJSON)
│   ├── cowrie.json.2
│   ├── ...
│   └── cowrie.json.24
│
├── output/                            # All pipeline outputs (generated, can be regenerated)
│   ├── step1/                         # Step 1 outputs
│   │   ├── 8.68/
│   │   │   ├── 8.68_parsed_events.json
│   │   │   ├── 8.68_parsed_events.csv
│   │   │   ├── 8.68_analysis.json
│   │   │   ├── 8.68_analysis.html        # ← HTML report per server
│   │   │   └── 8.68_*.csv                # Additional analytics CSVs
│   │   ├── 8.69/
│   │   │   └── (same structure as 8.68/)
│   │   ├── merged/
│   │   │   ├── 8.68_secure_merged.log
│   │   │   └── 8.69_secure_merged.log
│   │   └── global_summary.json
│   │
│   ├── step2/                         # Step 2 outputs
│   │   ├── cowrie_benign_corp.json               # Full benign Cowrie log
│   │   ├── corp_ssh_benign_cowrie.normal_login.json  # Login-only subset
│   │   └── step2_build_benign.html               # ← HTML report
│   │
│   ├── step3a/                        # Step 3A outputs (Attack Expert)
│   │   ├── attack_selected.json                  # Filtered + bias-corrected events
│   │   ├── pipeline_feature_config.json          # Feature recommendations (13 active)
│   │   ├── attack_expert_report.json             # Full analysis report
│   │   └── attack_expert_report.html             # ← Visual report with decisions
│   │
│   ├── step3b/                        # Step 3B outputs (Benign Expert)
│   │   ├── benign_upscaled.json                  # Real + synthetic benign events
│   │   ├── benign_expert_report.json             # Full analysis report
│   │   └── benign_expert_report.html             # ← Visual report with decisions
│   │
│   ├── step3c/                        # Step 3C outputs (Merge)
│   │   ├── cowrie_merged.json                    # Final merged + neutralized dataset
│   │   └── step3c_merge.html                     # ← Merge analysis report
│   │
│   ├── step4/                         # Step 4 outputs (Features)
│   │   ├── ml_features.json                      # Feature vectors (JSON)
│   │   ├── ml_features.csv                       # Feature vectors (CSV)
│   │   └── ml_features.html                      # ← Feature analysis report
│   │
│   ├── step5/                         # Step 5 outputs (Model + Evaluation)
│   │   ├── models/
│   │   │   └── random_forest.pkl                 # Trained model
│   │   └── reports/
│   │       ├── evaluation_report.html            # ← Comprehensive evaluation dashboard
│   │       ├── confusion_matrix.png              #    (includes dataset quality, scenario
│   │       ├── roc_curve.png                     #     comparison, SHAP, robustness, etc.)
│   │       ├── pr_curve.png
│   │       ├── feature_importance.png
│   │       ├── probability_distribution.png
│   │       ├── shap_summary.png
│   │       └── shap_bar.png
│   │
│   ├── ratio_study/                   # Step 6 outputs (Scenario ablation — RQ8)
│   │   ├── scenario_comparison.html              # Unified comparison report
│   │   ├── scenario_comparison.json              # Metrics for all scenarios
│   │   ├── EXPERT_SCENARIO_COMPARISON.md         # Markdown summary
│   │   ├── S0_natural/                           # Per-scenario output (mini-pipeline)
│   │   │   ├── step3b/
│   │   │   ├── step3c/
│   │   │   ├── step4/
│   │   │   ├── step5/
│   │   │   └── scenario_meta.json
│   │   ├── S1_1to2/
│   │   ├── S2_1to1/
│   │   ├── S3_2to1/
│   │   └── S4_3to1/
│   │
│   └── reports/                       # Utility outputs (session analyzer)
│       └── *_session_stats.{json,html}
│
├── docs/                              # Documentation
│   ├── 00_pipeline_overview.md        # Full pipeline documentation
│   ├── 01_repo_structure.md           # This file — repository layout
│   ├── 02_expert_tools_workflow.md    # Detailed workflow diagrams for 3A/3B/3C
│   ├── 03_ratio_scenario_study.md     # RQ8 ratio scenario study design
│   ├── 04_attack_expert_detailed.md   # Step 3A detailed analysis with exact numbers
│   ├── 05_benign_expert_detailed.md   # Step 3B detailed analysis with exact numbers
│   └── RUN_PIPELINE.md               # How to run the full pipeline (Step 1→6)
│
└── README.md                          # Project overview and quick start
```

## Directory Conventions

| Directory | Purpose | Git-tracked? |
|-----------|---------|-------------|
| `src/` | All pipeline source code | Yes |
| `src/utils/` | Shared utilities (report builder, session analyzer) | Yes |
| `logs/` | Raw source data (attack + RHEL secure) | Yes (or LFS) |
| `logs-sweetie/` | Alternative attack data source | Yes (or LFS) |
| `output/` | Generated outputs, can be fully regenerated | No (add to .gitignore) |
| `docs/` | Documentation | Yes |

## Data Flow

```
logs/8.{68,69}/secure* ──► step1 ──► output/step1/
                                          │
                                   step2 ◄┘
                                     │
                                output/step2/
                                     │
logs/cowrie_*.json ──► step3a ──► output/step3a/
                                     │    └── pipeline_feature_config.json
                                     │                    │
output/step2/ ──────► step3b ◄────────────────────────────┘
                        │
                   output/step3b/
                        │
              step3c ◄──┤ ◄── output/step3a/attack_selected.json
                │
           output/step3c/
                │
             step4 ──► output/step4/
                │
             step5 ──► output/step5/
                │        └── evaluation_report.html (includes dataset quality
                │             + scenario comparison from Step 6 if not skipped)
                │
   run_ratio_scenarios ──► output/ratio_study/
    (invokes 3B→3C→4→5       ├── S0_natural/ ... S4_3to1/
     per scenario)            └── scenario_comparison.{html,json}
```

## Feature Pipeline (17 total → 13 active)

| # | Feature | Group | Status |
|---|---------|-------|--------|
| 1 | `failed_attempts` | Frequency | **Active** |
| 2 | `num_unique_users` | Account | **Active** |
| 3 | `username_entropy` | Account | **Active** |
| 4 | `success_ratio` | Account | **Active** |
| 5 | `avg_time_between_attempts` | Temporal | **Active** |
| 6 | `login_interval_variance` | Temporal | **Active** |
| 7 | `client_version_category` | Meta | **Active** |
| 8 | `time_to_auth` | Inter-event | **Active** |
| 9 | `session_duration` | Inter-event | **Active** |
| 10 | `min_inter_arrival` | Inter-event | **Active** |
| 11 | `max_inter_arrival` | Inter-event | **Active** |
| 12 | `hour_sin` | Cyclic temporal | **Active** |
| 13 | `hour_cos` | Cyclic temporal | **Active** |
| 14 | `time_of_day_avg` | Temporal | **Dropped** (attack <24h) |
| 15 | `num_failed_days` | Temporal | **Dropped** (attack <2 days) |
| 16 | `num_failed_ports` | Meta | **Shortcut** (excluded) |
| 17 | `ip_entropy` | Meta | **Shortcut** (excluded) |
