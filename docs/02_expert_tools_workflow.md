# Expert Tools Workflow — Chi tiết quy trình phân tích

## Tổng quan kiến trúc

```
                    ┌──────────────────────────────────┐
                    │         RAW DATA SOURCES          │
                    └──────┬──────────────┬─────────────┘
                           │              │
               ┌───────────▼──┐     ┌─────▼────────────┐
               │ Cowrie Attack │     │ Cowrie Benign     │
               │ logs/*.json   │     │ (from Step 2)     │
               │ 313,412 events│     │ 3,611 events      │
               │ 47,569 sess.  │     │ 893 sessions      │
               └───────┬───────┘     └─────┬─────────────┘
                       │                    │
          ┌────────────▼────────────┐  ┌───▼──────────────────┐
          │    STEP 3A              │  │    STEP 3B            │
          │    ATTACK EXPERT        │  │    BENIGN EXPERT      │
          │                         │  │                       │
          │ ┌─────────────────────┐ │  │ ┌───────────────────┐ │
          │ │ 1. Characteristic   │ │  │ │ 1. Cross-verify   │ │
          │ │    Analysis         │ │  │ │    vs OpenSSH     │ │
          │ ├─────────────────────┤ │  │ ├───────────────────┤ │
          │ │ 2. Session Scoring  │ │  │ │ 2. Empirical      │ │
          │ │    & Selection      │ │  │ │    Distribution   │ │
          │ ├─────────────────────┤ │  │ ├───────────────────┤ │
          │ │ 3. Cowrie Bias      │ │  │ │ 3. Archetype      │ │
          │ │    Detection+Fix    │ │  │ │    Classification │ │
          │ ├─────────────────────┤ │  │ ├───────────────────┤ │
          │ │ 4. Feature          │ │  │ │ 4. Upscale Plan   │ │
          │ │    Recommendation   │─┼──┼▶│    (target=1,055) │ │
          │ └─────────────────────┘ │  │ ├───────────────────┤ │
          │                         │  │ │ 5. Parametric     │ │
          │  Outputs:               │  │ │    Bootstrap      │ │
          │  • attack_selected.json │  │ └───────────────────┘ │
          │  • pipeline_feature_    │  │                       │
          │    config.json          │  │  Outputs:             │
          │  • attack_expert_       │  │  • benign_upscaled.   │
          │    report.{json,html}   │  │    json               │
          └────────────┬────────────┘  │  • benign_expert_     │
                       │               │    report.{json,html} │
                       │               └──────┬────────────────┘
                       │                      │
                  ┌────▼──────────────────────▼────┐
                  │         STEP 3C                 │
                  │     MERGE & NEUTRALIZE          │
                  │                                 │
                  │  1. Nối attack + benign events  │
                  │  2. sensor → 'cowrie-ssh'       │
                  │  3. dst_port → 22               │
                  │  4. Sort by timestamp           │
                  │                                 │
                  │  Output: cowrie_merged.json      │
                  │  302,790 events                  │
                  └─────────────────────────────────┘
```

---

## ATTACK EXPERT — Workflow chi tiết

### Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    STEP 3A: ATTACK EXPERT                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  INPUT: logs/cowrie_*.json (10 files, 313,412 events)               │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 1: CHARACTERISTIC ANALYSIS                            │    │
│  │ Function: analyze_attack_log()                              │    │
│  │                                                             │    │
│  │  ┌──────────────────┐  ┌──────────────────┐                │    │
│  │  │ 1a. Sessionize   │  │ 1b. EventID      │                │    │
│  │  │ Group events by  │  │ Distribution     │                │    │
│  │  │ session ID       │  │ Count each type  │                │    │
│  │  │ → 47,569 sess.   │  │ → 17 event types │                │    │
│  │  └────────┬─────────┘  └──────────────────┘                │    │
│  │           │                                                 │    │
│  │  ┌────────▼─────────┐  ┌──────────────────┐                │    │
│  │  │ 1c. Per-session  │  │ 1d. Protocol     │                │    │
│  │  │ Login Profile    │  │ Distribution     │                │    │
│  │  │ n_fail, n_success│  │ ssh: 44,941      │                │    │
│  │  │ duration, src_ip │  │ telnet: 2,626    │                │    │
│  │  │ client_version   │  │ unknown: 2       │                │    │
│  │  └────────┬─────────┘  └──────────────────┘                │    │
│  │           │                                                 │    │
│  │  ┌────────▼─────────┐  ┌──────────────────┐                │    │
│  │  │ 1e. IP Analysis  │  │ 1f. Time Range   │                │    │
│  │  │ 1,591 unique IPs │  │ 16.7 hours       │                │    │
│  │  │ 544 with login   │  │ 0 days           │                │    │
│  │  │ 1,047 scan-only  │  │ 00:00 → 16:40    │                │    │
│  │  │ median span: 31s │  │                   │                │    │
│  │  └──────────────────┘  └──────────────────┘                │    │
│  │                                                             │    │
│  │  ┌──────────────────┐  ┌──────────────────┐                │    │
│  │  │ 1g. Cowrie Bias  │  │ 1h. Client       │                │    │
│  │  │ Detection        │  │ Version Dist.    │                │    │
│  │  │ root success     │  │ SSH-2.0-Go: 90%  │                │    │
│  │  │ rate = 60.8%     │  │ libssh: 7.5%     │                │    │
│  │  │ → BIAS DETECTED  │  │ 15 versions      │                │    │
│  │  └──────────────────┘  └──────────────────┘                │    │
│  │                                                             │    │
│  │  ┌──────────────────┐  ┌──────────────────┐                │    │
│  │  │ 1i. Behavioral   │  │ 1j. Username     │                │    │
│  │  │ Archetypes       │  │ Intelligence     │                │    │
│  │  │ success_only:    │  │ ubuntu: 4,833    │                │    │
│  │  │   26,628         │  │ admin: 3,877     │                │    │
│  │  │ fail_only: 17,276│  │ root: 114        │                │    │
│  │  │ scan_only: 3,364 │  │ → dictionary     │                │    │
│  │  │ mixed: 301       │  │   attack pattern │                │    │
│  │  └──────────────────┘  └──────────────────┘                │    │
│  │                                                             │    │
│  │  ┌──────────────────┐  ┌──────────────────┐                │    │
│  │  │ 1k. Feature Vec  │  │ 1l. Session      │                │    │
│  │  │ Estimation       │  │ Timeline +       │                │    │
│  │  │ (IP × 60min win) │  │ Event            │                │    │
│  │  │ = 1,055 vectors  │  │ Transitions      │                │    │
│  │  │ → Target cho 3B  │  │ (top 30)         │                │    │
│  │  └──────────────────┘  └──────────────────┘                │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 2: SESSION SCORING                                    │    │
│  │ Function: score_sessions()                                  │    │
│  │                                                             │    │
│  │  Góc nhìn: Cybersecurity Expert                             │    │
│  │  ┌─────────────────────────────────────────────────────┐    │    │
│  │  │ Rule: score = 1 nếu (protocol == SSH) AND           │    │    │
│  │  │                     (has login.failed OR             │    │    │
│  │  │                      has login.success)              │    │    │
│  │  │       score = 0 nếu telnet / scan-only / incomplete │    │    │
│  │  └─────────────────────────────────────────────────────┘    │    │
│  │                                                             │    │
│  │  Kết quả:                                                   │    │
│  │  ┌─────────────────────┐  ┌─────────────────────┐          │    │
│  │  │ ✓ Selected: 43,698  │  │ ✗ Discarded: 3,871  │          │    │
│  │  │   (score = 1)       │  │   (score = 0)       │          │    │
│  │  │   SSH + has login   │  │   2,626 telnet      │          │    │
│  │  └─────────────────────┘  │   1,047 scan-only   │          │    │
│  │                           │   198 incomplete     │          │    │
│  │  Cơ sở khoa học:          └─────────────────────┘          │    │
│  │  RFC 4253: authentication phase requires login events       │    │
│  │  Owezarski (2015): sessions without auth = not brute-force  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 3: COWRIE BIAS CORRECTION                             │    │
│  │ Function: handle_cowrie_bias()                              │    │
│  │                                                             │    │
│  │  Góc nhìn: Cybersecurity Expert + ML Expert                 │    │
│  │                                                             │    │
│  │  Phát hiện:                                                 │    │
│  │  ┌─────────────────────────────────────────────────────┐    │    │
│  │  │ Cowrie cấu hình UserDB: root:x:*                    │    │    │
│  │  │ → Accept ANY password cho root                       │    │    │
│  │  │ → 60.8% sessions có root login.success               │    │    │
│  │  │ Thực tế: SSH brute-force success rate = 1-8%         │    │    │
│  │  └─────────────────────────────────────────────────────┘    │    │
│  │                                                             │    │
│  │  Hành động: Smart Relabeling                                │    │
│  │  ┌─────────────────────────────────────────────────────┐    │    │
│  │  │ 26,439 sessions bị ảnh hưởng                        │    │    │
│  │  │                                                     │    │    │
│  │  │ ┌───────────────────┐  ┌───────────────────────┐    │    │    │
│  │  │ │ 97% → Relabel     │  │ 3% → Giữ nguyên       │    │    │    │
│  │  │ │ 25,646 sessions   │  │ 793 sessions           │    │    │    │
│  │  │ │ login.success     │  │ login.success giữ      │    │    │    │
│  │  │ │ → login.failed    │  │ để duy trì success     │    │    │    │
│  │  │ │                   │  │ rate ~3% (thực tế)     │    │    │    │
│  │  │ └───────────────────┘  └───────────────────────┘    │    │    │
│  │  │                                                     │    │    │
│  │  │ Metadata bảo tồn:                                   │    │    │
│  │  │ • _original_eventid = 'cowrie.login.success'        │    │    │
│  │  │ • _correction_reason = 'cowrie_userdb_allow_all'    │    │    │
│  │  └─────────────────────────────────────────────────────┘    │    │
│  │                                                             │    │
│  │  Cơ sở khoa học:                                            │    │
│  │  Owezarski (2015): success rate 2-8%                        │    │
│  │  Hofstede et al. (2014): success rate 1-5%                  │    │
│  │  → 3% keep rate nằm trong khoảng thực tế                   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 4: FEATURE RECOMMENDATION                             │    │
│  │ Function: recommend_features()                              │    │
│  │                                                             │    │
│  │  Góc nhìn: ML Expert                                        │    │
│  │                                                             │    │
│  │  Input: Kết quả phân tích từ Phase 1                        │    │
│  │                                                             │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │         17 CANDIDATE FEATURES                        │   │    │
│  │  │                                                      │   │    │
│  │  │  failed_attempts    │ num_unique_users               │   │    │
│  │  │  username_entropy   │ success_ratio                  │   │    │
│  │  │  num_failed_ports   │ avg_time_between_attempts      │   │    │
│  │  │  login_interval_variance │ time_of_day_avg           │   │    │
│  │  │  num_failed_days    │ ip_entropy                     │   │    │
│  │  │  client_version_category │ time_to_auth              │   │    │
│  │  │  session_duration   │ min_inter_arrival              │   │    │
│  │  │  max_inter_arrival  │ hour_sin │ hour_cos            │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │                          │                                  │    │
│  │                          ▼                                  │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ Rule 1: time_range < 24h?                            │   │    │
│  │  │   16.7h < 24h → YES                                  │   │    │
│  │  │   → DROP time_of_day_avg                             │   │    │
│  │  │   Lý do: Data chỉ 16.7h, feature này phản ánh       │   │    │
│  │  │   window thu thập chứ không phải hành vi             │   │    │
│  │  │   Cite: Owezarski (2015) — botnet hoạt động 24/7    │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ Rule 2: time_range < 2 days?                         │   │    │
│  │  │   0 days < 2 → YES                                   │   │    │
│  │  │   → DROP num_failed_days                             │   │    │
│  │  │   Lý do: Attack chỉ trong 1 ngày, feature luôn = 1  │   │    │
│  │  │   cho attack → tạo trivial shortcut                  │   │    │
│  │  │   Cite: Hofstede et al. (2014) — IP rotation         │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ Rule 3: bias_corrected == true?                      │   │    │
│  │  │   → YES → KEEP success_ratio (đã sửa bias)          │   │    │
│  │  │   Nếu false → success_ratio vào shortcut list        │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ Rule 4: Dominant client version > 80%?               │   │    │
│  │  │   SSH-2.0-Go = 90% → YES                             │   │    │
│  │  │   → WARNING: client_version_category có thể là       │   │    │
│  │  │   shortcut → cần monitor bằng SHAP analysis          │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ Mặc định: EXCLUDE num_failed_ports, ip_entropy       │   │    │
│  │  │   Lý do: Shortcut features phụ thuộc vào cách        │   │    │
│  │  │   build dataset hơn là hành vi thực                   │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │                          │                                  │    │
│  │                          ▼                                  │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ KẾT QUẢ: 13 ACTIVE FEATURES                         │   │    │
│  │  │                                                      │   │    │
│  │  │ ✓ failed_attempts          ✓ num_unique_users        │   │    │
│  │  │ ✓ username_entropy         ✓ success_ratio           │   │    │
│  │  │ ✓ avg_time_between_attempts                          │   │    │
│  │  │ ✓ login_interval_variance  ✓ client_version_category │   │    │
│  │  │ ✓ time_to_auth             ✓ session_duration        │   │    │
│  │  │ ✓ min_inter_arrival        ✓ max_inter_arrival       │   │    │
│  │  │ ✓ hour_sin                 ✓ hour_cos                │   │    │
│  │  │                                                      │   │    │
│  │  │ ✗ DROPPED: time_of_day_avg, num_failed_days          │   │    │
│  │  │ ✗ SHORTCUT: num_failed_ports, ip_entropy             │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  OUTPUT FILES:                                                       │
│  ├── attack_selected.json          (298,529 events)                  │
│  ├── pipeline_feature_config.json  (13 active, 2 dropped, 2 short.) │
│  ├── attack_expert_report.json     (full statistics + IP campaigns)  │
│  └── attack_expert_report.html     (visual report + decisions)       │
└─────────────────────────────────────────────────────────────────────┘
```

### Bảng tổng hợp quyết định Attack Expert

| Phase | Quyết định | Dữ liệu đầu vào | Hành động | Góc nhìn | Cơ sở khoa học |
|-------|-----------|-------------------|-----------|----------|----------------|
| 2 | Session filtering | protocol_distribution, session_login_stats | Loại 3,871 sessions (telnet + scan-only) | CyberSec | RFC 4253: SSH auth phase |
| 3 | Bias detection | cowrie_bias.root_success_rate = 60.8% | Phát hiện artifact cấu hình honeypot | CyberSec | Owezarski (2015): real rate 2-8% |
| 3 | Smart relabeling | 26,439 affected sessions | 97% relabel success→failed, giữ 3% | CyberSec + ML | Hofstede et al. (2014): 1-5% |
| 4 | Drop time_of_day_avg | time_range = 16.7h < 24h | Loại khỏi feature set | ML | Owezarski (2015): not discriminative |
| 4 | Drop num_failed_days | time_range = 0 days < 2 | Loại khỏi feature set | ML | Hofstede et al. (2014): IP rotation |
| 4 | Keep success_ratio | bias_corrected = true | Giữ lại vì đã sửa bias | ML | Nội bộ pipeline logic |
| 4 | Warn client_version | SSH-2.0-Go = 90% | Cảnh báo shortcut tiềm tàng | ML | SHAP monitoring needed |
| 4 | Exclude ip_entropy, num_failed_ports | Mặc định | Shortcut phụ thuộc data assembly | ML | Sommer & Paxson (2010) |
| 5 | IP-level campaign classification | Aggregate fc, unique_fail, intervals per IP | Classify: bursty/low_and_slow/spraying/scan_only/hit_and_run/success_only | CyberSec | Distributed botnet reveals true pattern at IP level |
| — | Feature vector count | 1,055 (IP × hour) pairs | Gửi cho Benign Expert làm target | ML | He & Garcia (2009): 1:1 ratio |

---

## BENIGN EXPERT — Workflow chi tiết

### Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    STEP 3B: BENIGN EXPERT                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  INPUT: output/step2/cowrie_benign_corp.json (3,611 events)         │
│         output/step1/8.{68,69}/*_parsed_events.json (OpenSSH)       │
│         output/step3a/pipeline_feature_config.json (target: 1,055)  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 1: CROSS-VERIFICATION                                 │    │
│  │ Function: verify_sessions()                                 │    │
│  │                                                             │    │
│  │  Góc nhìn: Cybersecurity Expert — Data Provenance           │    │
│  │                                                             │    │
│  │  ┌──────────────────────┐   ┌───────────────────────┐      │    │
│  │  │ OpenSSH gốc          │   │ Cowrie (Step 2)       │      │    │
│  │  │ 2,351 events         │──▶│ 3,611 events          │      │    │
│  │  │ 1,024 PID groups     │   │ 893 sessions          │      │    │
│  │  │ 6 usernames          │   │ 5 usernames           │      │    │
│  │  └──────────┬───────────┘   └──────────┬────────────┘      │    │
│  │             │                           │                   │    │
│  │             └─────────┬─────────────────┘                   │    │
│  │                       ▼                                     │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ CHECK 1: Session count                               │   │    │
│  │  │   893 (Cowrie) ≤ 1,024 (OpenSSH) → ✓ OK             │   │    │
│  │  │                                                      │   │    │
│  │  │ CHECK 2: Username consistency                        │   │    │
│  │  │   {oracle,sysadm,debug,ORACLE,DEBUG}                 │   │    │
│  │  │   ⊂ {oracle,sysadm,debug,ORACLE,DEBUG,root} → ✓ OK  │   │    │
│  │  │                                                      │   │    │
│  │  │ CHECK 3: Structural integrity                        │   │    │
│  │  │   893/893 có connect+closed → ✓ OK                   │   │    │
│  │  │   0 missing connect, 0 missing close                 │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │                                                             │    │
│  │  Quyết định: DATA INTEGRITY PASSED                          │    │
│  │  Cơ sở: Sommer & Paxson (2010) — ground truth validation   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 2: EMPIRICAL DISTRIBUTION MEASUREMENT                 │    │
│  │ Function: analyze_benign_log()                              │    │
│  │                                                             │    │
│  │  Góc nhìn: ML Expert — Population Characterization          │    │
│  │                                                             │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ 2a. Fail Count Distribution                          │   │    │
│  │  │   0 fails: 877 (98.2%)  ← admin chuyên nghiệp       │   │    │
│  │  │   1 fail:    3 (0.3%)   ← typo nhẹ                  │   │    │
│  │  │   2 fails:   5 (0.6%)                                │   │    │
│  │  │   3 fails:   2 (0.2%)                                │   │    │
│  │  │   4 fails:   4 (0.4%)   ← troubleshooting           │   │    │
│  │  │   5 fails:   1 (0.1%)                                │   │    │
│  │  │   6 fails:   1 (0.1%)                                │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ 2b. Duration Statistics                              │   │    │
│  │  │   Phân phối: Log-Normal                              │   │    │
│  │  │   Sessions with d > 0: 887                           │   │    │
│  │  │   Median: 3,357.5s (~56 phút)                        │   │    │
│  │  │   Mean: 41,279.6s (~11.5 giờ)                        │   │    │
│  │  │   Log-normal μ = 7.7283                              │   │    │
│  │  │   Log-normal σ = 2.0194                              │   │    │
│  │  │   → Dùng cho parametric bootstrap synthetic          │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ 2c. Username Pool + Frequency                        │   │    │
│  │  │   oracle:  777 (87.0%)  ← DB admin chính             │   │    │
│  │  │   sysadm:   84 (9.4%)  ← system admin               │   │    │
│  │  │   debug:    30 (3.4%)  ← developer                   │   │    │
│  │  │   ORACLE:    1 (0.1%)  ← caps lock accident          │   │    │
│  │  │   DEBUG:     1 (0.1%)                                │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ 2d. Client Version Pool                              │   │    │
│  │  │   OpenSSH_8.0:  190 (21.3%)  ← RHEL 8               │   │    │
│  │  │   PuTTY_0.78:   128 (14.3%)  ← Windows admin        │   │    │
│  │  │   OpenSSH_7.4:  124 (13.9%)  ← RHEL 7               │   │    │
│  │  │   OpenSSH_8.7:   97 (10.9%)  ← RHEL 9               │   │    │
│  │  │   + 8 loại khác (WinSCP, JSCH, paramiko, ...)       │   │    │
│  │  │   → 12 client versions đa dạng (enterprise mix)     │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ 2e. Hour Distribution (UTC)                          │   │    │
│  │  │   Peak: 09-17h UTC = 16-24h (UTC+7 Vietnam)         │   │    │
│  │  │   → Phản ánh giờ làm việc ngân hàng                  │   │    │
│  │  │   → Dùng làm weight cho synthetic timestamp          │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │ 2f. Session Timeline + Event Transitions             │   │    │
│  │  │   Typical path: connect → version → success → closed │   │    │
│  │  │   Typo path: connect → version → failed → success    │   │    │
│  │  │                                      → closed        │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 3: ARCHETYPE CLASSIFICATION                           │    │
│  │                                                             │    │
│  │  Góc nhìn: Cybersecurity Expert — User Behavior Modeling    │    │
│  │                                                             │    │
│  │  ┌────────────────────────────────────────────────────────┐ │    │
│  │  │ Archetype    │ Điều kiện          │ Sessions │ %       │ │    │
│  │  │──────────────┼────────────────────┼──────────┼─────────│ │    │
│  │  │ clean_login  │ 0 fail, ≥1 success │     877  │ 98.2%   │ │    │
│  │  │ typo         │ 1-3 fail + success │       8  │  0.9%   │ │    │
│  │  │ troubleshoot │ ≥4 fail + success  │       1  │  0.1%   │ │    │
│  │  │ give_up      │ fail only, 0 succ. │       7  │  0.8%   │ │    │
│  │  └────────────────────────────────────────────────────────┘ │    │
│  │                                                             │    │
│  │  Cơ sở: Cochran (1977) — stratified sampling bảo toàn       │    │
│  │  cấu trúc population khi upscale                            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 4: UPSCALE PLANNING                                  │    │
│  │ Function: plan_upscale()                                    │    │
│  │                                                             │    │
│  │  Góc nhìn: ML Expert — Class Balance                        │    │
│  │                                                             │    │
│  │  Input: target = 1,055 (từ Attack Expert)                   │    │
│  │  Real:  893 sessions                                        │    │
│  │  Need:  1,055 - 893 = 162 synthetic sessions                │    │
│  │  Factor: 0.18x                                              │    │
│  │                                                             │    │
│  │  Allocation (tỉ lệ thuận theo archetype thực tế):           │    │
│  │  ┌────────────────────────────────────────────────────────┐ │    │
│  │  │ Archetype     │ Real │ Synthetic │ Total │ Tỷ lệ giữ  │ │    │
│  │  │───────────────┼──────┼───────────┼───────┼─────────────│ │    │
│  │  │ clean_login   │  877 │       160 │ 1,037 │ 98.2%       │ │    │
│  │  │ typo          │    8 │         1 │     9 │  0.9%       │ │    │
│  │  │ troubleshoot  │    1 │         0 │     1 │  0.1%       │ │    │
│  │  │ give_up       │    7 │         1 │     8 │  0.8%       │ │    │
│  │  │───────────────┼──────┼───────────┼───────┼─────────────│ │    │
│  │  │ TOTAL         │  893 │       162 │ 1,055 │             │ │    │
│  │  └────────────────────────────────────────────────────────┘ │    │
│  │                                                             │    │
│  │  Cơ sở: He & Garcia (2009) — 1:1 ratio cho Random Forest   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ PHASE 5: PARAMETRIC BOOTSTRAP EXECUTION                     │    │
│  │ Function: execute_upscale()                                 │    │
│  │                                                             │    │
│  │  Góc nhìn: ML Expert — Synthetic Data Generation            │    │
│  │                                                             │    │
│  │  Với mỗi synthetic session:                                 │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │                                                      │   │    │
│  │  │  1. Chọn archetype template (round-robin từ real)    │   │    │
│  │  │     → Lấy n_fail, n_success từ template              │   │    │
│  │  │                                                      │   │    │
│  │  │  2. Sample IP từ Vietnamese IP pool                  │   │    │
│  │  │     → Không overlap với real IPs                     │   │    │
│  │  │     → Chống IP-based shortcut                        │   │    │
│  │  │                                                      │   │    │
│  │  │  3. Sample timestamp                                 │   │    │
│  │  │     → Giờ: weighted theo business hours (UTC+7)      │   │    │
│  │  │     → Ngày: random trong 60 ngày (Oct-Dec 2024)      │   │    │
│  │  │                                                      │   │    │
│  │  │  4. Sample duration                                  │   │    │
│  │  │     → LogNormal(μ=7.73, σ=2.02)                      │   │    │
│  │  │     → Đo từ 887 real sessions                        │   │    │
│  │  │                                                      │   │    │
│  │  │  5. Sample username                                  │   │    │
│  │  │     → Weighted: oracle(777), sysadm(84), debug(30)   │   │    │
│  │  │     → Nếu fail: 40% chance hoán vị ký tự (typo)     │   │    │
│  │  │                                                      │   │    │
│  │  │  6. Sample client version                            │   │    │
│  │  │     → Weighted: OpenSSH_8.0(190), PuTTY(128), ...    │   │    │
│  │  │                                                      │   │    │
│  │  │  7. Generate event sequence:                         │   │    │
│  │  │     connect → client.version → [failed]* →           │   │    │
│  │  │     [success]* → session.closed                      │   │    │
│  │  │     Với inter-event delays ngẫu nhiên                │   │    │
│  │  │                                                      │   │    │
│  │  │  8. Tag: data_origin = 'benign_corp_synthetic'       │   │    │
│  │  │                                                      │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  │                                                             │    │
│  │  Multi-session clustering: 5% synthetic IPs chia sẻ IP      │    │
│  │  → Tạo feature vectors multi-session (tránh ecological      │    │
│  │    fallacy khi aggregate ở Step 4)                          │    │
│  │                                                             │    │
│  │  Cơ sở:                                                     │    │
│  │  Efron & Tibshirani (1993) — parametric bootstrap            │    │
│  │  Davison & Hinkley (1997) — valid khi sample representative │    │
│  │  Robinson (1950) — ecological fallacy prevention             │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  OUTPUT FILES:                                                      │
│  ├── benign_upscaled.json        (4,261 events: 3,611 real + 650)  │
│  ├── benign_expert_report.json   (full statistics + timelines)      │
│  └── benign_expert_report.html   (visual report + decisions)        │
└─────────────────────────────────────────────────────────────────────┘
```

### Bảng tổng hợp quyết định Benign Expert

| Phase | Quyết định | Dữ liệu đầu vào | Hành động | Góc nhìn | Cơ sở khoa học |
|-------|-----------|-------------------|-----------|----------|----------------|
| 1 | Data integrity | OpenSSH PID groups vs Cowrie sessions | 893 ≤ 1,024 → PASSED | CyberSec | Sommer & Paxson (2010) |
| 1 | Username check | OpenSSH usernames vs Cowrie usernames | Subset match → PASSED | CyberSec | Ground truth validation |
| 1 | Structure check | connect + closed events per session | 893/893 valid → PASSED | CyberSec | Cowrie protocol spec |
| 2 | Distribution fit | Duration histogram | Log-Normal(μ=7.73, σ=2.02) | ML | Maximum likelihood estimation |
| 3 | Archetype classify | fail/success counts per session | 4 behavioral types identified | CyberSec | Domain knowledge |
| 4 | Upscale target | pipeline_feature_config.json | 1,055 (1:1 với attack) | ML | He & Garcia (2009) |
| 4 | Allocation method | Archetype proportions | Stratified proportional | ML | Cochran (1977) |
| 5 | IP assignment | VN IP pool exclusion | No overlap with real IPs | ML | Anti-shortcut design |
| 5 | Timestamp weight | Hour distribution | Business hours (UTC+7) | CyberSec | Observed bank patterns |
| 5 | Duration sampling | Log-normal parameters | lognorm(7.73, 2.02) | ML | Efron & Tibshirani (1993) |
| 5 | Session clustering | 5% shared IPs | Multi-session feature vectors | ML | Robinson (1950) |

---

## STEP 3C: MERGE & NEUTRALIZE — Workflow

### Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    STEP 3C: MERGE & NEUTRALIZE                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────┐   ┌─────────────────────────┐         │
│  │ FROM ATTACK EXPERT (3A) │   │ FROM BENIGN EXPERT (3B) │         │
│  │ attack_selected.json    │   │ benign_upscaled.json    │         │
│  │ 298,529 events          │   │ 4,261 events            │         │
│  │ 43,698 sessions         │   │ 1,055 sessions          │         │
│  │ data_origin:            │   │ data_origin:            │         │
│  │   'attack_cowrie'       │   │   'benign_corp'         │         │
│  │ sensor: honeypot-*      │   │   'benign_corp_synthetic│         │
│  │ dst_port: 2222          │   │ sensor: corp-ssh-benign │         │
│  │ time: 2024-10-31        │   │ dst_port: 22            │         │
│  │       (16.7 hours)      │   │ time: 2024-Oct ~ Dec    │         │
│  └────────────┬────────────┘   │       (60 days)         │         │
│               │                └────────────┬────────────┘         │
│               │                             │                      │
│               └──────────┬──────────────────┘                      │
│                          │                                         │
│                          ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ STEP 1: CONCATENATE                                         │   │
│  │                                                             │   │
│  │ merged = attack_events + benign_events                      │   │
│  │ = 298,529 + 4,261 = 302,790 events                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          │                                         │
│                          ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ STEP 2: NEUTRALIZE DOMAIN SHORTCUTS                         │   │
│  │                                                             │   │
│  │  Tại sao?                                                   │   │
│  │  Nếu model nhìn thấy sensor hoặc dst_port, nó có thể       │   │
│  │  học shortcut: "sensor == corp-ssh-benign → benign" với      │   │
│  │  accuracy 100% mà KHÔNG cần phân tích hành vi.              │   │
│  │                                                             │   │
│  │  ┌────────────────────────────────────────────────────────┐ │   │
│  │  │ Field    │ Attack (trước) │ Benign (trước) │ Sau      │ │   │
│  │  │──────────┼────────────────┼────────────────┼──────────│ │   │
│  │  │ sensor   │ honeypot-*     │ corp-ssh-benign│cowrie-ssh│ │   │
│  │  │ dst_port │ 2222           │ 22             │ 22       │ │   │
│  │  └────────────────────────────────────────────────────────┘ │   │
│  │                                                             │   │
│  │  Cơ sở: Sommer & Paxson (2010) — tránh domain shortcut     │   │
│  │         Geirhos et al. (2020) — shortcut learning           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          │                                         │
│                          ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ STEP 3: SORT BY TIMESTAMP                                   │   │
│  │                                                             │   │
│  │ merged.sort(key=timestamp)                                  │   │
│  │                                                             │   │
│  │  Kết quả timeline sau sort:                                 │   │
│  │  ┌────────────────────────────────────────────────────────┐ │   │
│  │  │ Oct 15-Dec 13 (synthetic benign) ─────────────────┐    │ │   │
│  │  │         Oct 31 (attack) ─┐                        │    │ │   │
│  │  │                          │                        │    │ │   │
│  │  │ ──────────────|──────────|──|─────────────────────|──▶ │ │   │
│  │  │         Oct 15         Oct 31              Dec 13      │ │   │
│  │  │                                                        │ │   │
│  │  │ Jan-Feb 2026 (real benign) ──────────────────────────▶ │ │   │
│  │  └────────────────────────────────────────────────────────┘ │   │
│  │                                                             │   │
│  │  Timestamp gap KHÔNG ảnh hưởng model vì:                    │   │
│  │  1. Feature extraction group theo (IP, 60-min window)       │   │
│  │     → IP attack ≠ IP benign → không trộn hành vi           │   │
│  │  2. time_of_day_avg đã bị DROP (Attack Expert quyết định)  │   │
│  │  3. num_failed_days đã bị DROP                              │   │
│  │  4. Label dùng data_origin, KHÔNG dùng timestamp            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          │                                         │
│                          ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ STEP 4: WRITE OUTPUT + STATISTICS                           │   │
│  │                                                             │   │
│  │  Data origin distribution:                                  │   │
│  │    attack_cowrie:          298,529 events                   │   │
│  │    benign_corp:              3,611 events                   │   │
│  │    benign_corp_synthetic:      650 events                   │   │
│  │                                                             │   │
│  │  Session balance:                                           │   │
│  │    Attack sessions:  43,698                                 │   │
│  │    Benign sessions:   1,055                                 │   │
│  │    → Feature vectors ≈ 1,055 : 1,055 (1:1)                 │   │
│  │                                                             │   │
│  │  Output: cowrie_merged.json (302,790 events)                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  VAI TRÒ CỦA 2 EXPERT TOOLS TRONG MERGE:                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │  Attack Expert đã hoàn thành TRƯỚC merge:                   │   │
│  │  ✓ Lọc 3,871 sessions vô ích (telnet/scan)                 │   │
│  │  ✓ Sửa 25,646 sessions bias (root login.success)           │   │
│  │  ✓ Gán data_origin = 'attack_cowrie'                        │   │
│  │  ✓ Drop 2 time-absolute features (giải quyết time gap)     │   │
│  │  ✓ Cung cấp target = 1,055 cho Benign Expert               │   │
│  │                                                             │   │
│  │  Benign Expert đã hoàn thành TRƯỚC merge:                   │   │
│  │  ✓ Xác minh tính toàn vẹn data benign                      │   │
│  │  ✓ Upscale 893 → 1,055 (thêm 162 synthetic)                │   │
│  │  ✓ Gán data_origin = 'benign_corp' / 'benign_corp_synth.'  │   │
│  │  ✓ IP pool không overlap → chống IP shortcut                │   │
│  │                                                             │   │
│  │  → Step 3C chỉ cần: NỐI + NEUTRALIZE + SORT                │   │
│  │    Mọi quyết định phức tạp đã được expert tools xử lý      │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Tổng hợp: Dual Expert Perspective

```
┌───────────────────────────────────────────────────────────────────┐
│                   CYBERSECURITY EXPERT LENS                        │
│                                                                   │
│  "Dữ liệu này đại diện cho thực tế tấn công SSH như thế nào?"    │
│                                                                   │
│  Attack Expert:                                                   │
│  • SSH brute-force từ Cowrie honeypot                              │
│  • 60.8% root success = artifact cấu hình, KHÔNG phải thực tế    │
│  • 90% dùng SSH-2.0-Go = automated tool (script kiddie/botnet)   │
│  • Dictionary attack pattern: ubuntu, admin, root                 │
│  • Median IP span = 31s → hit-and-run attack                     │
│                                                                   │
│  Benign Expert:                                                   │
│  • Real bank admin SSH sessions (dev, sysadmin, DBA)              │
│  • 98.2% clean login → chuyên nghiệp, ít sai mật khẩu           │
│  • 5 usernames thực (oracle, sysadm, debug)                      │
│  • 12 enterprise SSH clients (OpenSSH, PuTTY, WinSCP, JSCH)      │
│  • Business hours pattern (UTC+7)                                 │
└───────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────┐
│                   ML EXPERT LENS                                   │
│                                                                   │
│  "Dữ liệu này có đủ tốt để train model không?"                   │
│                                                                   │
│  Attack Expert:                                                   │
│  • 1,055 feature vectors → đủ cho Random Forest                  │
│  • Bias correction: success_ratio đã sạch → dùng được            │
│  • 2 features bị drop vì temporal artifact                        │
│  • 1 feature cảnh báo shortcut (client_version 90%)               │
│  • 13 active features: frequency + temporal + inter-event + cyclic│
│  • IP-level campaign classification (bursty/slow/spraying/...)    │
│                                                                   │
│  Benign Expert:                                                   │
│  • 893 real sessions → representative (Cochran 1977)              │
│  • Upscale 0.18x (chỉ thêm 18%) → ít synthetic, nhiều real      │
│  • Parametric bootstrap bảo toàn empirical distribution           │
│  • Stratified allocation → không bias archetype                   │
│  • 5% multi-session IP → tránh ecological fallacy                 │
│                                                                   │
│  Merge:                                                           │
│  • Neutralize sensor + dst_port → chống domain shortcut           │
│  • data_origin tag chỉ dùng cho label, KHÔNG phải feature         │
│  • Time gap xử lý bằng DROP features, không cần align timestamp  │
└───────────────────────────────────────────────────────────────────┘
```

---

## Tham khảo khoa học

| Trích dẫn | Sử dụng trong | Nội dung |
|-----------|--------------|----------|
| RFC 4253 (Ylonen & Lonvick, 2006) | 3A Phase 2 | SSH protocol: authentication phase after key exchange |
| Owezarski (2015) | 3A Phase 3, 4 | SSH brute-force success rate 2-8%; botnet operates 24/7 |
| Hofstede et al. (2014) | 3A Phase 3, 4 | SSH brute-force success rate 1-5%; IP rotation behavior |
| Sommer & Paxson (2010) | 3B Phase 1, 3C | Ground truth validation; behavioral features over temporal |
| He & Garcia (2009) | 3B Phase 4 | 1:1 class ratio for balanced classifier training |
| Cochran (1977) | 3B Phase 3, 4 | Stratified sampling preserves population structure |
| Efron & Tibshirani (1993) | 3B Phase 5 | Parametric bootstrap methodology |
| Davison & Hinkley (1997) | 3B Phase 5 | Bootstrap validity when sample is representative |
| Robinson (1950) | 3B Phase 5 | Ecological fallacy — matching aggregation structure |
| Geirhos et al. (2020) | 3C Step 2 | Shortcut learning in machine learning models |
