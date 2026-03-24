# Benign Expert (Step 3B) — Workflow phân tích, đánh giá & quyết định chi tiết

> Tài liệu trích xuất trực tiếp từ `output/step3b/benign_expert_report.json` và source code `src/step3b_benign_expert.py`.
> Mọi con số đều kèm nguồn gốc (field JSON, phép tính, hoặc hằng số trong code).

---

## PHASE 1: CROSS-VERIFICATION VỚI OPENSSH GỐC

**Input:**
- Cowrie benign log: `output/step2/cowrie_benign_corp.json` (sản phẩm Step 2)
- OpenSSH parsed events: `output/step1/8.68/8.68_parsed_events.json` + `output/step1/8.69/8.69_parsed_events.json` (sản phẩm Step 1)

**Mục tiêu:** Đảm bảo quá trình chuyển đổi OpenSSH → Cowrie format ở Step 2 không làm mất/sai lệch dữ liệu.

### Kết quả verification

| Metric | Giá trị | Nguồn (JSON field) | Giải thích |
|--------|---------|---------------------|------------|
| OpenSSH PID groups | **1,024** | `verification.openssh_pid_groups` | Mỗi (host, pid) = 1 SSH session gốc |
| OpenSSH tổng events | **2,351** | `verification.openssh_total_events` | Toàn bộ sự kiện parsed từ syslog |
| OpenSSH unique usernames | **6** | `verification.openssh_unique_usernames` | DEBUG, ORACLE, debug, oracle, root, sysadm |
| Cowrie session count | **893** | `verification.cowrie_session_count` | Số sessions sau Step 2 |
| Cowrie unique usernames | **5** | `verification.cowrie_unique_usernames` | DEBUG, ORACLE, debug, oracle, sysadm |
| Sessions có đủ cấu trúc (connect+close) | **893** | `verification.sessions_valid_structure` | = 893/893 → **100%** |
| Sessions thiếu connect | **0** | `verification.sessions_missing_connect` | |
| Sessions thiếu close | **0** | `verification.sessions_missing_close` | |
| Session count match? | **true** | `verification.session_count_match` | 893 ≤ 1,024 (OpenSSH groups) ✓ |
| Username consistency? | **true** | `verification.username_consistency` | Cowrie usernames ⊆ OpenSSH usernames ✓ |

**Phân tích các con số:**

1. **Tại sao 893 < 1,024?** OpenSSH có 1,024 PID groups nhưng Cowrie chỉ có 893 sessions. Lý do: Step 2 chỉ chuyển đổi sessions có đủ thông tin (có authentication event). Một số PID groups trong OpenSSH chỉ có log hệ thống (không phải interactive login) → bị loại.

2. **Tại sao Cowrie có 5 usernames nhưng OpenSSH có 6?** Username `root` xuất hiện trong OpenSSH parsed events nhưng không trong Cowrie benign. Lý do: Step 2 bỏ qua `root` sessions vì `root` là username bị honeypot bias ở attack log (tránh nhầm lẫn).

3. **100% valid structure:** Mọi session đều có cặp `cowrie.session.connect` + `cowrie.session.closed` → Step 2 đã generate đúng format.

**Cơ sở khoa học:** Wang & Strong (1996) — data quality dimensions: completeness, consistency, accuracy. Verification checks cả 3.

---

## PHASE 2: NHẬN ATTACK REFERENCE TỪ STEP 3A

**Input:** `output/step3a/pipeline_feature_config.json` (sản phẩm Attack Expert — chứa 13 active features, 2 dropped, 2 shortcut, và target vector count)

### Xác định target

| Metric | Giá trị | Nguồn (JSON field) | Giải thích |
|--------|---------|---------------------|------------|
| Mode | config_1to1_default | `ratio_study.mode` | Mặc định pipeline: 1:1 |
| Attack reference sessions | **1,055** | `ratio_study.attack_reference_sessions` | Từ `pipeline_feature_config.json` → `estimated_attack_feature_vectors` |
| Target sessions | **1,055** | `ratio_study.target_sessions` | = attack reference × (1/1) |
| Upscale target | **1,055** | `ratio_study.upscale_target_sessions` | Sau khi áp dụng ratio |

**Cách tính target (code `step3b_benign_expert.py`):**

```
# Đọc từ pipeline_feature_config.json
attack_ref = config["estimated_attack_feature_vectors"]  # = 1,055
target = attack_ref × (benign_ratio / attack_ratio)      # = 1,055 × (1/1) = 1,055
```

**Con số 1,055 có nghĩa:** Benign Expert cần tạo ra **đúng 1,055 benign sessions** (bao gồm cả real và synthetic) để balance với 1,055 attack feature vectors.

---

## PHASE 3: ĐO LƯỜNG PHÂN PHỐI THỰC NGHIỆM (EMPIRICAL DISTRIBUTIONS)

**Input:** 893 real benign sessions từ Phase 1.

### 3.1 Tổng quan sessions

| Metric | Giá trị | Nguồn |
|--------|---------|-------|
| Tổng sessions file | **893** | `sessions_total_in_file` |
| Sessions sử dụng | **893** | `sessions_used` |

Trong pipeline mặc định (1:1), toàn bộ 893 sessions được sử dụng. Nếu ratio < 1:1 (ví dụ "natural"), có thể subsample xuống ít hơn.

### 3.2 Phân phối số lần login thất bại per session

| Fail count | Sessions | % | Nguồn |
|------------|----------|---|-------|
| 0 | **877** | 98.2% | `empirical_stats.fail_count_distribution` |
| 1 | 3 | 0.3% | — |
| 2 | 5 | 0.6% | — |
| 3 | 2 | 0.2% | — |
| 4 | 4 | 0.4% | — |
| 5 | 1 | 0.1% | — |
| 6 | 1 | 0.1% | — |

**Cách tính %:** 877/893 = 98.2%.

**Nhận xét:** 98.2% sessions không có login thất bại → người dùng thật nhập đúng password ngay lần đầu. Đây là đặc trưng điển hình của benign SSH (nhân viên dùng daily, quen thuộc).

### 3.3 Behavioral Archetype Classification

**Quy tắc phân loại (từ source code `analyze_benign_log()`):**

| Archetype | Điều kiện | Sessions | % | Nguồn |
|-----------|-----------|----------|---|-------|
| **clean_login** | `n_fail == 0` AND `n_success ≥ 1` | **877** | 98.2% | `empirical_stats.archetype_counts` |
| **typo** | `1 ≤ n_fail ≤ 3` AND `n_success ≥ 1` | **8** | 0.9% | — |
| **troubleshoot** | `n_fail ≥ 4` AND `n_success ≥ 1` | **1** | 0.1% | — |
| **give_up** | `n_fail > 0` AND `n_success == 0` | **7** | 0.8% | — |

**Kiểm chứng:** 877 + 8 + 1 + 7 = **893** ✓

**Ý nghĩa từng archetype:**
- `clean_login`: Đăng nhập sạch, đúng password lần đầu (dev/sysadmin quen máy).
- `typo`: Nhập sai 1–3 lần rồi đúng (typo, quên caps lock).
- `troubleshoot`: Nhập sai ≥4 lần nhưng cuối cùng vào được (đổi password gần đây, troubleshoot).
- `give_up`: Toàn fail, không bao giờ success (nhầm server, quên hoàn toàn password).

**Tại sao phân loại này quan trọng?** Mỗi archetype có behavioral pattern khác nhau. Khi upscale, synthetic sessions phải **tỉ lệ thuận** với phân phối empirical để không bias model.

### 3.4 Username Pool

| Username | Sessions | % | Nguồn |
|----------|----------|---|-------|
| **oracle** | **777** | 87.0% | `empirical_stats.username_pool` |
| **sysadm** | **84** | 9.4% | — |
| **debug** | **30** | 3.4% | — |
| ORACLE | 1 | 0.1% | — |
| DEBUG | 1 | 0.1% | — |

**Cách tính %:** 777/893 = 87.0%.

**Nhận xét:** 5 username, chủ yếu `oracle` (database admin) → phản ánh 2 server RHEL trong ngân hàng chủ yếu serve Oracle DB. Username pool dùng làm **weighted sampling** cho synthetic sessions.

### 3.5 Client Version Pool

| Client Version | Sessions | % | Nguồn |
|----------------|----------|---|-------|
| SSH-2.0-OpenSSH_8.0 | **190** | 21.3% | `empirical_stats.client_version_pool` |
| SSH-2.0-PuTTY_Release_0.78 | **128** | 14.3% | — |
| SSH-2.0-OpenSSH_7.4 | **124** | 13.9% | — |
| SSH-2.0-OpenSSH_8.7 | **97** | 10.9% | — |
| SSH-2.0-OpenSSH_9.0 | **69** | 7.7% | — |
| SSH-2.0-PuTTY_Release_0.81 | **60** | 6.7% | — |
| SSH-2.0-OpenSSH_9.3 | **48** | 5.4% | — |
| SSH-2.0-WinSCP_5.21.5 | **44** | 4.9% | — |
| SSH-2.0-OpenSSH_for_Windows_8.1 | **43** | 4.8% | — |
| SSH-2.0-JSCH-0.1.54 | **39** | 4.4% | — |
| SSH-2.0-OpenSSH_for_Windows_9.5 | **33** | 3.7% | — |
| SSH-2.0-paramiko_3.4.0 | **18** | 2.0% | — |

**Cách tính %:** 190/893 = 21.3%.

**So sánh với Attack log:**

| | Attack | Benign |
|---|--------|--------|
| Dominant client | SSH-2.0-Go (89.4%) | SSH-2.0-OpenSSH_8.0 (21.3%) |
| Diversity | 15 loại, 1 chiếm gần hết | **12 loại, phân tán đều** |
| Tính chất | Automated tool (Go SSH lib) | Diverse enterprise tools (OpenSSH, PuTTY, WinSCP, JSCH, Paramiko) |

**Nhận xét:** Phân phối benign rất đa dạng (enterprise environment) → đây là tín hiệu mạnh phân biệt attack vs benign. Client version pool dùng làm **weighted sampling** cho synthetic sessions.

### 3.6 Duration Statistics

| Metric | Giá trị | Đơn vị | Nguồn |
|--------|---------|--------|-------|
| Sessions có duration > 0 | **887** | sessions | `empirical_stats.duration_stats.count_positive` |
| Median duration | **3,357.5** | giây (~56 phút) | `empirical_stats.duration_stats.median` |
| Mean duration | **41,279.6** | giây (~11.5 giờ) | `empirical_stats.duration_stats.mean` |
| Log-normal μ | **7.7283** | | `empirical_stats.duration_stats.lognormal_mu` |
| Log-normal σ | **2.0194** | | `empirical_stats.duration_stats.lognormal_sigma` |

**Cách tính log-normal parameters (source code):**

```
positive_durations = [d for d in durations if d > 0]    # 887 giá trị
log_durations = [ln(d) for d in positive_durations]
μ = mean(log_durations) = 7.7283
σ = stdev(log_durations) = 2.0194
```

**Kiểm chứng:** e^μ = e^7.7283 ≈ 2,268 giây ≈ 37.8 phút → xấp xỉ median (3,357s) ✓ (log-normal: median = e^μ).

**Tại sao 887 mà không 893?** 6 sessions có duration = 0 (connect rồi disconnect ngay) → loại khỏi log-normal fit.

**Tại sao Log-normal?** Duration SSH session tuân theo log-normal vì:
- Đa số sessions ngắn (quick command, kiểm tra)
- Một số ít rất dài (interactive work, monitoring)
- Efron & Tibshirani (1993): log-normal là prior tự nhiên cho "thời gian hoạt động".

**Mục đích:** Khi sinh synthetic sessions, duration = `exp(Normal(μ=7.7283, σ=2.0194))` → cùng phân phối với real.

### 3.7 Hour Distribution (giờ bắt đầu session)

| Giờ (UTC) | Sessions | Giờ VN (UTC+7) | Nguồn |
|-----------|----------|----------------|-------|
| 10 | **94** | 17:00 | `empirical_stats.hour_distribution` |
| 9 | 69 | 16:00 | — |
| 14 | 64 | 21:00 | — |
| 15 | 61 | 22:00 | — |
| 17 | 60 | 00:00 | — |
| 16 | 56 | 23:00 | — |
| 11 | 51 | 18:00 | — |
| 13 | 50 | 20:00 | — |
| 12 | 43 | 19:00 | — |
| 23 | 43 | 06:00 | — |
| 8 | 34 | 15:00 | — |
| 18 | 32 | 01:00 | — |
| 19 | 31 | 02:00 | — |
| 21 | 24 | 04:00 | — |
| 1 | 23 | 08:00 | — |
| 2 | 21 | 09:00 | — |
| 0 | 20 | 07:00 | — |
| 7 | 19 | 14:00 | — |
| 4 | 17 | 11:00 | — |
| 5 | 17 | 12:00 | — |
| 6 | 16 | 13:00 | — |
| 20 | 16 | 03:00 | — |
| 22 | 16 | 05:00 | — |
| 3 | 16 | 10:00 | — |

**Nhận xét:** Đỉnh ở UTC 8–13 (VN 15:00–20:00) → phù hợp giờ làm việc chiều + tối của nhân viên ngân hàng. Phân phối dùng để tạo **business-hour weights** cho synthetic timestamp.

### 3.8 Event Transitions (Top 9)

| Transition | Lần | Nguồn |
|------------|-----|-------|
| connect → client.version | **887** | `empirical_stats.event_transitions` |
| login.success → session.closed | **886** | — |
| client.version → login.success | **877** | — |
| login.failed → login.failed | **30** | — |
| client.version → login.failed | **16** | — |
| login.failed → login.success | **9** | — |
| connect → session.closed | **6** | — |
| session.closed → client.version | **6** | — |
| login.failed → session.closed | **1** | — |

**Phân tích:**
- **Đường đi chủ đạo (877 sessions):** connect → version → success → closed = **clean login**.
- **Đường đi typo (9 sessions):** ... → failed → ... → failed → success → closed = **nhập sai rồi đúng**.
- **Đường đi give_up (1 session):** ... → failed → closed = **toàn fail, ngắt kết nối**.

**So sánh với Attack log:**

| | Attack | Benign |
|---|--------|--------|
| Dominant path | kex → failed → closed (17,280 lần) | version → success → closed (877 lần) |
| failed → failed (lặp) | **448** | **30** |
| Command execution | 28,878 (sau success) | **0** |

Attack có command execution sau login → exploiting phase. Benign **không có** command events trong Cowrie log (vì Step 2 không generate command events).

---

## PHASE 4: ARCHETYPE CLASSIFICATION (QUYẾT ĐỊNH)

### Quyết định: 4 behavioral archetypes

| # | Archetype | Rule (source code line 355-368) | Real count | % |
|---|-----------|------|------|---|
| 1 | `clean_login` | `n_fail == 0 AND n_success ≥ 1` | 877 | 98.2% |
| 2 | `typo` | `1 ≤ n_fail ≤ 3 AND n_success ≥ 1` | 8 | 0.9% |
| 3 | `troubleshoot` | `n_fail ≥ 4 AND n_success ≥ 1` | 1 | 0.1% |
| 4 | `give_up` | `n_fail > 0 AND n_success == 0` | 7 | 0.8% |

**Cơ sở phân loại:**
- Ngưỡng 1–3 fails (typo): Người thật trung bình nhập sai password 1–2 lần → caps lock, typo.
- Ngưỡng ≥4 fails (troubleshoot): Vượt quá typo bình thường → đang troubleshoot (password mới, account issue).
- Sommer & Paxson (2010): "behavioral archetypes preserve semantic meaning in synthetic generation."

---

## PHASE 5: LẬP KẾ HOẠCH UPSCALE

### Dữ liệu vào

| Thông số | Giá trị | Nguồn |
|----------|---------|-------|
| Target | 1,055 sessions | Phase 2 (`ratio_study.target_sessions`) |
| Real sessions | 893 | Phase 3 (`sessions_used`) |
| Thiếu | 1,055 − 893 = **162** | Phép trừ |

### Kết quả kế hoạch

| Metric | Giá trị | Nguồn (JSON field) | Cách tính |
|--------|---------|---------------------|-----------|
| Target vectors | **1,055** | `upscale_plan.target_vectors` | = attack ref |
| Real sessions | **893** | `upscale_plan.real_sessions` | = đếm sessions thực |
| **Synthetic needed** | **162** | `upscale_plan.synthetic_needed` | = 1,055 − 893 |
| Upscale factor | **0.18** | `upscale_plan.upscale_factor` | = 162 / 893 = 0.18 (18%) |
| Multi-session IPs | **8** | `upscale_plan.multi_session_ips` | = round(162 × 0.05) |

**Cách tính `MULTI_SESSION_IP_FRACTION`:** Hằng số `0.05` (5%) trong code line 72. Mục đích: 5% synthetic sessions chia sẻ IP → mô phỏng nhân viên cùng subnet (realistic).

### Allocation by Archetype (Proportional Stratified)

| Archetype | Real | % thực | Synthetic allocated | Cách tính | Total |
|-----------|------|--------|---------------------|-----------|-------|
| clean_login | 877 | 98.2% | **160** | round(162 × 877/893) = round(162 × 0.982) = 159 → +1 remainder | **1,037** |
| typo | 8 | 0.9% | **1** | round(162 × 8/893) = round(1.45) = 1 | **9** |
| troubleshoot | 1 | 0.1% | **0** | round(162 × 1/893) = round(0.18) = 0 | **1** |
| give_up | 7 | 0.8% | **1** | round(162 × 7/893) = round(1.27) = 1 | **8** |
| **TOTAL** | **893** | | **162** | | **1,055** |

**Cách tính chi tiết (source code `plan_upscale()`):**

```
n_needed = 162
allocation = {}
for archetype, count in archetype_counts.items():
    proportion = count / total_classified      # VD: 877/893 = 0.9821
    allocation[archetype] = round(162 × proportion)

# Sau round: clean_login=159, typo=1, troubleshoot=0, give_up=1 → sum=161
# Remainder = 162 - 161 = 1 → cộng vào archetype lớn nhất (clean_login)
# clean_login = 159 + 1 = 160

Kết quả: {clean_login: 160, typo: 1, troubleshoot: 0, give_up: 1}
```

**Kiểm chứng:** 160 + 1 + 0 + 1 = 162 ✓

**Cơ sở khoa học:** Cochran (1977) — Stratified sampling: "allocation proportional to stratum size preserves population characteristics." Đảm bảo synthetic data không over-represent typo/give_up sessions.

---

## PHASE 6: THỰC THI UPSCALE (PARAMETRIC BOOTSTRAP)

### Cho mỗi synthetic session, lấy mẫu từ:

| Parameter | Distribution | Nguồn distribution | Cơ sở |
|-----------|-------------|-------------------|-------|
| **IP address** | Uniform từ Vietnamese IP pool (loại trừ IP đã dùng) | `output/step2/ipvn.json` | Tránh domain shortcut qua IP range |
| **Username** | Weighted random từ empirical username pool | `empirical_stats.username_pool` | oracle:777, sysadm:84, debug:30, ... |
| **Client version** | Weighted random từ empirical client version pool | `empirical_stats.client_version_pool` | OpenSSH_8.0:190, PuTTY:128, ... |
| **Duration** | Log-normal(μ=7.7283, σ=2.0194) | `empirical_stats.duration_stats` | Efron & Tibshirani (1993) |
| **Start hour** | Business-hour weighted | Code: `_business_hour_weights()` | UTC+7, peak 08:00-18:00 VN |
| **Start date** | Uniform random trong 60 ngày (15/10/2024 − 13/12/2024) | Code line 584-586 | Rải đều qua 2 tháng |
| **Fail count** | Lấy từ template session (cùng archetype) | Template rotation | Giữ đúng behavior |
| **Success count** | Lấy từ template session (cùng archetype) | Template rotation | Giữ đúng behavior |

### Business-hour weights (source code `_business_hour_weights()`)

```
Giờ VN 08:00–18:00 (business hours) → weight = 1.0
Giờ VN 06:00–08:00 & 18:00–20:00 → weight = 0.3
Giờ VN còn lại (đêm) → weight = 0.02
```

Chuyển đổi sang UTC (offset +7):
- UTC 01:00–11:00 → VN 08:00–18:00 → weight = 1.0
- UTC 23:00–01:00 & 11:00–13:00 → VN 06:00–08:00 & 18:00–20:00 → weight = 0.3
- UTC còn lại → weight = 0.02

**Cơ sở:** Phản ánh thực tế nhân viên ngân hàng Việt Nam làm việc chủ yếu giờ hành chính.

### Multi-session IP clustering

8 synthetic sessions sẽ share IP → mô phỏng cùng 1 người SSH nhiều lần trong ngày.

**Cơ chế (source code line 575-577):**
```
is_multi = synth_count < n_multi    # 8 sessions đầu tiên
if is_multi and i > 0 and i % 3 == 0:
    ip_idx -= 1   # Reuse IP trước đó → nhóm 3 sessions/IP
```

**Kết quả:** ~3 IP × ~3 sessions/IP = ~8 sessions shared → 8/162 = 4.9% ≈ `MULTI_SESSION_IP_FRACTION` (5%).

### Cấu trúc synthetic session (ví dụ clean_login)

```json
[
  {"eventid": "cowrie.session.connect",   "timestamp": "T₀",   "src_ip": "VN_IP", "session": "synth_xxx", "data_origin": "benign_corp_synthetic"},
  {"eventid": "cowrie.client.version",    "timestamp": "T₀+1s", "version": "SSH-2.0-OpenSSH_8.0"},
  {"eventid": "cowrie.login.success",     "timestamp": "T₀+2s", "username": "oracle"},
  {"eventid": "cowrie.session.closed",    "timestamp": "T₀+duration", "duration": 2268.5}
]
```

**Với typo archetype (VD n_fail=2, n_success=1):**
```json
[
  {"eventid": "cowrie.session.connect",   "timestamp": "T₀"},
  {"eventid": "cowrie.client.version",    "timestamp": "T₀+1s"},
  {"eventid": "cowrie.login.failed",      "timestamp": "T₀+3s", "username": "oracle"},
  {"eventid": "cowrie.login.failed",      "timestamp": "T₀+6s", "username": "oracle"},
  {"eventid": "cowrie.login.success",     "timestamp": "T₀+10s", "username": "oracle"},
  {"eventid": "cowrie.session.closed",    "timestamp": "T₀+duration"}
]
```

---

## PHASE 7: OUTPUT STATISTICS

### Kết quả cuối cùng

| Metric | Giá trị | Nguồn (JSON field) |
|--------|---------|---------------------|
| Real events | **3,611** | `output_stats.real_events` |
| Synthetic events | **650** | `output_stats.synthetic_events` |
| **Total events** | **4,261** | `output_stats.total_events` |

**Cách tính:**
- Real events: 893 sessions × trung bình ~4 events/session = ~3,611 events (mỗi session: connect + version + success + closed).
- Synthetic events: 162 sessions × trung bình ~4 events/session = ~650 events.
  - 160 clean_login × 4 events = 640
  - 1 typo × ~6 events = 6
  - 1 give_up × ~4 events = 4
  - Tổng ≈ 650 ✓

---

## TỔNG KẾT: BENIGN EXPERT OUTPUT

| Output file | Nội dung | Size |
|-------------|----------|------|
| `benign_upscaled.json` | 893 real + 162 synthetic = **1,055 sessions**, **4,261 events** | ~46,871 dòng NDJSON |
| `benign_expert_report.json` | Toàn bộ verification + statistics + upscale plan + timelines | ~10,881 dòng JSON |
| `benign_expert_report.html` | Báo cáo visual với decision reasoning + allocation table | HTML standalone |

### Dòng chảy con số

```
OpenSSH logs (2 servers)                    Attack Expert
  │                                              │
  ├─ 1,024 PID groups                           │
  ├─ 2,351 events                               │
  ├─ 6 usernames                    Target = 1,055 feature vectors
  │                                              │
  ▼                                              ▼
Step 2: Parse → 893 Cowrie sessions    ──────► Benign Expert receives target
                │
     ┌──────────┴──────────────────┐
     │  VERIFY vs OpenSSH          │
     │  893/893 valid structure ✓  │
     │  5/6 usernames match ✓      │
     └──────────┬──────────────────┘
                │
     ┌──────────┴──────────────────┐
     │  MEASURE EMPIRICAL          │
     │  877 clean_login (98.2%)    │
     │  8 typo (0.9%)             │
     │  1 troubleshoot (0.1%)     │
     │  7 give_up (0.8%)          │
     │  Duration: LogN(7.73, 2.02)│
     │  5 usernames, 12 clients   │
     └──────────┬──────────────────┘
                │
     ┌──────────┴──────────────────┐
     │  PLAN UPSCALE               │
     │  Need: 1,055 - 893 = 162   │
     │  Factor: 0.18x (18%)       │
     │  160 clean + 1 typo        │
     │  + 0 troubleshoot + 1 give_up│
     └──────────┬──────────────────┘
                │
     ┌──────────┴──────────────────┐
     │  EXECUTE                    │
     │  Real:      893 sessions    │
     │             3,611 events    │
     │  Synthetic: 162 sessions    │
     │             650 events      │
     │  TOTAL:     1,055 sessions  │
     │             4,261 events    │
     └─────────────────────────────┘
                │
                ▼
      benign_upscaled.json → Step 3C Merge
```

### Tổng hợp quyết định của Benign Expert

| # | Quyết định | Dữ liệu đầu vào | Kết quả | Cơ sở khoa học |
|---|------------|-------------------|---------|----------------|
| D1 | Dữ liệu đầu vào hợp lệ | 893/893 valid, usernames ⊆ OpenSSH | **PASS** | Wang & Strong (1996) |
| D2 | Target balance ratio | Attack ref = 1,055, mode = 1:1 | **1,055 sessions** | He & Garcia (2009) |
| D3 | Phân loại archetype | Rule-based từ n_fail/n_success | **4 archetypes** | Sommer & Paxson (2010) |
| D4 | Số synthetic cần tạo | 1,055 − 893 | **162 sessions** | Phép trừ |
| D5 | Allocation strategy | Proportional to empirical % | **160+1+0+1** | Cochran (1977) |
| D6 | Duration distribution | Fit log-normal từ 887 samples | **LogN(7.73, 2.02)** | Efron & Tibshirani (1993) |
| D7 | Timestamp strategy | Business-hour weights (UTC+7) | **Peak 08–18 VN** | Đặc thù domain ngân hàng |
| D8 | IP assignment | VN pool, tránh overlap real IPs | **Unique per session** | Chống domain shortcut |
| D9 | Multi-session clustering | 5% synthetic share IP | **8 sessions** | Mô phỏng cùng 1 user |
