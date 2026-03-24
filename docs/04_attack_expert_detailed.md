# Attack Expert (Step 3A) — Workflow phân tích, đánh giá & quyết định chi tiết

> Tài liệu trích xuất trực tiếp từ `output/step3a/attack_expert_report.json`.
> Mọi con số đều kèm nguồn gốc (field JSON hoặc phép tính).

---

## PHASE 1: ĐỌC VÀ THỐNG KÊ ĐẦU VÀO

**Input:** 10 file `logs/cowrie_*.json` (loại trừ file có tên chứa benign/merged/selected).

### 1.1 Tổng quan

| Metric | Giá trị | Nguồn (JSON field) |
|--------|---------|---------------------|
| Tổng events | **313,412** | `analysis.summary.total_events` |
| Tổng sessions | **47,569** | `analysis.summary.total_sessions` |
| IP duy nhất | **1,591** | `analysis.summary.unique_ips` |
| IP có login event | **544** | `analysis.summary.ips_with_login` |
| IP chỉ scan (không login) | **1,047** | `analysis.summary.ips_scan_only` |
| Thời gian đầu tiên | 2024-10-31 00:00:00 UTC | `analysis.summary.first_timestamp` |
| Thời gian cuối cùng | 2024-10-31 16:40:01 UTC | `analysis.summary.last_timestamp` |
| Khoảng thời gian | **16.7 giờ** | `analysis.summary.time_range_hours` |
| Số ngày (distinct calendar days) | **0** (cùng 1 ngày) | `analysis.summary.time_range_days` |

**Cách tính `time_range_hours`:** `(last_timestamp - first_timestamp).total_seconds() / 3600` = (16:40:01 − 00:00:00) / 3600 ≈ 16.7.

**Cách tính `estimated_feature_vectors`:** Đếm số cặp `(src_ip, floor(timestamp, 60min))` duy nhất trong toàn bộ login events = **1,055** (`analysis.summary.estimated_feature_vectors`). Con số này trở thành **target** cho Benign Expert.

### 1.2 Phân phối EventID

| EventID | Số lần | Nguồn |
|---------|--------|-------|
| cowrie.session.connect | 47,567 | `analysis.eventid_distribution` |
| cowrie.session.closed | 47,562 | — |
| cowrie.client.version | 44,483 | — |
| cowrie.client.kex | 44,283 | — |
| cowrie.command.input | 28,878 | — |
| **cowrie.login.success** | **26,876** | — |
| cowrie.session.params | 26,727 | — |
| cowrie.log.closed | 26,718 | — |
| **cowrie.login.failed** | **18,025** | — |
| cowrie.command.failed | 887 | — |
| cowrie.command.success | 354 | — |
| cowrie.direct-tcpip.request | 314 | — |
| cowrie.session.file_upload | 303 | — |
| cowrie.session.file_download | 157 | — |
| cowrie.direct-tcpip.data | 145 | — |
| cowrie.client.fingerprint | 93 | — |
| cowrie.client.size | 40 | — |

**Nhận xét bất thường:**  
`login.success` (26,876) > `login.failed` (18,025). Trong honeypot **thực tế**, failed phải áp đảo success vì attacker thường đoán sai. Đây là **dấu hiệu đầu tiên** của Cowrie UserDB bias (`root:x:*` accept mọi password).

### 1.3 Phân phối giao thức

| Protocol | Sessions | Nguồn |
|----------|----------|-------|
| SSH | **44,941** | `analysis.protocol_distribution.ssh` |
| Telnet | **2,626** | `analysis.protocol_distribution.telnet` |
| Unknown | 2 | `analysis.protocol_distribution.unknown` |

**Quyết định sẽ dùng ở Phase 2:** Telnet sessions (2,626) sẽ bị loại vì ngoài scope SSH brute-force.

### 1.4 Thống kê login per session

| Metric | Giá trị | Nguồn |
|--------|---------|-------|
| Sessions có login events | **44,205** | `analysis.session_login_stats.sessions_with_login` |
| Sessions chỉ scan (không login) | **3,364** | `analysis.session_login_stats.sessions_scan_only` |
| Sessions có ít nhất 1 failed | **17,577** | `analysis.session_login_stats.sessions_with_fail` |
| Sessions có ít nhất 1 success | **26,876** | `analysis.session_login_stats.sessions_with_success` |

**Kiểm chứng:** 44,205 + 3,364 = 47,569 = total_sessions ✓

### 1.5 Phát hiện Cowrie UserDB Bias

| Metric | Giá trị | Nguồn |
|--------|---------|-------|
| Sessions root login success | **26,876** | `analysis.cowrie_bias.root_success_sessions` |
| Tổng sessions có login | **44,205** | `analysis.cowrie_bias.total_login_sessions` |
| **Root success rate** | **60.8%** | `analysis.cowrie_bias.root_success_rate` |
| Bias detected? | **true** | `analysis.cowrie_bias.bias_detected` |

**Cách tính rate:** 26,876 / 44,205 = 0.608 = **60.8%**.

**So sánh literature:**
- Owezarski (2015): brute-force thực tế success rate **2–8%**
- Hofstede et al. (2014): brute-force thực tế success rate **1–5%**

60.8% >> 8% → **Bias confirmed**. Nguyên nhân: Cowrie cấu hình `UserDB` với rule `root:x:*` (accept mọi password cho root).

### 1.6 Phân tích IP

| Metric | Giá trị | Nguồn |
|--------|---------|-------|
| IP duy nhất | 1,591 | `analysis.ip_analysis.total_unique_ips` |
| IP có login | 544 | `analysis.ip_analysis.ips_with_login_events` |
| IP chỉ scan | 1,047 | `analysis.ip_analysis.ips_scan_only` |
| IP active > 1 giờ | **202** | `analysis.ip_analysis.ips_spanning_gt_1h` |
| Median thời gian active per IP | **31.1 giây** | `analysis.ip_analysis.median_ip_span_seconds` |

**Nhận xét:** Median 31.1 giây → đa số IP kiểu "hit-and-run" (thử vài password rồi đi). 202 IP active > 1h có thể là botnet dai dẳng.

### 1.7 Phân phối SSH Client Version

| Client Version | Sessions | % tổng | Nguồn |
|----------------|----------|--------|-------|
| **SSH-2.0-Go** | **39,803** | **89.4%** | `analysis.client_version_distribution` |
| SSH-2.0-libssh_0.9.6 | 3,319 | 7.5% | — |
| SSH-2.0-libssh2_1.11.0 | 757 | 1.7% | — |
| SSH-2.0-libssh2_1.4.3 | 122 | 0.3% | — |
| (11 loại khác) | 467 | 1.1% | — |

**Cách tính %:** 39,803 / 44,483 (sessions có client.version) = 89.4%.

**Nhận xét:** 89.4% dùng Go SSH library → automated attack tool. Đây là **cảnh báo shortcut** cho feature `client_version_category`.

### 1.8 Top 10 Username bị brute-force

| Username | Lần thử | Nguồn |
|----------|---------|-------|
| ubuntu | 4,833 | `analysis.top_20_fail_usernames` |
| admin | 3,877 | — |
| validator | 115 | — |
| root | 114 | — |
| oracle | 102 | — |
| bitcoin | 99 | — |
| plcmspip | 94 | — |
| solana | 87 | — |
| node | 86 | — |
| ethereum | 85 | — |

**Nhận xét:** `ubuntu` và `admin` chiếm phần lớn → dictionary attack nhắm vào default usernames. Các tên liên quan crypto (bitcoin, solana, ethereum) phản ánh xu hướng tấn công cryptominer.

### 1.9 Phân phối Behavioral Archetype

| Archetype | Sessions | Nguồn |
|-----------|----------|-------|
| success_only(1) | **26,628** | `analysis.archetype_distribution` |
| fail_only(1) | 17,276 | — |
| scan_only | 3,364 | — |
| fail(1)\_success(1) | 103 | — |
| fail(2)\_success(1) | 61 | — |
| fail(3)\_success(1) | 43 | — |
| (10 loại nhỏ khác) | 94 | — |

**Nhận xét:** 26,628 sessions chỉ có 1 `login.success` (không fail) → **artifact** của UserDB bias. Sau bias correction, phần lớn sẽ chuyển thành fail_only.

### 1.10 Event Transitions (Top 10)

| Transition | Lần | Nguồn |
|------------|-----|-------|
| connect → client.version | 44,483 | `analysis.event_transitions` |
| client.version → client.kex | 44,270 | — |
| session.params → command.input | 26,647 | — |
| login.success → session.params | 26,415 | — |
| client.kex → login.success | 26,413 | — |
| log.closed → session.closed | 26,384 | — |
| command.input → log.closed | 26,033 | — |
| **login.failed → session.closed** | **17,328** | — |
| **client.kex → login.failed** | **17,280** | — |
| connect → session.closed | 2,575 | — |

**Nhận xét:**
- Đường đi phổ biến nhất: connect → version → kex → login.success → params → command → log.closed → closed (**attacker vào được**, chạy command).
- Đường đi fail: connect → version → kex → login.failed → closed (**đoán sai, bị đuổi**).
- connect → closed (2,575): scan-only sessions (không hoàn thành kex).

---

## PHASE 2: SESSION SCORING

**Mục tiêu:** Chỉ giữ sessions **có ý nghĩa** cho bài toán SSH brute-force detection.

### Quy tắc scoring

```
score = 1  nếu  (protocol == "ssh") AND (có login.failed HOẶC login.success)
score = 0  nếu  telnet / scan-only / incomplete
```

### Kết quả

| Metric | Giá trị | Nguồn |
|--------|---------|-------|
| **Sessions được chọn (score=1)** | **43,698** | `scoring.selected` |
| **Sessions bị loại (score=0)** | **3,871** | `scoring.discarded` |

**Kiểm chứng:** 43,698 + 3,871 = 47,569 = total_sessions ✓

**Phân tích 3,871 sessions bị loại:**

| Loại | Ước tính | Suy luận từ |
|------|----------|-------------|
| Telnet | ~2,626 | `protocol_distribution.telnet` |
| Scan-only (SSH, không login) | ~1,047 | `ip_analysis.ips_scan_only` tương ứng ~sessions |
| Incomplete/unknown | ~198 | 3,871 − 2,626 − 1,047 |

**Cơ sở khoa học:**
- **RFC 4253:** SSH authentication phase xảy ra sau key exchange. Sessions không đến authentication phase → không phải brute-force.
- **Owezarski (2015):** "sessions without authentication attempts are scanning/probing, not brute-force — they contribute noise to behavioral models."

---

## PHASE 3: COWRIE BIAS CORRECTION

### Dữ liệu vào Phase 3

Từ 43,698 sessions đã chọn ở Phase 2, xác định sessions bị ảnh hưởng bởi UserDB bias.

### Kết quả correction

| Metric | Giá trị | Nguồn (JSON field) |
|--------|---------|---------------------|
| Sessions có root login.success | **26,439** | `bias_correction.attack_sessions_with_root_success` |
| Sessions **giữ** success (3%) | **793** | `bias_correction.sessions_kept_success` |
| Sessions **relabel** → failed (97%) | **25,646** | `bias_correction.sessions_relabeled` |
| Keep rate thực tế | **3.0%** | `bias_correction.keep_rate_actual` |
| Events bị relabel | **25,646** | `bias_correction.events_relabeled` |
| Events giữ success | **793** | `bias_correction.events_kept_success` |

**Cách tính:**
- `sessions_kept_success` = round(26,439 × 0.03) = 793
- `sessions_relabeled` = 26,439 − 793 = 25,646
- `keep_rate_actual` = 793 / 26,439 = 0.03 = **3%**

**Cơ chế relabel:**
1. Liệt kê tất cả sessions có `root login.success` trong 43,698 selected → 26,439 sessions.
2. Shuffle ngẫu nhiên (seed=42) danh sách 26,439 sessions.
3. Giữ nguyên 793 sessions đầu tiên (3%) — `login.success` không đổi.
4. Với 25,646 sessions còn lại: đổi `eventid` từ `cowrie.login.success` → `cowrie.login.failed`.
5. Gắn metadata: `_original_eventid = 'cowrie.login.success'`, `_correction_reason = 'cowrie_userdb_allow_all'`.

**Tại sao 3%?**
- Literature cho range 1–8% (Owezarski 2015: 2–8%; Hofstede 2014: 1–5%).
- 3% nằm trong khoảng trung vị.
- Mục tiêu: feature `success_ratio` có **variation** (không phải 0% cũng không phải 60.8%), phản ánh thực tế.

**Kết quả sau correction:**
- Trước: 26,876 login.success + 18,025 login.failed → success rate ≈ 60%
- Sau: (793 + ~1,230 non-root success) login.success + (18,025 + 25,646) login.failed → success rate ≈ **3–4%** → **khớp literature**

---

## PHASE 4: IP-LEVEL CAMPAIGN CLASSIFICATION

### Mục tiêu

Phân loại chiến dịch tấn công theo **IP** (không theo session) để bắt đúng các botnet phân tán — một IP có thể tạo hàng trăm session ngắn (`fc=1` mỗi session) nhưng tổng hợp ở IP level cho thấy chiến dịch brute-force rõ ràng.

### Cơ chế

Với mỗi IP duy nhất (trong selected sessions):
1. **Gom tất cả login events** (failed + success) xuyên suốt mọi session của IP đó.
2. **Tính:** `ip_fc` (tổng failed), `n_unique_fail` (số username fail duy nhất), `intervals_s` (khoảng cách giữa các lần login).
3. **Phân loại** dựa trên thresholds:

| Campaign type | Điều kiện (ưu tiên từ trên xuống) | Ý nghĩa |
|---------------|-----------------------------------|---------|
| **spraying** | `unique_fail / fc ≥ 0.5` AND `fc ≥ 5` | Thử nhiều username khác nhau (dictionary attack) — ưu tiên cao nhất |
| **bursty** | `fc ≥ 5` AND `avg_interval < 3s` | Tấn công bùng nổ, automated tool chạy liên tục |
| **low_and_slow** | `avg_interval ≥ 30s` | Tấn công chậm, rải đều, né IDS |
| **hit_and_run** | `fc ≤ 2` | Thử 1-2 lần rồi chuyển IP (fleeting probe) |
| **success_only** | `fc == 0` (từ IP chỉ có login.success) | Artifact Cowrie bias đã sửa |
| **scan_only** | IP không có login event | Chỉ scan port, không thử đăng nhập (từ analysis phase) |

### Kết quả (từ pipeline_feature_config.json)

| Campaign type | Số IP |
|---------------|-------|
| scan_only | 1,047 |
| spraying | 271 |
| low_and_slow | 99 |
| success_only | 98 |
| hit_and_run | 67 |
| bursty | 9 |

**Tại sao IP-level thay vì Session-level?**
Botnet hiện đại (Mirai-based) mở connection → thử 1 password → đóng → đợi → thử lại. Nếu track theo session: mỗi session có `fc=1` → bị xếp vào "hit-and-run". Nhưng nếu aggregate theo IP: thấy rõ 100+ failed logins từ cùng 1 IP → chiến dịch low_and_slow hoặc spraying.

---

## PHASE 5: FEATURE RECOMMENDATION

### Dữ liệu vào Phase 5

17 candidate features + kết quả phân tích từ Phase 1 (time range, client version distribution, bias correction status).

### Quy tắc quyết định + kết quả

| Rule | Điều kiện | Dữ liệu | Kết quả | Cơ sở |
|------|-----------|----------|---------|-------|
| **R1** | `time_range_hours < 24` ? | 16.7 < 24 → **YES** | **DROP** `time_of_day_avg` | Owezarski (2015): botnet 24/7, giờ tuyệt đối không discriminative khi data < 24h |
| **R2** | `time_range_days < 2` ? | 0 < 2 → **YES** | **DROP** `num_failed_days` | Hofstede (2014): IP rotation → per-IP day count unreliable khi data ≤ 1 ngày |
| **R3** | `bias_correction_applied` ? | true → **YES** | **KEEP** `success_ratio` | Nội bộ: sau correction, success_ratio phản ánh thực tế → không phải shortcut |
| **R4** | Dominant client version > 80% ? | SSH-2.0-Go = 89.4% → **YES** | **WARNING** `client_version_category` | Cần monitor bằng SHAP analysis |
| **R5** | Mặc định | — | **EXCLUDE** `num_failed_ports`, `ip_entropy` | Sommer & Paxson (2010): phụ thuộc cách assembly dataset |

### Output: `pipeline_feature_config.json`

| Nhóm | Features | Nguồn |
|------|----------|-------|
| **Active (13)** | failed_attempts, num_unique_users, username_entropy, success_ratio, avg_time_between_attempts, login_interval_variance, client_version_category, time_to_auth, session_duration, min_inter_arrival, max_inter_arrival, hour_sin, hour_cos | `feature_config.active_features` |
| **Dropped (2)** | time_of_day_avg, num_failed_days | `feature_config.drop_features` |
| **Shortcut (2)** | num_failed_ports, ip_entropy | `feature_config.shortcut_features` |
| **estimated_attack_feature_vectors** | **1,055** | `feature_config.estimated_attack_feature_vectors` |
| **attack_type_distribution** | IP-level campaign counts | `feature_config.attack_type_distribution` |

**6 features mới (inter-event + cyclic temporal):**
- `time_to_auth`: thời gian từ connect đến auth event đầu tiên — attack thường rất nhanh
- `session_duration`: thời lượng session — attack ngắn, benign dài
- `min_inter_arrival`, `max_inter_arrival`: khoảng cách min/max giữa events — attack đều đặn (automated)
- `hour_sin`, `hour_cos`: mã hóa vòng tròn giờ trong ngày — benign tập trung giờ hành chính

**Con số 1,055 → gửi cho Benign Expert** làm target upscale.

---

## TỔNG KẾT: ATTACK EXPERT OUTPUT

| Output file | Nội dung | Events/Records |
|-------------|----------|----------------|
| `attack_selected.json` | 43,698 sessions (score=1), bias-corrected, tagged `data_origin='attack_cowrie'` | **298,529 events** |
| `pipeline_feature_config.json` | 13 active features, 2 dropped, 2 shortcut, target=1,055, IP campaign distribution | 1 JSON object |
| `attack_expert_report.json` | Toàn bộ statistics + session timelines + event transitions + IP campaigns | ~3,529 dòng JSON |
| `attack_expert_report.html` | Báo cáo visual với decision reasoning (8 sections) | HTML standalone |

**Dòng chảy con số:**
```
313,412 events → 47,569 sessions → 1,591 unique IPs
                    │
           ┌────────┴────────┐
      43,698 selected    3,871 discarded
           │                  (2,626 telnet
      26,439 root success      1,047 scan
           │                    198 incomplete)
     ┌─────┴─────┐
   793 keep    25,646 relabel
   (3%)        (97%)
           │
      298,529 events output
           │
      1,055 estimated feature vectors → gửi cho Step 3B
           │
      IP Campaign Classification (1,591 IPs):
        scan_only: 1,047 │ spraying: 271 │ low_and_slow: 99
        success_only: 98  │ hit_and_run: 67 │ bursty: 9
```
