# DDoS Checker - Work Session Notes

## Current State

- **Branch**: `main`, 1 commit ahead of `origin/main`
- **Last commit**: `d3442ff` - single monolithic commit ("Fix multiple critical bugs, add direct reporting and per-domain status")
- **Daemon**: running in production via `systemctl restart nginx_ddos-checker.service` (screen-based)
- **Service status**: active, PID ~1410883, running the new code
- **Config**: `nginx_ddos_checker.ini` is gitignored, tuned values, `abuseipdb_report_method=bulk`

---

## What Changed (since origin/main)

### Bug Fixes

1. **TCP kill double-fork** (`tcp_kill()`): wrapped `timeout ... tcpkill` in a subshell `( ... & )` so the daemon can't orphan tcpkill past its 60s window on force-kill.

2. **nginx_blocklist sed regex** (lines 200, 239, 302): `sed -i "/$ip/d"` -> `sed -i "/^${ip}$/d"` to prevent matching IPs that are substrings of others.

3. **excluded_ips exact match** (line 170): `[[ "$excluded_ips" =~ $ip ]]` -> `[[ " ${excluded_ips//,/ } " == *" $ip "* ]]` to prevent e.g. `27.0.0.1` matching excluded `127.0.0.1`.

4. **excluded_domains exact match** (line 426): same pattern fix as excluded_ips.

5. **abuseipdb_report boolean check** (line 446): `if $abuseipdb_report;` -> `if [[ "$abuseipdb_report" == "true" ]];` to prevent "command not found" when value is not literally `true`.

6. **CSF bantime missing** (line 273): `csf --tempdeny "$ip_cidr.0/24" "$dist_comment"` -> `csf --tempdeny "$ip_cidr.0/24" "$bantime" "$dist_comment"` — bantime was never passed.

7. **nginx CIDR restart_nginx reset** (was line 191): removed `restart_nginx=0` inside the "already banned" else branch — was resetting the flag for *all* domains.

8. **/24 CIDR range bug** (lines 183-184, 272-278, 286-293): `$ip_cidr_1.$ip_cidr_2` (2 octets) -> `$ip_cidr_1.$ip_cidr_2.$ip_cidr_3` (3 octets). All `$ip_cidr.0.0/24` -> `$ip_cidr.0/24`. Fixes wrong network range for /24 bans.

### New Features

9. **AbuseIPDB direct report** (`abuseipdb_direct_report()`): single-IP v2 /report endpoint with HTTP 429 detection, saves response JSON. `abuseipdb_report_ip()` dispatcher auto-falls back direct->bulk on rate limit. New config key `abuseipdb_report_method=bulk|direct`.

10. **Per-domain attack status** (`attack_status()`): reads `csf -t` for entries matching `part of network|lone high-rate source`, filters to offenders in the affected domain's log, prints compact 80-column status block beneath that domain's scan. Triggered via `flagged_domain=1` set inside `check_logs()`.

11. **Lone high-rate ban path** (inside check_logs "not distributed" branch): when `total_timeframe_requests > total_threshold`, bans the exact IP (csf `/32` tempdeny + nginx_blocklist + AbuseIPDB), NOT the /24 to avoid cloud collateral.

### Performance / Rewrites

12. **Single-pass per-IP counting**: `declare -A timeframe_count / additional_timeframe_count` via `awk '{c[$1]++} END {...}'` instead of repeated `grep -c "$ip"` per unique IP.

13. **Distributed detection rewrite**: window-scoped metrics:
    - `distributed_group_requests`: requests from IPs sharing culprit's first octet (45.x.x.x) in the timeframe window
    - `distributed_sources`: distinct source IPs in that first-octet group (this window only)
    - `distributed_bot_peak`: loudest OTHER source in the /8 excluding the culprit
    - Gate: requires `sources >= 3` AND `bot_peak >= threshold/2` — prevents cloud /8 false positives
    - Removed all-time `distributed_total_requests` and dead `distributed_requests_1/_2` variables
    - Removed impossible condition `d1 > d1+d2`

14. **Config tuning** (both INI files): `timeframe=10`, `threshold=30`, `additional_threshold=100`, `additional_timeframe=10`, `total_threshold=100`, `bantime=7200`

15. **AbuseIPDB config read** (line 407): `abuseipdb_report_method=$(config_grep abuseipdb_report_method)`

### Files

16. **AGENTS.md** created (untracked) — session documentation for opencode agents.

17. **example_nginx_ddos_checker.ini** updated with tuned values + `abuseipdb_report_method=bulk`.

---

## Production Log

### Bans issued

| IP | Type | When | Traffic | Ban duration | Status |
|---|---|---|---|---|---|
| `193.92.230.67` | lone high-rate (scraper, invidious thumbnails) | ~14:30 | 86-224/10min | 2h | expired |
| `34.185.194.222` | lone high-rate (Google Cloud, /firebase-key.json) | ~16:47 | 278/10min (1670/hr) | 2h | expired |

Both reported to AbuseIPDB via bulk CSV. `34.185.194.222` traffic stopped after ban.

### lfd tempdenies (unrelated to script)

- `45.130.51.250` (amazonbot) — from lfd, not script
- Various googlebot entries — from lfd

---

## Known Issues / TODO

### Indentation bug in main loop

Lines 440-441 (`restart_nginx=0` and `flagged_domain=0`) are flush-left but should be indented inside the `if` block. Cosmetic only but should be fixed:

```bash
  if [[ "$restart_nginx" == "1" ]]; then
    >/dev/null 2>&1 nginx -t && systemctl restart nginx && echo "ℹ️  Nginx has been restarted."
restart_nginx=0    # <-- should be indented with 4 spaces
flagged_domain=0   # <-- same
  fi
```

### Pending: split monolithic commit

The user wants to split `d3442ff` into one commit per logical fix. Plan:

1. `git reset HEAD~1` to unstage everything (working tree keeps changes)
2. Re-commit each group in logical order, one per commit

#### Planned commit order (logical dependency order)

| # | Commit message | Key changes |
|---|---|---|
| 1 | Fix nginx_blocklist sed regex to prevent substring matching | `sed -i "/^${ip}$/d"` |
| 2 | Fix excluded_ips exact match to prevent substring shadowing | `[[ " ${excluded_ips//,/ } " == *" $ip "* ]]` |
| 3 | Fix excluded_domains exact match | same pattern |
| 4 | Fix abuseipdb_report boolean check to prevent command-not-found | `[[ "$abuseipdb_report" == "true" ]]` |
| 5 | Pass bantime to csf tempdeny for distributed ban path | `csf --tempdeny "$ip_cidr.0/24" "$bantime" "$dist_comment"` |
| 6 | Fix /24 CIDR range to use correct 3-octet prefix | `ip_cidr_3` added, all `.0.0/24` -> `.0/24` |
| 7 | Remove restart_nginx reset inside nginx CIDR else branch | deleted `restart_nginx=0` from "already banned" |
| 8 | Fix tcpkill double-fork to survive daemon teardown | `( timeout ... tcpkill ... & )` |
| 9 | Improve per-IP counting efficiency with awk arrays | `declare -A timeframe_count` etc. |
| 10 | Rewrite distributed detection with window-scoped metrics | `distributed_sources`, `distributed_bot_peak`, gate logic |
| 11 | Add lone high-rate exact-IP ban path | not-distributed but high volume -> ban exact IP |
| 12 | Add AbuseIPDB direct report with auto-fallback to bulk | `abuseipdb_direct_report()`, `abuseipdb_report_ip()`, config key |
| 13 | Add per-domain attack status reporting | `attack_status()`, `flagged_domain` flag, domain loop integration |
| 14 | Tune detection thresholds and ban duration | `timeframe=10`, `threshold=30`, `additional_threshold=100`, etc. |
| 15 | Add AGENTS.md session documentation | new untracked file |
| 16 | Update example config with tuned values and report method | `example_nginx_ddos_checker.ini` |

#### Execution strategy

Since changes are interleaved across functions, use `git add -p` (patch mode) or manually construct each commit. The cleanest approach:

```bash
git reset HEAD~1  # unstage, keep working tree
# For each commit:
git add -p nginx_ddos_checker.sh  # stage only the relevant hunks
# or for INI/config changes:
git add example_nginx_ddos_checker.ini
git add AGENTS.md
git commit -m "..."
```

**Key challenge**: hunks in `check_logs()` are interleaved (CIDR fix touches lines that also have the distributed rewrite). May need to edit hunks manually in `git add -p` or use `git diff > patch` and reconstruct.

**Alternative**: create the original file (`git show HEAD~1:nginx_ddos_checker.sh > /tmp/orig.sh`) and apply patches one at a time, committing each. Then cherry-pick the INI and AGENTS.md changes.

---

## Service Management Notes

- Service type: `Type=simple`, runs `screen -DmS nginx_ddos_checker ...`
- `systemctl start` hangs because screen keeps running in foreground
- **Correct restart method**:
  ```bash
  systemctl reset-failed nginx_ddos-checker.service
  screen -S nginx_ddos_checker -X quit
  sleep 2
  nohup systemctl restart nginx_ddos-checker.service >/tmp/svc_restart.log 2>&1 &
  # verify
  systemctl is-active nginx_ddos-checker.service
  pgrep -af 'nginx_ddos_checker.sh' | grep -v pgrep | grep bash
  ```

---

## Config Reference (live `nginx_ddos_checker.ini`)

```ini
nginx_logs_path=/home/abuseipdb/public_html/
nginx_blocklist=/home/abuseipdb/public_html/nginx_blocklist.txt
nginx_block=true
nginx_cidr_blocklist=/etc/nginx/snippets/nginx_cidr_blocklist.conf
nginx_cidr=true
excluded_domains=
excluded_ips=
timeframe=10
threshold=30
additional_threshold=100
additional_timeframe=10
total_threshold=100
bantime=7200
abuseipdb_token=/home/abuseipdb/tokens/abuseipdb
abuseipdb_report=true
abuseipdb_log_folder=/var/log/abuseipdb
abuseipdb_report_method=bulk
abuseipdb_bulk_report_interval=12hours
csf=true
tcp_kill=true
```
