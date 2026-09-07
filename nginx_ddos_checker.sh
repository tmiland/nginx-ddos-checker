#!/usr/bin/env bash

# Detect absolute and full path
sfp=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || greadlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
if [ -z "$sfp" ]; then sfp=${BASH_SOURCE[0]}; fi
SCRIPT_DIR=$(dirname "${sfp}")

if [[ $* =~ "debug" ]]
then
  set -o errexit
  set -o pipefail
  set -o nounset
  set -o xtrace
fi

restart_nginx=0

abuseipdb_bulk_report() {
  category="4,19,21"
  abuseipdb_report_time=$(date +"%Y-%m-%dT%H:%M:%S%z")
  # Strip server IP from log
  if echo "$ip_logs" | grep -Eq $excluded_ips; then
    echo "ℹ️  Stripped $excluded_ips from logs..."
    ip_logs=$(echo "$ip_logs" | sed "s/$excluded_ips/*.*.*.*/g")
  fi
  # Strip server domain from log
  if echo "$ip_logs" | grep -Eq $domain; then
    echo "ℹ️  Removed $domain from logs..."
    ip_logs=$(echo "$ip_logs" | sed "s/$domain/*.*/g")
  fi
  ip_logs=$(echo "$ip_logs" | sed "s/\"/\\\\\"/g")
  comment="$comment; Logs: $(echo "$ip_logs" | tr '\n' ' ')"
  # Truncate comment
  # Source: https://linuxgenie.net/truncate-string-variable-in-bash
  if [[ ${#comment} > 1024 ]]; then
    echo "ℹ️  Truncated comment to 1024 characters..."
    comment=${comment:0:1024}
  fi
  # Create directory if it doesn't exist
  if ! [ -d "$abuseipdb_log_folder" ]; then
    mkdir -p "$abuseipdb_log_folder"
  fi
  # Generate csv
  if ! [ -f "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv ]; then
    touch "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv
    # Add csv header
    if ! grep -q "IP,Categories,ReportDate,Comment" "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv; then
      tee "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv <<'EOF' >/dev/null
IP,Categories,ReportDate,Comment
EOF
    fi
  fi
  # Add ip's to csv bulk report
  if ! grep -q "${ip}" "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv; then
    # Add ip, catecories, report time and log to csv
    echo "${ip},\"${category}\",${abuseipdb_report_time},\"${comment}\"" >> "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv
    echo "🚫 IP ${ip} has been added to the bulk report."
  else
    echo "ℹ️  IP ${ip} with report date ${abuseipdb_report_time} already exist in the bulk report."
  fi
}

abuseipdb_submit_bulk_report() {
  # Capture the HTTP status code; only a 200 should clear the queue.
  local resp code
  resp=$(curl -s -w '\n%{http_code}' https://api.abuseipdb.com/api/v2/bulk-report \
    -F csv=@"$abuseipdb_log_folder"/abuseipdb_bulk_report.csv \
    -H "Key: $abuseipdb_token" \
    -H "Accept: application/json")
  code=$(echo "$resp" | tail -n 1)
  echo "$resp" | sed '$d' > "$abuseipdb_log_folder"/abuseipdb_bulk_report_"${abuseipdb_report_time}".json
  echo "$code"
}

# Report a single IP directly to AbuseIPDB (no queueing), then check the
# HTTP response for rate limiting.
abuseipdb_direct_report() {
  category="4,19,21"
  abuseipdb_report_time=$(date +"%Y-%m-%dT%H:%M:%S%z")
  if echo "$ip_logs" | grep -Eq $excluded_ips; then
    ip_logs=$(echo "$ip_logs" | sed "s/$excluded_ips/*.*.*.*/g")
  fi
  if echo "$ip_logs" | grep -Eq $domain; then
    ip_logs=$(echo "$ip_logs" | sed "s/$domain/*.*/g")
  fi
  ip_logs=$(echo "$ip_logs" | sed "s/\"/\\\\\"/g")
  report_comment="$comment; Logs: $(echo "$ip_logs" | tr '\n' ' ')"
  if [[ ${#report_comment} > 1024 ]]; then
    report_comment=${report_comment:0:1024}
  fi
  if ! [ -d "$abuseipdb_log_folder" ]; then
    mkdir -p "$abuseipdb_log_folder"
  fi
  # Capture the HTTP status code to detect rate limiting (429)
  local resp
  resp=$(curl -s -w '\n%{http_code}' https://api.abuseipdb.com/api/v2/report \
    -H "Key: $abuseipdb_token" \
    -H "Accept: application/json" \
    -F "ip=$ip" \
    -F "categories=$category" \
    -F "comment=$report_comment")
  local code
  code=$(echo "$resp" | tail -n 1)
  echo "$resp" | sed '$d' > "$abuseipdb_log_folder"/abuseipdb_direct_report_"${abuseipdb_report_time}".json
  if [[ "$code" == "429" ]]; then
    echo "ℹ️  Direct report for $ip hit a rate limit (429)."
    return 1
  fi
  echo "🚫 IP $ip reported directly to AbuseIPDB (HTTP $code)."
  return 0
}

# Dispatcher: report the IP using the configured method, auto-switching to the
# other method when the current one runs into a rate limit.
abuseipdb_report_ip() {
  if [[ "$abuseipdb_report_method" == "direct" ]]; then
    abuseipdb_direct_report && return 0
    echo "ℹ️  Rate limit on direct report - switching this IP to the bulk queue."
    abuseipdb_bulk_report
    return 0
  fi
  # default: bulk queue first
  abuseipdb_bulk_report
}

tcp_kill() {
  # Double-fork so the timeout wrapper (and tcpkill) survive daemon teardown;
  # otherwise a force-killed daemon orphans tcpkill past its 60s window.
  ( timeout -k 5 -s 9 60 \
      tcpkill -9 host "$ip" >/dev/null 2>&1 & )
}

# Function to check logs for DDoS attacks
check_logs() {
  local domain="$1"
  local log_file="$2"
  local timeframe="$3"
  local threshold="$4"
  local additional_threshold="$5"
  local additional_timeframe="$6"

  echo "✅ Checking logs for $domain"

  # Credit: https://stackoverflow.com/a/55050093
  log_timeframe=$(awk -F '[][]' -v stop_when_before="$(date -d "-${timeframe}minutes" +'%d/%b/%Y:%T %z')" '
    $2 < stop_when_before { exit }
    1 { print }
  ' < <(tac "$log_file"))

  log_additional_timeframe=$(awk -F '[][]' -v stop_when_before="$(date -d "-${additional_timeframe}minutes" +'%d/%b/%Y:%T %z')" '
    $2 < stop_when_before { exit }
    1 { print }
  ' < <(tac "$log_file"))

  # log_time_frame=$(awk -v d1="$(date --date 'now -'"$timeframe"' min' '+%d/%b/%Y:%T')" '{gsub(/^[\[\t]+/, "", $4);}; $4 > d1' "$log_file")
  # Per-IP request counts in a single awk pass per window, instead of
  # growling the whole window once per unique IP in the loop below.
  declare -A timeframe_count
  while read -r c_ipk r_cnt; do
    timeframe_count["$c_ipk"]=$r_cnt
  done < <(echo "$log_timeframe" | awk '{c[$1]++} END {for (k in c) print k, c[k]}')
  declare -A additional_timeframe_count
  while read -r c_ipk r_cnt; do
    additional_timeframe_count["$c_ipk"]=$r_cnt
  done < <(echo "$log_additional_timeframe" | awk '{c[$1]++} END {for (k in c) print k, c[k]}')

  ips=$(echo "$log_timeframe" | awk '{print $1}' | sort -u)

  # Loop through all unique IPs and send the data to AbuseIPDB
  for ip in $ips; do

    # Exact match, so an excluded IP can't accidentally shadow a substring
    # (e.g. 27.0.0.1 matching excluded "127.0.0.1")
    if [[ " ${excluded_ips//,/ } " == *" $ip "* ]]; then
      echo "ℹ️  Skipping $ip as it is excluded."
      continue
    fi

    # Per-IP counts from the precomputed single-pass arrays
    timeframe_requests=${timeframe_count["$ip"]:-0}
    additional_timeframe_requests=${additional_timeframe_count["$ip"]:-0}
    # Count total number of attacks
    # total_requests=$(cat "$log_file" | grep -c "$ip")
    # Get culprit's network grouping
    ip_cidr_1=$(echo "$ip" | cut -d '.' -f1)
    ip_cidr_2=$(echo "$ip" | cut -d '.' -f2)
    ip_cidr_3=$(echo "$ip" | cut -d '.' -f3)
    ip_cidr="$ip_cidr_1.$ip_cidr_2.$ip_cidr_3"
    # Distributed-attack metrics: anchored to the source-IP field and scoped to the
    # window, so response codes/timestamps/stale all-time traffic can't inflate counts.
    # Requests in the window from IPs sharing the culprit's first octet (45.x.x.x)
    distributed_group_requests=$(echo "$log_timeframe" \
      | awk -v oct="$ip_cidr_1" '$1 ~ "^" oct "\\." {n++} END {print n+0}')
    # Distinct sources in that first-octet group (a botnet spreads across many IPs)
    distributed_sources=$(echo "$log_timeframe" \
      | awk -v oct="$ip_cidr_1" '$1 ~ "^" oct "\\." {print $1}' | sort -u | wc -l | tr -d ' ')
    # Loudest OTHER source in the culprit's /8 (excluding the culprit itself).
    # Proves genuine distribution: at least one independent machine must be
    # individually pushing substantial traffic, so a busy cloud /8 full of
    # innocent 1-2 request users can't inflate the group count.
    distributed_bot_peak=$(echo "$log_timeframe" \
      | awk -v oct="$ip_cidr_1" -v culprit="$ip" \
          '$1 ~ "^" oct "\\." && $1 != culprit {c[$1]++} END {m=0; for (k in c) if (c[k]>m) m=c[k]; print m+0}')
    total_timeframe_requests=$(( timeframe_requests + additional_timeframe_requests ))
    # Generate comments
    dist_comment="$ip is part of network $ip_cidr_1.0.0.0 with $distributed_sources source(s) ($distributed_group_requests connections) in the last $timeframe minutes"
    comment="Detected $timeframe_requests connections from $ip last $timeframe minutes."

    if [[ "$timeframe_requests" -gt "$threshold" ]]; then
      flagged_domain=1
      echo "🛑 $comment"

      # A distributed attack needs other machines in the same network range:
      # at least 3 distinct sources in the culprit's first-octet group this window,
      # AND the loudest other source must be individually meaningful (>= half the
      # single-IP threshold). This keeps a busy cloud /8 (many innocent 1-2 request
      # users) from ever looking like a botnet, while still catching botnets whose
      # members each contribute a moderate share.
      if [[ "$distributed_sources" -lt 3 ]] \
        || [[ "$distributed_bot_peak" -lt "$(( threshold / 2 ))" ]]; then
        echo "ℹ️  $ip is not part of a distributed attack ($distributed_sources source(s), loudest other $distributed_bot_peak req in $ip_cidr_1.0.0.0)."
        # Not distributed, but a lone source hammering this hard is still
        # abusive: ban the exact IP (not the /24, to avoid cloud collateral)
        # once its combined rate clears the total high-volume threshold.
        if [[ "$total_timeframe_requests" -gt "$total_threshold" ]]; then
          comment="$comment; lone high-rate source (combined $total_timeframe_requests requests in both windows)"
          echo "ℹ️  $ip is a lone high-rate source ($total_timeframe_requests combined requests) - banning exact IP."
          if [[ $csf == "true" ]]; then
            if csf -g "$ip" | grep -q "No matches found"; then
              csf --tempdeny "$ip" "$bantime" "$comment" >/dev/null 2>&1
              echo
              echo "🚫 Banned IP $ip for $bantime seconds in csf firewall."
              echo
            else
              echo "ℹ️  IP $ip is temporarily banned in csf firewall already."
            fi
          fi
          if [[ $nginx_block == "true" ]]; then
            if ! [ -f "$nginx_blocklist" ]; then
              touch "$nginx_blocklist"
            fi
            if ! grep -qw "$ip" "$nginx_blocklist"; then
              sed -i "/^${ip}$/d" "$nginx_blocklist"
              echo "$ip" | tee >> "$nginx_blocklist"
              echo "🚫 IP $ip has been added to the Nginx blocklist."
              echo
            else
              echo "ℹ️  IP $ip has been banned in the Nginx blocklist already."
            fi
          fi
          if [[ $abuseipdb_report == "true" ]]; then
            ip_logs=$(cat "$log_file" | grep -F "$ip")
            abuseipdb_report_ip
            sleep 0.1
          fi
        fi
        continue
      fi
      # Distributed attack confirmed - ban when the volume is meaningful:
      # group traffic above additional_threshold, culprit above total_threshold,
      # or the group collectively outdoes the culprit's two-window count
      # (distributed traffic exceeds "1 & 2 combined").
      if [[ "$distributed_group_requests" -gt "$additional_threshold" ]] \
        || [[ "$total_timeframe_requests" -gt "$total_threshold" ]] \
        || [[ "$distributed_group_requests" -gt "$total_timeframe_requests" ]]; then
        comment="$comment; $dist_comment"
        echo "ℹ️  $dist_comment"
        
        if [[ $csf == "true" ]]; then
          # Run tcpkill on ip
          if [[ $tcp_kill == "true" ]]; then
            tcp_kill
            echo "ℹ️  tcpkill executed on IP $ip for 60 seconds."
          fi
          # Tempban ip in csf
          if csf -g "$ip_cidr.0/24" | grep -q "No matches found"; then
            csf --tempdeny "$ip_cidr.0/24" "$bantime" "$dist_comment" >/dev/null 2>&1
            echo
            echo "🚫 Banned IP CIDR $ip_cidr.0 from IP $ip for $bantime seconds in csf firewall."
            echo
          else
            echo "ℹ️  IP CIDR $ip_cidr.0/24 is temporarily banned in csf firewall already."
          fi
        fi
        if [[ $nginx_cidr == "true" ]]; then
          if ! [ -f "$nginx_cidr_blocklist" ]; then
            touch "$nginx_cidr_blocklist"
          fi
          # Add ip to nginx cidr blocklist if not found
          if ! grep -qw "$ip_cidr.0/24" "$nginx_cidr_blocklist"; then
            sed -i "/$ip_cidr.0\/24/d" "$nginx_cidr_blocklist"
            echo "$ip_cidr.0/24 1;" | tee >> "$nginx_cidr_blocklist"
            echo "🚫 IP CIDR $ip_cidr.0/24 has been added to the Nginx CIDR blocklist."
            echo
            restart_nginx=1
          else
            echo "ℹ️  IP CIDR $ip_cidr.0/24 has been banned in the Nginx CIDR blocklist already."
          fi
        fi
        if [[ $nginx_block == "true" ]]; then
          if ! [ -f "$nginx_blocklist" ]; then
            touch "$nginx_blocklist"
          fi
          # Add ip to nginx blocklist if not found
          if ! grep -qw "$ip" "$nginx_blocklist"; then
            sed -i "/^${ip}$/d" "$nginx_blocklist"
            echo "$ip" | tee >> "$nginx_blocklist"
            echo "🚫 IP $ip has been added to the Nginx blocklist."
            echo
          else
            echo "ℹ️  IP $ip has been banned in the Nginx blocklist already."
          fi
        fi
        if [[ $abuseipdb_report == "true" ]]; then
          # Relevant log lines for this IP, needed for the AbuseIPDB report comment
          ip_logs=$(cat "$log_file" | grep -F "$ip")
          abuseipdb_report_ip
          sleep 0.1
        fi
      fi
    fi
  done
}

# Report the current attack status for a given domain: any offenders our script
# has banned that are still blocked in csf, each with whether it is also blocked
# at Nginx layer(s) and whether it has been reported to AbuseIPDB. Only renders
# when the domain is actually affected. Output is wrapped to 80 columns.
attack_status() {
  local domain="$1"
  local blocked line ip ttl type extra layer stat col
  # csf tempdeny entries still blocked whose comment carries our offence markers.
  blocked="$({ csf -t 2>/dev/null || true; } | grep -iE 'part of network|lone high-rate source' || true)"
  if [[ -z "$blocked" ]]; then
    return 0
  fi

  echo
  echo "⚠️  ONGOING ATTACK on $domain:"
  echo
  while IFS= read -r line; do
    # Lines look like: DENY <ip>  * inout 4h 5m 2s <comment>
    ip=$(echo "$line" | awk '{print $2}')
    # Only report offenders actually seen in this domain's log.
    if ! grep -qF "$ip" "$nginx_logs_path/$domain"_access_log; then
      continue
    fi
    ttl=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /s$|m$|h$/) {print $i; break}}')
    type=$(echo "$line" | grep -q 'lone high-rate' && echo "lone high-rate" || echo "distributed")
    extra=$(echo "$line" | grep -o 'Detected [0-9]* connections[^;]*')
    # Blocked layer status
    layer="csf"
    if [[ "$nginx_block" == "true" ]] && grep -qw "$ip" "$nginx_blocklist" 2>/dev/null; then
      layer="$layer, nginx-ip"
    fi
    if [[ "$nginx_cidr" == "true" ]] && grep -qw "$(echo "$ip" | cut -d. -f1-3).0/24" "$nginx_cidr_blocklist" 2>/dev/null; then
      layer="$layer, nginx-cidr"
    fi
    # Reported status
    stat="not reported"
    if [[ "$abuseipdb_report" == "true" ]]; then
      if ls "$abuseipdb_log_folder"/abuseipdb_direct_report_*.json >/dev/null 2>&1 \
        && grep -lq "$ip" "$abuseipdb_log_folder"/abuseipdb_direct_report_*.json 2>/dev/null; then
        stat="reported-direct"
      elif ls "$abuseipdb_log_folder"/abuseipdb_bulk_report_*.csv >/dev/null 2>&1 \
        && grep -lq "^$ip," "$abuseipdb_log_folder"/abuseipdb_bulk_report_*.csv 2>/dev/null; then
        stat="reported-bulk"
      fi
    fi
    # Build a compact, 80-column-wrapped status block for this offender.
    printf '  IP        : %s\n' "$ip"
    printf '  Type      : %s\n' "$type"
    printf '  Traffic   : %s\n' "$extra"
    printf '  Remaining : %s\n' "$ttl"
    printf '  Blocked   : %s\n' "$layer"
    printf '  Reported  : %s\n' "$stat"
    echo
  done <<< "$blocked"
  echo "---------------------------------------------"
  echo
}

# Main script
config_file="${SCRIPT_DIR}/nginx_ddos_checker.ini"
example_config_file=""${SCRIPT_DIR}/example_nginx_ddos_checker.ini""

if [[ ! -f "$config_file" ]]; then
  cp -rp "$example_config_file" "$config_file" \
    || echo "Error: Configuration file $config_file not found."; exit 1;
fi
config_grep() {
  grep -Pow ''"$1"'=\K.*' "$config_file"
}
# Read configurations from the INI file
nginx_logs_path=$(config_grep nginx_logs_path)
nginx_blocklist=$(config_grep nginx_blocklist)
nginx_block=$(config_grep nginx_block)
nginx_cidr_blocklist=$(config_grep nginx_cidr_blocklist)
nginx_cidr=$(config_grep nginx_cidr)
excluded_domains=$(config_grep excluded_domains)
excluded_ips=$(config_grep excluded_ips)
timeframe=$(config_grep timeframe)
threshold=$(config_grep threshold)
additional_threshold=$(config_grep additional_threshold)
additional_timeframe=$(config_grep additional_timeframe)
total_threshold=$(config_grep total_threshold)
bantime=$(config_grep bantime)
abuseipdb_token=$(config_grep abuseipdb_token)
abuseipdb_report=$(config_grep abuseipdb_report)
abuseipdb_log_folder=$(config_grep abuseipdb_log_folder)
abuseipdb_report_method=$(config_grep abuseipdb_report_method)
abuseipdb_bulk_report_interval=$(config_grep abuseipdb_bulk_report_interval)
csf=$(config_grep csf)
tcp_kill=$(config_grep tcp_kill)
# Check if csf is installed
if ! [[ $(command -v 'csf') ]]; then
  echo "ℹ️  csf is not installed..."
fi
# AbuseIPDB
# Set your AbuseIPDB API key here.
abuseipdb_token=$(< "$abuseipdb_token")
# Check available parked domains in Nginx
virtual_hosts=($(ls "$nginx_logs_path" | grep -E '_access_log' | sed -E 's/^_access_log//g' | grep -v '.gz' | sed "s|_access_log||g"))
while true; do
  begin_check=$(date)
  # Source: https://stackoverflow.com/a/8903280
  SECONDS=0
  # Check logs for DDoS attacks for each domain
  for domain in "${virtual_hosts[@]}"; do
    if [[ " ${excluded_domains//,/ } " == *" $domain "* ]]; then
      echo "ℹ️  Skipping $domain as it is excluded."
    else
      flagged_domain=0
      check_logs "$domain" "$nginx_logs_path/$domain"_access_log "$timeframe" "$threshold" "$additional_threshold" "$additional_timeframe"
      # Report any ongoing attack on this specific domain right beneath its scan.
      if [[ "$flagged_domain" == "1" ]]; then
        attack_status "$domain"
      fi
    fi
  done

  if [[ "$restart_nginx" == "1" ]]; then
    >/dev/null 2>&1 nginx -t && systemctl restart nginx && echo "ℹ️  Nginx has been restarted."
    restart_nginx=0
    flagged_domain=0
  fi

  # AbuseIPDB bulk report submission (interval since the first queued entry)
  now=$(date +%s)
  if [[ "$abuseipdb_report" == "true" ]]; then
    # Latest response file from an ISO-timestamped submission; ignores stale
    # old-format leftovers like abuseipdb_bulk_report_.json
    latest_json=$(ls -t "$abuseipdb_log_folder"/abuseipdb_bulk_report_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T*.json 2>/dev/null | head -n 1)
    last_abuseipdb_report=""
    if [[ -n "$latest_json" ]]; then
      last_abuseipdb_report=$(basename "$latest_json" | sed 's/^abuseipdb_bulk_report_//; s/\.json$//')
    fi
    if [ -f "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv ] \
      && [[ $(wc -l < "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv) -gt 1 ]]; then
      # Get report date from the first data row of the CSV (ISO timestamp)
      abuseipdb_first_date=$(sed -n '2p' "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv \
        | grep -Po '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4}' \
        | head -n 1)
      # Set interval for bulk report submission (epoch seconds)
      abuseipdb_next_report=0
      if [[ -n "$abuseipdb_first_date" ]]; then
        abuseipdb_next_report=$(date -d "$abuseipdb_first_date +$abuseipdb_bulk_report_interval" +%s 2>/dev/null || echo 0)
      fi
      # Submit abuseipdb bulk report if past interval
      if [[ "$now" -ge "$abuseipdb_next_report" ]]; then
        # Skip if the daily rate limit was already hit today
        if [[ -n "$latest_json" ]] \
          && [[ "${last_abuseipdb_report%%T*}" == "$(date +%F)" ]] \
          && jq -r '.errors[]?.detail // empty' "$latest_json" 2>/dev/null | grep -q "Daily rate limit"; then
          echo "⚠️  AbuseIPDB daily rate limit already hit today - keeping the bulk queue."
        else
          # Submit abuseipdb bulk report; only clear the queue on HTTP 200
          echo "ℹ️  Submitting AbuseIPDB bulk report."
          abuseipdb_report_time=$(date +"%Y-%m-%dT%H:%M:%S%z")
          code=$(abuseipdb_submit_bulk_report)
          if [[ "$code" == "200" ]]; then
            echo "Ok."
            mv "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv "$abuseipdb_log_folder"/abuseipdb_bulk_report_"${abuseipdb_report_time}".csv
          else
            echo "⚠️  AbuseIPDB bulk report failed (HTTP $code) - keeping the bulk queue."
          fi
        fi
      else
        echo
        echo "⌚ AbuseIPDB bulk report will be submitted after $(date -d "@$abuseipdb_next_report" +"%F %H:%M")."
        echo
        if [[ -n "$last_abuseipdb_report" ]]; then
          echo "⌚ Last AbuseIPDB report was submitted at $(date -d "$last_abuseipdb_report" +"%F %H:%M")."
        fi
      fi
    fi
  fi
  end_check=$(date)
  duration=$SECONDS
  echo
  echo "⌚ Last check: $begin_check"
  echo "     Finished: $end_check ($((duration / 60)) minutes and $((duration % 60)) seconds elapsed.)"
  echo
  echo "💤 Sleeping for 60 seconds..."
  echo
  sleep 60
done
