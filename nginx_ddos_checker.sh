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
  curl -s https://api.abuseipdb.com/api/v2/bulk-report \
    -F csv=@"$abuseipdb_log_folder"/abuseipdb_bulk_report.csv \
    -H "Key: $abuseipdb_token" \
    -H "Accept: application/json" \
    > "$abuseipdb_log_folder"/abuseipdb_bulk_report_"${abuseipdb_report_time}".json
}

tcp_kill() {
  # execute tcpkill for 60 seconds
  timeout --foreground -k 60 -s 9 60 \
    tcpkill -9 host "$ip" >/dev/null 2>&1 &
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
  log_timeframe=$(awk -F '[][]' -v stop_when_before="$(date -d -"$timeframe"minutes +'%d/%b/%Y:%T %z')" '
    $2 < stop_when_before { exit }
    1 { print }
  ' < <(tac "$log_file"))

  log_additional_timeframe=$(awk -F '[][]' -v stop_when_before="$(date -d -"$additional_timeframe"minutes +'%d/%b/%Y:%T %z')" '
    $2 < stop_when_before { exit }
    1 { print }
  ' < <(tac "$log_file"))

  # log_time_frame=$(awk -v d1="$(date --date 'now -'"$timeframe"' min' '+%d/%b/%Y:%T')" '{gsub(/^[\[\t]+/, "", $4);}; $4 > d1' "$log_file")
  ips=$(echo "$log_timeframe" | awk '{print $1}' | sort -u)

  # Loop through all unique IPs and send the data to AbuseIPDB
  for ip in $ips; do

    if [[ "$excluded_ips" =~ $ip ]]; then
      echo "ℹ️  Skipping $ip as it is excluded."
      continue
    fi

    # Count timeframe requests per ip
    timeframe_requests=$(echo "$log_timeframe" | grep -c "$ip")
    # Count additional timeframe requests per ip
    additional_timeframe_requests=$(echo "$log_additional_timeframe" | grep -c "$ip")
    # Count total number of attacks
    # total_requests=$(cat "$log_file" | grep -c "$ip")
    # Extract relevant logs for the current IP
    ip_logs=$(cat "$log_file" | grep "$ip")
    # Get first two groups
    ip_cidr_1=$(echo "$ip" | cut -d '.' -f1)
    ip_cidr_2=$(echo "$ip" | cut -d '.' -f2)
    ip_cidr="$ip_cidr_1.$ip_cidr_2"
    # Count ips from network
    distributed_requests_1=$(echo "$log_timeframe" | grep -c "$ip_cidr_1")
    distributed_requests_2=$(echo "$log_timeframe" | grep -c "$ip_cidr_2")
    distributed_requests=$(( distributed_requests_1 + distributed_requests_2 ))
    total_timeframe_requests=$(( timeframe_requests + additional_timeframe_requests ))
    # total_timeframe_distributed_requests=$((  ))
    distributed_total_requests=$(awk '{print $1}' "$log_file" \
        | awk -F'.' '{print $1"."0"."0"."0}' \
        | sort \
        | uniq -c \
      | sort -rn | grep "$ip_cidr_1.0.0.0" | cut -d ' ' -f2)
    # Generate comments
    dist_comment="$ip is part of network $ip_cidr.0.0 with $distributed_requests distributed connections"
    dist_total_comment="$ip is part of network $ip_cidr_1.0.0.0 with $distributed_total_requests total distributed connections"
    comment="Detected $timeframe_requests connections from $ip last $timeframe minutes."

    if [[ "$timeframe_requests" -gt "$threshold" ]]; then
      echo "🛑 $comment"

      # Exit if requests per timeframe is less than distributed requests
      if ! [[ "$timeframe_requests" -lt "$distributed_requests" ]]; then
        continue
      fi
      # If distributed requests 1 & 2 combined are above threshold or
      # ip group 1 has more requests than 1 & 2 combined or
      # distributed total requests is greater than timeframe + additional timeframe requests or
      # distributed total requests is greater than total threshold
      if [[ "$distributed_requests" -gt "$additional_threshold" ]] \
        || [[ "$distributed_requests_1" -gt "$distributed_requests" ]] \
        || [[ "$total_timeframe_requests" -gt "$total_threshold" ]] \
        || [[ "$distributed_total_requests" -gt "$total_timeframe_requests" ]]; then
        # Generate comments
        if [[ "$distributed_total_requests" -gt "$total_timeframe_requests" ]]; then
          comment="$comment; $dist_total_comment"
          echo "ℹ️  $dist_total_comment"
        else
          comment="$comment; $dist_comment"
          echo "ℹ️  $dist_comment"
        fi
        
        if [[ $csf == "true" ]]; then
          # Run tcpkill on ip
          if [[ $tcp_kill == "true" ]]; then
            tcp_kill
            echo "ℹ️  tcpkill executed on IP $ip for 60 seconds."
          fi
          # Tempban ip in csf
          if csf -g "$ip_cidr.0.0/24" | grep -q "No matches found"; then
            csf --tempdeny "$ip_cidr.0.0/24" "$dist_comment" >/dev/null 2>&1
            echo
            echo "🚫 Banned IP CIDR $ip_cidr.0.0 from IP $ip for $bantime seconds in csf firewall."
            echo
          else
            echo "ℹ️  IP CIDR $ip_cidr.0.0/24 is temporarily banned in csf firewall already."
          fi
        fi
        if [[ $nginx_cidr == "true" ]]; then
          if ! [ -f "$nginx_cidr_blocklist" ]; then
            touch "$nginx_cidr_blocklist"
          fi
          # Add ip to nginx cidr blocklist if not found
          if ! grep -qw "$ip_cidr.0.0/24" "$nginx_cidr_blocklist"; then
            sed -i "/$ip_cidr.0.0\/24/d" "$nginx_cidr_blocklist"
            echo "$ip_cidr.0.0/24 1;" | tee >> "$nginx_cidr_blocklist"
            echo "🚫 IP CIDR $ip_cidr.0.0/24 has been added to the Nginx CIDR blocklist."
            echo
            restart_nginx=1
          else
            echo "ℹ️  IP CIDR $ip_cidr.0.0/24 has been banned in the Nginx CIDR blocklist already."
            restart_nginx=0
          fi
        fi
        if [[ $nginx_block == "true" ]]; then
          if ! [ -f "$nginx_blocklist" ]; then
            touch "$nginx_blocklist"
          fi
          # Add ip to nginx blocklist if not found
          if ! grep -qw "$ip" "$nginx_blocklist"; then
            sed -i "/$ip/d" "$nginx_blocklist"
            echo "$ip" | tee >> "$nginx_blocklist"
            echo "🚫 IP $ip has been added to the Nginx blocklist."
            echo
          else
            echo "ℹ️  IP $ip has been banned in the Nginx blocklist already."
          fi
        fi
        if [[ $abuseipdb_report == "true" ]]; then
          abuseipdb_bulk_report
          sleep 0.1
        fi
      fi
    fi
  done
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
    if [[ "$excluded_domains" =~ "$domain" ]]; then
      echo "ℹ️  Skipping $domain as it is excluded."
    else
      check_logs "$domain" "$nginx_logs_path/$domain"_access_log "$timeframe" "$threshold" "$additional_threshold" "$additional_timeframe"
    fi
  done

  if [[ "$restart_nginx" == "1" ]]; then
    >/dev/null 2>&1 nginx -t && systemctl restart nginx && echo "ℹ️  Nginx has been restarted."
  fi

  # Get current time
  currenttime=$(date +%H:%M)
  if $abuseipdb_report; then
    last_abuseipdb_report=$(find "$abuseipdb_log_folder" -name "abuseipdb_bulk_report_*.json" | sort | tail -n 1 | grep -Po ".*_\K.*\.json" | sed "s|.json||g")
    if [ -f "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv ]; then
      # Get report date from first in report
      abuseipdb_first_date=$(cat "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv \
          | cut -d ',' -f5 \
          | head -n 2 \
        | sed ':a;N;$!ba;s/\n//g')
      # Set interval for bulk report submission
      abuseipdb_interval=$(date -d "+$abuseipdb_bulk_report_interval $abuseipdb_first_date" +"%H:%M")
      # Submit abuseipdb bulk report if past interval
      if [[ "$currenttime" > "$abuseipdb_interval" ]]; then
        if [[ -f $abuseipdb_log_folder/abuseipdb_bulk_report.csv ]]; then
          # Skip if rate limit is exceeded
          if jq -r '.errors[].detail' "$(find "$abuseipdb_log_folder" -name "abuseipdb_bulk_report_*.json" | sort | tail -n 1)" >/dev/null 2>&1 \
          | grep -q "Daily rate limit of 100 requests exceeded"; then
            continue
          fi
          # Submit abuseipdb bulk report
          echo "ℹ️  Submitting AbuseIPDB bulk report."
          abuseipdb_submit_bulk_report
          if [ $? -eq 0 ]; then
            echo "Ok."
            mv "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv "$abuseipdb_log_folder"/abuseipdb_bulk_report_"${abuseipdb_report_time}".csv
          fi
        fi
      else
        echo
        echo "⌚ AbuseIPDB bulk report will be submitted after $abuseipdb_interval o'clock."
        echo
        echo "⌚ Last AbuseIPDB report was submitted at $(date -d "$last_abuseipdb_report")."
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
