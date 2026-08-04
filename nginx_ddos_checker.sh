#!/usr/bin/env bash

if [[ $* =~ "debug" ]]
then
  set -o errexit
  set -o pipefail
  set -o nounset
  set -o xtrace
fi

abuseipdb_bulk_report() {
  category="4,19,21"
  abuseipdb_report_time=$(date +"%Y-%m-%dT%H:%M:%S%z")
  # Create directory if it doesn't exist
  if ! [ -d "$abuseipdb_log_folder" ]; then
    mkdir -p "$abuseipdb_log_folder"
  fi
  # Generate csv
  if ! [ -f "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv ]; then
    touch "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv
    # Add csv header
    if ! grep "IP,Categories,ReportDate,Comment" "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv >/dev/null 2>&1; then
      tee "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv <<'EOF' >/dev/null
IP,Categories,ReportDate,Comment
EOF
    fi
  fi
  # Add ip's to csv bulk report
  if ! grep "${ip}" "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv >/dev/null 2>&1; then
    # Add ip, catecories, report time and log to csv
    echo "${ip},\"${category}\",${abuseipdb_report_time},\"${comment}\"" >> "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv
    echo "🚫 IP ${ip} has been added to the bulk report."
  else
    echo "ℹ️  IP ${ip} with report date ${abuseipdb_report_time} already exist in the bulk report."
  fi
}

abuseipdb_submit_bulk_report() {
  curl https://api.abuseipdb.com/api/v2/bulk-report \
    -F csv=@"$abuseipdb_log_folder"/abuseipdb_bulk_report.csv \
    -H "Key: $abuseipdb_token" \
    -H "Accept: application/json" \
    > "$abuseipdb_log_folder"/abuseipdb_bulk_report_"${abuseipdb_report_time}".json
}

# Function to check logs for DDoS attacks
check_logs() {
  local domain="$1"
  local log_file="$2"
  local timeframe="$3"
  local threshold="$4"
  local attack_url="$5"
  local additional_threshold="$6"
  local additional_timeframe="$7"

  echo "✅ Checking logs for $domain"

  log_time_frame=$(awk -v d1="$(date --date '-'"$timeframe"' min' '+%d/%b/%Y:%T')" '{gsub(/^[\[\t]+/, "", $4);}; $4 > d1' "$log_file")
  ips=$(echo "$log_time_frame" | grep -oP '(([0-9]{1,3}\.){3}[0-9]{1,3})' | sort -u)

  # Loop through all unique IPs and send the data to AbuseIPDB
  for ip in $ips; do

    if [[ "$excluded_ips" =~ $ip ]]; then
      echo "ℹ️  Skipping $ip as it is excluded."
      continue
    fi

    # Count the number of distributed attacks
    time_frame_requests=$(echo "$log_time_frame" | grep -c "$ip")
    # Count total number of attacks
    # total_requests=$(cat "$log_file" | grep -c "$ip")
    # Extract relevant logs for the current IP
    # ip_logs=$(cat "$log_file" | grep "$ip")
    # Get first two groups
    ip_cidr_1=$(echo "$ip" | cut -d '.' -f1)
    ip_cidr_2=$(echo "$ip" | cut -d '.' -f2)
    ip_cidr="$ip_cidr_1.$ip_cidr_2"
    # Count ips from network
    distributed_requests_1=$(echo "$log_time_frame" | grep -c "$ip_cidr_1")
    distributed_requests_2=$(echo "$log_time_frame" | grep -c "$ip_cidr_2")
    distributed_requests=$(( distributed_requests_1 + distributed_requests_2 ))
    # Generate comments
    dist_comment="$ip is part of network $ip_cidr.0.0 with $distributed_requests distributed connections"
    comment="Detected $time_frame_requests connections from $ip last $timeframe minutes."

    if [[ "$time_frame_requests" -gt "$threshold" ]]; then
      echo "🛑 $comment"

      # Exit if requests per timeframe is less than distributed requests
      if ! [[ "$time_frame_requests" -lt "$distributed_requests" ]]; then
        continue
      fi
      if [[ "$distributed_requests" -gt "$additional_threshold" ]] \
        || [[ "$distributed_requests_1" -gt "$distributed_requests" ]]; then
        comment="$comment; $dist_comment"
        echo "ℹ️  $dist_comment"
        if [[ $csf == "true" ]]; then
          if csf -g "$ip_cidr.0.0/24" | grep "No matches found" >/dev/null 2>&1; then
            csf --tempdeny "$ip_cidr.0.0/24" "$dist_comment" >/dev/null 2>&1
            echo
            echo "🚫 Banned IP CIDR $ip_cidr.0.0 from IP $ip for $bantime seconds in csf firewall."
            echo
            # else
            #   echo "ℹ️  IP CIDR $ip_cidr.0.0/24 is temporarily banned in csf firewall already."
            #   echo
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
            >/dev/null 2>&1 nginx -t && systemctl reload nginx && echo "Nginx has been reloaded."
            # else
            #   echo "ℹ️  IP CIDR $ip_cidr.0.0/24 has been banned in the Nginx CIDR blocklist already."
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
            # else
            #   echo "ℹ️  IP $ip has been banned in the Nginx blocklist already."
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
config_file="nginx_ddos_checker.ini"

if [[ ! -f "$config_file" ]]; then
  cp -rp "example_$config_file" "$config_file" || echo "Error: Configuration file $config_file not found."; exit 1;
fi

# Read configurations from the INI file
nginx_logs_path=$(awk -F "=" '/^nginx_logs_path/ {print $2}' "$config_file")
nginx_blocklist=$(awk -F "=" '/^nginx_blocklist/ {print $2}' "$config_file")
nginx_block=$(awk -F "=" '/^nginx_block/ {print $2}' "$config_file")
nginx_cidr_blocklist=$(awk -F "=" '/^nginx_cidr_blocklist/ {print $2}' "$config_file")
nginx_cidr=$(awk -F "=" '/^nginx_cidr/ {print $2}' "$config_file")
excluded_domains=$(awk -F "=" '/^excluded_domains/ {print $2}' "$config_file")
excluded_ips=$(awk -F "=" '/^excluded_ips/ {print $2}' "$config_file")
timeframe=$(awk -F "=" '/^timeframe/ {print $2}' "$config_file")
threshold=$(awk -F "=" '/^threshold/ {print $2}' "$config_file")
additional_threshold=$(awk -F "=" '/^additional_threshold/ {print $2}' "$config_file")
additional_timeframe=$(awk -F "=" '/^additional_timeframe/ {print $2}' "$config_file")
bantime=$(awk -F "=" '/^bantime/ {print $2}' "$config_file")
abuseipdb_token=$(awk -F "=" '/^abuseipdb_token/ {print $2}' "$config_file")
abuseipdb_report=$(awk -F "=" '/^abuseipdb_report/ {print $2}' "$config_file")
abuseipdb_log_folder=$(awk -F "=" '/^abuseipdb_log_folder/ {print $2}' "$config_file")
abuseipdb_bulk_report_interval=$(awk -F "=" '/^abuseipdb_bulk_report_interval/ {print $2}' "$config_file")
csf=$(awk -F "=" '/^csf/ {print $2}' "$config_file")
# Check if csf is installed
if ! [[ $(command -v 'csf') ]]; then
  echo "csf is not installed..."
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
      echo "Skipping $domain as it is excluded."
    else
      check_logs "$domain" "$nginx_logs_path/$domain"_access_log "$timeframe" "$threshold" "$attack_url" "$additional_threshold" "$additional_timeframe"
    fi
  done
  # Get current time
  currenttime=$(date +%H:%M)
  if $abuseipdb_report; then
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
        # Submit abuseipdb bulk report
        echo "Submitting AbuseIPDB bulk report."
        abuseipdb_submit_bulk_report
        if [ $? -eq 0 ]; then
          echo "Ok."
          mv "$abuseipdb_log_folder"/abuseipdb_bulk_report.csv "$abuseipdb_log_folder"/abuseipdb_bulk_report_"$currenttime".csv
        fi
      fi
    else
      echo "AbuseIPDB bulk report will be submitted at $abuseipdb_interval o'clock."
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