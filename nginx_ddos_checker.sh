#!/usr/bin/env bash

if [[ $* =~ "debug" ]]
then
  set -o errexit
  set -o pipefail
  set -o nounset
  set -o xtrace
fi

if [[ $(command -v 'csf') ]]; then
  CSF=true
else
  echo "csf is not installed..."
fi

abuseipdb_report() {
  category="4,19,21"
  abuseipdb_category="DDoS Attack,Bad Web Bot,Web App Attack"

  ABUSEIPDB_CHECK=$(curl -sG https://api.abuseipdb.com/api/v2/check \
      --data-urlencode "ipAddress=$ip" \
      -d maxAgeInDays=90 \
      -d verbose \
      -H "Key: $abuseipdb_token" \
    -H "Accept: application/json")

  abuseipdb_confidence_score=$(echo "${ABUSEIPDB_CHECK}" | jq -r '.data.abuseConfidenceScore' )

  if [ "${abuseipdb_confidence_score}" -gt "${abuseipdb_confidense_score_limit}" ]; then
    echo "AbuseIPDB Confidence Score ${abuseipdb_confidence_score} is greater than limit ${abuseipdb_confidense_score_limit} past 90 days..."
    echo "Sending a new report to AbuseIPDB"
  else
    echo "AbuseIPDB Confidence Score ${abuseipdb_confidence_score} is lower than limit ${abuseipdb_confidense_score_limit}..."
    echo "Not sending report to AbuseIPDB."
    echo
    return
  fi
  abuseipdb_is_whitelisted=$(echo "${ABUSEIPDB_CHECK}" | jq -r '.data.isWhitelisted')

  if [ "${abuseipdb_is_whitelisted}" == "true" ]; then
    echo "IP is whitelisted on AbuseIPDB, sending report anyways..."
  fi

  echo "Reporting IP: $ip with comment: $comment"
  comment="$comment; Logs: $(echo "$ip_logs" | tr '\n' ' ')"
  # Truncate comment
  # Source: https://linuxgenie.net/truncate-string-variable-in-bash
  if [[ ${#comment} > 1024 ]]; then
    echo "Truncated comment to 1024 characters..."
    comment=${comment:0:1024}
  fi

  abuseipdb_response=$(curl -s https://api.abuseipdb.com/api/v2/report \
      --data-urlencode "ip=$ip" \
      -d categories="$category" \
      --data-urlencode "comment=$comment" \
      -H "Key: ${abuseipdb_token}" \
    -H "Accept: application/json")

  # Parse and log the response
  abuse_confidence_score=$(echo "$abuseipdb_response" | grep -oP '(?<="abuseConfidenceScore":)\d+')
  echo "AbuseIPDB Categories: $abuseipdb_category"
  if [ -n "$abuse_confidence_score" ]; then
    echo "AbuseIPDB Confidence Score: $abuse_confidence_score"
  else
    echo "AbuseIPDB Confidence Score: Not Available"
  fi
  echo "AbuseIPDB Response: $abuseipdb_response"
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

  log_time_frame=$(awk -v d1="$(date --date '-'"$timeframe"' min' '+%d/%b/%Y:%T')" '{gsub(/^[\[\t]+/, "", $4);}; $4 > d1' "$log_file")
  ips=$(echo "$log_time_frame" | grep -oP '(([0-9]{1,3}\.){3}[0-9]{1,3})' | sort -u)

  # Loop through all unique IPs
  for ip in $ips; do
    # Count the number of distributed attacks within timeframe
    time_frame_requests=$(echo "$log_time_frame" | grep -c "$ip")
    # Count total number of attacks
    # total_requests=$(cat "$log_file" | grep -c "$ip")
    # Extract relevant logs for the current IP
    ip_logs=$(cat "$log_file" | grep "$ip")
    # Get first two groups from ip
    ip_cidr=$(echo "$ip" | awk -F '.' '{print $1,$2}' | sed "s| |.|g")
    # Count ips from network cidr
    distributed_requests=$(echo "$log_time_frame" | grep -c "$ip_cidr")
    # Generate comments
    dist_comment="$ip is part of network $ip_cidr.0.0 with $distributed_requests distributed connections"
    comment="Detected $time_frame_requests connections from $ip last $timeframe minutes."
    # Check if requests within timeframe is greater than threshold
    if [[ "$time_frame_requests" -gt "$threshold" ]]; then
      echo "$comment"
      # Exit if requests per timeframe is less than distributed requests
      if ! [[ "$time_frame_requests" -lt "$distributed_requests" ]]; then
        continue
      fi
      # Check if distributed requests is greater than additional threshold
      if [[ "$distributed_requests" -gt "$additional_threshold" ]]; then
        # Generate comment for distributed attacks
        comment="$comment; $dist_comment"
        echo "$dist_comment"
        # Add temp ban to csf firewall
        if $CSF; then
          csf --tempdeny "$ip_cidr.0.0/24" "$dist_comment" >/dev/null 2>&1
          echo "🚫 Banned CIDR $ip_cidr.0.0 from IP $ip for $bantime seconds in csf firewall."
          echo
        fi
        # Send report to AbuseIPDB if higher than abuseipdb confidense score limit
        if $abuseipdb_report; then
          abuseipdb_report
        fi
        # Add ip to nginx blocklist if not found
        if ! cat "$nginx_blocklist" | grep "$ip" >/dev/null 2>&1; then
          echo "$ip" | tee >> "$nginx_blocklist"
          echo "ℹ️ IP has been added to the Nginx blocklist."
        fi
      fi
    fi
  done
}

# Main script
config_file="nginx_ddos_checker.ini"

if [[ ! -f "$config_file" ]]; then
  echo "Error: Configuration file $config_file not found."
  exit 1
fi

# Read configurations from the INI file
abuseipdb_token=$(awk -F "=" '/^abuseipdb_token/ {print $2}' "$config_file")
abuseipdb_report=$(awk -F "=" '/^abuseipdb_report/ {print $2}' "$config_file")
abuseipdb_confidense_score_limit=$(awk -F "=" '/^abuseipdb_confidense_score_limit/ {print $2}' "$config_file")
nginx_blocklist=$(awk -F "=" '/^nginx_blocklist/ {print $2}' "$config_file")
nginx_logs_path=$(awk -F "=" '/^nginx_logs_path/ {print $2}' "$config_file")
excluded_domains=$(awk -F "=" '/^excluded_domains/ {print $2}' "$config_file")
timeframe=$(awk -F "=" '/^timeframe/ {print $2}' "$config_file")
threshold=$(awk -F "=" '/^threshold/ {print $2}' "$config_file")
additional_threshold=$(awk -F "=" '/^additional_threshold/ {print $2}' "$config_file")
additional_timeframe=$(awk -F "=" '/^additional_timeframe/ {print $2}' "$config_file")
bantime=$(awk -F "=" '/^bantime/ {print $2}' "$config_file")

# Check available parked domains in Apache
virtual_hosts=($(ls "$nginx_logs_path" | grep -E '_access_log' | sed -E 's/^_access_log//g' | grep -v '.gz' | sed "s|_access_log||g"))
while true; do
  # Check logs for DDoS attacks for each domain
  for domain in "${virtual_hosts[@]}"; do
    if [[ "$excluded_domains" =~ "$domain" ]]; then
        echo "Skipping $domain as it is excluded."
    else
    check_logs "$domain" \
    "$nginx_logs_path/$domain"_access_log \
    "$timeframe" \
    "$threshold" \
    "$additional_threshold" \
    "$additional_timeframe"
    fi
  done
  echo
  echo "⌚ Last check: $(date)"
  echo
  echo "💤 Sleeping for 60 seconds..."
  echo
  sleep 60
done
