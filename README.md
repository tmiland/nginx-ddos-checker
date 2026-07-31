# Nginx DDoS Attack Detection Script Documentation
A super simple Bash script designed to monitor and detect potential
Distributed Denial of Service (DDoS) attacks on web server logs. The script analyzes
Nginx web server logs for suspicious traffic patterns and alerts administrators when
potential DDoS attacks are detected. 

It allows for customization of detection parameters and can trigger a webhook, upon detecting an attack.

## Script Components
check_logs() Function: The core function responsible for scanning Nginx logs and
identifying potential DDoS attacks. The function takes several parameters:

#### domain
The domain name for which the logs will be analyzed.
#### log_file
The path to the Nginx access log file for the given domain.
#### timeframe
The time window (in seconds) within which multiple requests from the same IP address are counted as part of a potential attack.
#### threshold
The minimum number of requests from a single IP address within the timeframe to trigger a potential DDoS alert.
#### additional_threshold
An optional additional threshold for the total number of requests from all IPs within the additional_timeframe to trigger a potential DDoS alert.
#### additional_timeframe
An optional additional timeframe (in minutes) within which the total_threshold is checked for a potential DDoS attack.


## Script Flow
1. Reads configuration parameters from an INI file (nginx_ddos_checker.ini).
2. Retrieves Nginx logs path, excluded domains, timeframes, thresholds and additional parameters from the INI file.
3. Obtains a list of virtual hosts (domains) from the Nginx logs directory.
4. Checks each domain for DDoS attacks using the check_logs() function.
5. Skips domains that are excluded from DDoS detection based on the configuration.

## Configuration
The script requires a configuration file named ddos_checker.ini located in the same directory
as the script. 
The INI file contains the following configuration parameters:

#### abuseipdb_token
Token for AbuseIPDB
#### abuseipdb_report
Turn on/off AbuseIPDB reporting
#### abuseipdb_confidense_score_limit
Set AbuseIPDB confidence score limit
#### nginx_blocklist
Path to ip blocklist (ips/cidr's will be added to this list, to be used with any firewall.)
#### nginx_logs_path
The path to the directory containing Nginx access logs.
#### excluded_domains
A list of domains (separated by commas) to be excluded from DDoS attack detection.
#### timeframe
The time window (in seconds) within which multiple requests from the same IP address are counted as part of a potential attack.
#### threshold
The minimum number of requests from a single IP address within the timeframe to trigger a potential DDoS alert.
#### additional_threshold
An additional threshold for the total number of requests from all IPs within the additional_timeframe to trigger a potential DDoS alert.
~~#### additional_timeframe
An additional time frame (in minutes) within which the additional_threshold is checked for a potential DDoS attack.~~
#### bantime
Set time in seconds for csf firewall ban