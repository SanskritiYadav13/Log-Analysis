import re
import csv
from collections import Counter, defaultdict

# Constants
LOG_FILE = "sample.log"
CSV_OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Function to parse log entries
def parse_logs(log_file):
    log_pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<endpoint>[^ ]+) HTTP/\d+\.\d+" (?P<status>\d+) (?P<size>\d+)'
    )
    parsed_logs = []
    with open(log_file, "r") as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                parsed_logs.append(match.groupdict())
    return parsed_logs

# Function to count requests per IP
def count_requests_by_ip(parsed_logs):
    ip_counter = Counter(log['ip'] for log in parsed_logs)
    return ip_counter

# Function to find the most accessed endpoint
def most_accessed_endpoint(parsed_logs):
    endpoint_counter = Counter(log['endpoint'] for log in parsed_logs)
    most_common_endpoint = endpoint_counter.most_common(1)[0]
    return most_common_endpoint

# Function to detect suspicious activity
def detect_suspicious_activity(parsed_logs, threshold):
    failed_logins = defaultdict(int)
    for log in parsed_logs:
        if log['status'] == "401":  # HTTP 401 Unauthorized
            failed_logins[log['ip']] += 1
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips

# Function to save results to CSV
def save_results_to_csv(ip_counts, most_common_endpoint, suspicious_activity):
    with open(CSV_OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write IP request counts
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_common_endpoint[0], most_common_endpoint[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Main function
def main():
    # Parse the log file
    parsed_logs = parse_logs(LOG_FILE)

    # Count requests per IP
    ip_counts = count_requests_by_ip(parsed_logs)

    # Identify the most accessed endpoint
    most_common_endpoint = most_accessed_endpoint(parsed_logs)

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(parsed_logs, FAILED_LOGIN_THRESHOLD)

    # Display results in terminal
    print("Requests per IP:")
    for ip, count in ip_counts.most_common():
        print(f"{ip:20} {count}")
    print("\nMost Accessed Endpoint:")
    print(f"{most_common_endpoint[0]} - {most_common_endpoint[1]} times")
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")

    # Save results to CSV
    save_results_to_csv(ip_counts, most_common_endpoint, suspicious_activity)
    print(f"\nResults saved to {CSV_OUTPUT_FILE}")

# Run the script
if __name__ == "__main__":
    main()
