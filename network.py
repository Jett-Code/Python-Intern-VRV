import re
from collections import Counter
import csv
import os
import sys
import logging

logging.basicConfig(level=logging.INFO)

class EfficientLogAnalyzer:
    def __init__(self, log_file_path: str, risk_threshold: int = 10, chunk_size: int = 1024 * 1024):

        # Initialize log analyzer with optimized settings
        self.log_file_path = log_file_path
        self.risk_threshold = risk_threshold
        self.chunk_size = chunk_size

        # Precompile regex patterns for better performance
        self.ip_pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+)')
        self.endpoint_pattern = re.compile(r'"[A-Z]+ (/[/\w/]+)')

    def parse_log_chunk(self, chunk: str):
    
        # Process a chunk of log data to extract meaningful insights.
        ip_counts = Counter()
        endpoint_counts = Counter()
        failed_logins = Counter()

        for line in chunk.splitlines():
            # Extract IP address
            ip_match = self.ip_pattern.search(line)
            network_source = ip_match.group(1) if ip_match else None

            if network_source:
                ip_counts[network_source] += 1

            # Extract accessed endpoint
            endpoint_match = self.endpoint_pattern.search(line)
            if endpoint_match:
                accessed_resource = endpoint_match.group(1)
                endpoint_counts[accessed_resource] += 1

            # Check for failed login attempts
            if "POST /login" in line and "401" in line:
                if network_source:
                    failed_logins[network_source] += 1

        return ip_counts, endpoint_counts, failed_logins

    def analyze_log_file(self):
        
        # Analyze the log file in chunks to handle large files efficiently.
        total_ip_counts = Counter()
        total_endpoint_counts = Counter()
        total_auth_failures = Counter()

        try:
            with open(self.log_file_path, 'r') as file:
                buffer = ""
                while True:
                    # Read chunks from the file
                    chunk = file.read(self.chunk_size)
                    if not chunk:
                        break
                    buffer += chunk
                    *lines, buffer = buffer.splitlines()
                    for line in lines:
                        ip_counts, endpoint_counts, failed_logins = self.parse_log_chunk(line)
                        total_ip_counts.update(ip_counts)
                        total_endpoint_counts.update(endpoint_counts)
                        total_auth_failures.update(failed_logins)

                # Process leftover buffer
                if buffer:
                    ip_counts, endpoint_counts, failed_logins = self.parse_log_chunk(buffer)
                    total_ip_counts.update(ip_counts)
                    total_endpoint_counts.update(endpoint_counts)
                    total_auth_failures.update(failed_logins)

        except IOError as e:
            logging.error(f"Error reading file: {e}")
            sys.exit(1)

        return total_ip_counts, total_endpoint_counts, total_auth_failures

    def export_analysis_csv(self, ip_counts: Counter, 
                             endpoint_counts: Counter, 
                             failed_logins: Counter):
        
        # Export analysis results to a CSV file.
        csv_filename = 'network_log.csv'
        try:
            with open(csv_filename, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)

                # Write network traffic data
                csv_writer.writerow(["Network Traffic Analysis"])
                csv_writer.writerow(["Network Source", "Request Count"])
                csv_writer.writerows(ip_counts.most_common())

                # Write accessed resources data
                csv_writer.writerow([])
                csv_writer.writerow(["Resource Access Analysis"])
                csv_writer.writerow(["Resource", "Access Count"])
                csv_writer.writerows(endpoint_counts.most_common())

                # Write authentication failures data
                csv_writer.writerow([])
                csv_writer.writerow(["Security Risks"])
                csv_writer.writerow(["Network Source", "Failed Attempts"])
                csv_writer.writerows([
                    (source, attempts) 
                    for source, attempts in failed_logins.items() 
                    if attempts > self.risk_threshold
                ])

            logging.info(f"Detailed analysis exported to {csv_filename}")

        except IOError as e:
            logging.error(f"Error exporting CSV: {e}")

    def generate_report(self, ip_counts: Counter, endpoint_counts: Counter, failed_logins: Counter):
        
        # Print analysis results to the CLI.

        print("\n--- Network Traffic Analysis ---")
        for source, count in ip_counts.most_common(10):
            print(f"Source: {source:<15} Requests: {count:>6}")

        print("\n--- Top Accessed Resources ---")
        top_resources = endpoint_counts.most_common(5)
        for resource, count in top_resources:
            print(f"Resource: {resource:<15} Accesses: {count:>6}")

        print("\n--- Potential Security Risks ---")
        risks = [
            (source, attempts) 
            for source, attempts in failed_logins.items() 
            if attempts > self.risk_threshold
        ]

        if risks:
            for source, attempts in risks:
                print(f"Risky Source: {source:<15} Failed Attempts: {attempts:>6}")
        else:
            print("No significant security risks detected.")

def main(log_file_path: str = 'sample.log'):
    
    # Main function to run the log analysis.
    if not os.path.exists(log_file_path):
        logging.error(f"Error: Log file '{log_file_path}' not found.")
        sys.exit(1)

    # Initialize the log analyzer
    log_analyzer = EfficientLogAnalyzer(
        log_file_path, 
        risk_threshold=10,  # Flag sources with more than 10 failed attempts
        chunk_size=1024 * 1024  # Adjust chunk size based on memory limits
    )

    # Analyze log file
    ip_counts, endpoint_counts, failed_logins = log_analyzer.analyze_log_file()

    # Print results to CLI
    log_analyzer.generate_report(ip_counts, endpoint_counts, failed_logins)

    # Export results to CSV
    log_analyzer.export_analysis_csv(
        ip_counts, endpoint_counts, failed_logins
    )

if __name__ == "__main__":
    main()
