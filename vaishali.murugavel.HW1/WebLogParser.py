import re
import sys
import pandas as pd
import logging

# Logging configuration
logging.basicConfig(level=logging.INFO)

class LogParser:
    """Parses individual log lines based on a predefined regular expression pattern.

    The pattern matches common web server log formats and extracts the following fields:
    ip, ident, user, timestamp, method, resource, protocol, status, and size.
    """

    pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) (?P<ident>[\w-]+) (?P<user>[\w-]+) '
        r'\[(?P<timestamp>\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] '
        r'"(?P<method>[A-Z]+) (?P<resource>/[\w/_.\-?=]*) (?P<protocol>[A-Z]+/\d(\.\d)*)" '
        r'(?P<status>\d{3}) (?P<size>\d+|-)'
    )

    def parse_log_line(self, line):
        """Parses a single line from the log file.

        Args:
            line (str): A single line from a log file.

        Returns:
            dict or None: A dictionary of parsed fields if matched; otherwise, None.
        """
        match = self.pattern.search(line)
        if not match:
            return None
        return match.groupdict()

def classify_status(status, resource):
    """Classifies a log entry based on HTTP status code and resource path.

    Args:
        status (str or int): The HTTP status code.
        resource (str): The requested resource path.

    Returns:
        str: The category of the log (e.g., 'successful', 'client_error', etc.).
    """
    try:
        status = int(status)
    except ValueError:
        return 'invalid'

    if resource.startswith('/admin') or resource.startswith('/wp-admin'):
        return 'suspicious'
    if 400 <= status <= 499:
        return 'client_error'
    if 500 <= status <= 599:
        return 'server_error'
    if 200 <= status <= 299:
        return 'successful'
    return 'other'


def classify_ip(ip):
    """Classifies an IP address into its corresponding class.

    Args:
        ip (str): The IP address.

    Returns:
        str: The IP class (e.g., 'Class A', 'Class B', etc.).
    """
    try:
        first_octet = int(ip.split('.')[0])
        if 1 <= first_octet <= 126:
            return 'Class A'
        elif 128 <= first_octet <= 191:
            return 'Class B'
        elif 192 <= first_octet <= 223:
            return 'Class C'
        else:
            return 'Unknown Class'
    except Exception:
        return 'Invalid IP address'


class LogProcessor:
    """Processes a log file line by line and generates structured data and statistics."""

    def __init__(self, file_path):
        """Initializes the LogProcessor with the path to the log file.

        Args:
            file_path (str): The path to the log file.
        """
        self.file_path = file_path
        self.parser = LogParser()
        self.logs = []
        self.malformed_count = 0
        self.total_count = 0
        self.df = pd.DataFrame()

    def parse_log_file(self):
        """Parses the log file and stores the results in a DataFrame."""
        try:
            with open(self.file_path) as f:
                for line in f:
                    parsed = self.parser.parse_log_line(line)
                    self.total_count += 1
                    print('Line: ',line, 'parsed: ', parsed)
                    if parsed:
                        parsed['type'] = classify_status(parsed['status'], parsed['resource'])
                        parsed['ip_class'] = classify_ip(parsed['ip'])
                        self.logs.append(parsed)
                    else:
                        self.malformed_count += 1
            self.df = pd.DataFrame(self.logs)
        except FileNotFoundError:
            logging.error(f"File '{self.file_path}' not found.")

    def export_to_csv(self, output_path):
        """Exports the parsed log data to a CSV file.

        Args:
            output_path (str): The path where the CSV file will be saved.
        """
        if not self.df.empty:
            self.df.to_csv(output_path, index=False)
        else:
            logging.warning("No data to export.")

    def stats(self):
        """Displays statistics about the parsed logs."""
        if self.df.empty:
            logging.warning("No logs to analyze.")
            return

        print("------- Log Statistics -------")
        print(f"Total logs processed: {self.total_count}")
        print(f"Malformed log lines: {self.malformed_count}")
        print(f"Client/Server errors: {(self.df['type'].isin(['client_error', 'server_error'])).sum()}")
        print(f"Successful requests: {(self.df['type'] == 'successful').sum()}")
        print(f"Suspicious requests: {(self.df['type'] == 'suspicious').sum()}")
        print("----------------------------------")


class LogAnalytics:
    """Performs analytical operations on parsed log data."""

    def __init__(self, processor: LogProcessor):
        """Initializes the LogAnalytics with a processed LogProcessor object.

        Args:
            processor (LogProcessor): The log processor containing parsed log data.
        """
        self.processor = processor
        self.df = processor.df.copy()

    def analyze(self):
        """Performs and prints basic analytics on the log data."""
        if self.df.empty:
            logging.warning("No data for analytics.")
            return

        self.df['timestamp_trimmed'] = self.df['timestamp'].str.slice(0, 17)
        try:
            self.df['timestamp_trimmed'] = pd.to_datetime(self.df['timestamp_trimmed'], format='%d/%b/%Y:%H:%M')
        except Exception as e:
            logging.warning(f"Timestamp parsing error: {e}")

        print("------------- Log Analytics -------------")
        print(f"- Total logs processed: {self.processor.total_count}")
        print(f"- Malformed log lines: {self.processor.malformed_count}")
        print(f"- Distinct IP addresses: {self.df['ip'].nunique()}")
        print(f"- Top 3 IP addresses:\n{self.df['ip'].value_counts().head(3).to_string()}")
        vc = self.df['resource'].value_counts()
        max_count = vc.iloc[0]
        top_resources = vc[vc == max_count]
        print(f"- Most requested resource:")
        print('\n'.join(f"{resource} ({count} requests)" for resource, count in top_resources.items()))
        print(f"- HTTP method distribution:\n{self.df['method'].value_counts().to_string()}")
        if not self.df['timestamp_trimmed'].isnull().all():
            busiest = self.df['timestamp_trimmed'].value_counts().idxmax()
            count = self.df['timestamp_trimmed'].value_counts().max()
            print(f"- Busiest time: {busiest} with {count} requests")
        print("-----------------------------------------")


if __name__ == '__main__':
    log_file = 'access.log'
    csv_file = 'access.csv'
    if len(sys.argv) >= 2:
        log_file = sys.argv[1]
        if len(sys.argv) == 3:
            csv_file = sys.argv[2]

    processor = LogProcessor(log_file)
    processor.parse_log_file()
    processor.stats()
    processor.export_to_csv(csv_file)

    analytics = LogAnalytics(processor)
    analytics.analyze()
    par = LogParser()