import unittest
import os
import tempfile
from WebLogParser import LogParser, classify_status, classify_ip, LogProcessor

# Sample valid log line.
VALID_LOG_LINE =  '127.0.0.3 identd user3 [01/Jan/2025:00:05:10 +0000] "GET /unusual HTTP/1.1" 200 10'

# Malformed log line.
MALFORMED_LOG_LINE = "127.0.0.3 identd user3 [01/Jan/2025:00:05:10 +0000] GET /unusual 200 10"

class TestLogParser(unittest.TestCase):
    def setUp(self):
        """Set up a LogParser instance for testing."""
        self.parser = LogParser()

    def test_parse_valid_line(self):
        """Test parsing of a valid log line."""
        result = self.parser.parse_log_line(VALID_LOG_LINE)
        expected = {
            'ip': '127.0.0.3',
            'ident': 'identd',
            'user': 'user3',
            'timestamp': '01/Jan/2025:00:05:10 +0000',
            'method': 'GET',
            'resource': '/unusual',
            'protocol': 'HTTP/1.1',
            'status': '200',
            'size': '10'
        }
        self.assertEqual(result, expected)

    def test_parse_invalid_line(self):
        """Test that a malformed log line returns None."""
        result = self.parser.parse_log_line(MALFORMED_LOG_LINE)
        self.assertIsNone(result)

class TestClassifyFunctions(unittest.TestCase):
    def test_classify_status_successful(self):
        """Test classify_status for a successful HTTP status."""
        # Resource is not admin and status is in the 200 range.
        category = classify_status("200", "/index")
        self.assertEqual(category, "successful")

    def test_classify_status_client_error(self):
        """Test classify_status for a client error."""
        category = classify_status("404", "/index")
        self.assertEqual(category, "client_error")

    def test_classify_status_server_error(self):
        """Test classify_status for a server error."""
        category = classify_status("500", "/index")
        self.assertEqual(category, "server_error")

    def test_classify_status_suspicious(self):
        """Test classify_status for suspicious resources."""
        category = classify_status("200", "/admin/dashboard")
        self.assertEqual(category, "suspicious")

    def test_classify_status_invalid(self):
        """Test classify_status for an invalid status value."""
        category = classify_status("NaN", "/index")
        self.assertEqual(category, "invalid")

    def test_classify_ip_class_A(self):
        """Test IP classification for a Class A IP."""
        category = classify_ip("10.0.0.1")
        self.assertEqual(category, "Class A")

    def test_classify_ip_class_B(self):
        """Test IP classification for a Class B IP."""
        category = classify_ip("150.0.0.1")
        self.assertEqual(category, "Class B")

    def test_classify_ip_class_C(self):
        """Test IP classification for a Class C IP."""
        category = classify_ip("192.168.1.1")
        self.assertEqual(category, "Class C")

    def test_classify_ip_invalid(self):
        """Test classification with an invalid IP address."""
        category = classify_ip("not.an.ip")
        self.assertEqual(category, "Invalid IP address")

class TestLogProcessor(unittest.TestCase):
    def setUp(self):
        """Set up a temporary file containing sample log lines."""
        self.temp_log_file = tempfile.NamedTemporaryFile(delete=False, mode='w+', encoding='utf-8')
        # Write one valid log line and one malformed line.
        self.temp_log_file.write(VALID_LOG_LINE + "\n")
        self.temp_log_file.write(MALFORMED_LOG_LINE + "\n")
        self.temp_log_file.flush()
        self.temp_log_file.close()

    def tearDown(self):
        """Remove the temporary file after tests."""
        os.unlink(self.temp_log_file.name)

    def test_parse_log_file(self):
        """Test parsing a log file containing both valid and malformed lines."""
        processor = LogProcessor(self.temp_log_file.name)
        processor.parse_log_file()
        # Expect one valid entry.
        self.assertEqual(processor.total_count, 2)
        self.assertEqual(len(processor.logs), 1)
        # Check that the DataFrame has one entry.
        self.assertFalse(processor.df.empty)
        self.assertEqual(processor.df.shape[0], 1)
        # Confirm that the valid log was parsed correctly.
        parsed = processor.logs[0]
        self.assertEqual(parsed['ip'], '127.0.0.3')
        self.assertEqual(parsed['type'], 'successful')
        self.assertIn('ip_class', parsed)

if __name__ == '__main__':
    unittest.main()
