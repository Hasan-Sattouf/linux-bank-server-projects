import io
import unittest
from contextlib import redirect_stdout

from analyzer import LogAnalyzer
from parser import parseLine


# Run a report and return the text that it printed
def getOutput(method, *args):
    """Run a report method and return the text it printed."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        method(*args)
    return buffer.getvalue()


class TestParser(unittest.TestCase):
    """Tests for parseLine."""

    def test_valid_line(self):
        """A valid line is parsed correctly."""
        line = ("[2026-08-15 10:00:01] [ERROR] [SESSION_1003] [unknown] "
                "[203.0.113.55] [AUTH] - Failed login attempt for user root")
        log = parseLine(line)
        self.assertEqual(log.log_level, "ERROR")
        self.assertEqual(log.module, "AUTH")
        self.assertEqual(log.client_ip, "203.0.113.55")

    def test_line_without_ip(self):
        """A line without an IP gets N/A."""
        line = ("[2026-08-15 10:03:01] [ERROR] [SESSION_1006] [unknown] "
                "[AUTH] - Failed login attempt for user admin")
        self.assertEqual(parseLine(line).client_ip, "N/A")

    def test_malformed_lines(self):
        """Malformed lines return None."""
        self.assertIsNone(parseLine("THIS LINE IS COMPLETELY INVALID"))
        self.assertIsNone(parseLine("[2026-08-15 20:02:00] [INFO] [SESSION_1234] [admin] [NOT_AN_IP] [AUTH] - x"))
        self.assertIsNone(parseLine("[2026-08-15 20:04:00] [BAD_LEVEL] [SESSION_1234] [admin] [1.1.1.1] [AUTH] - x"))
        self.assertIsNone(parseLine("[2026-08-15 20:03:00] [INFO] [SESSION_1234] [admin] [1.1.1.1] [UNKNOWN_MODULE] - x"))
        self.assertIsNone(parseLine("[2026/08/15 20:07:00] [INFO] [SESSION_1234] [admin] [1.1.1.1] [AUTH] - x"))
        self.assertIsNone(parseLine("[2026-08-15 20:06:00] [INFO] [SESSION_1234] [admin] [1.1.1.1] [AUTH] - "))


class TestReports(unittest.TestCase):
    """Tests for the nine reports (using bank_server.log)."""

    def setUp(self):
        """Load the sample log before each test."""
        self.analyzer = LogAnalyzer("bank_server.log")

    def test_file_was_loaded(self):
        """The file is read and the malformed lines are skipped."""
        self.assertTrue(self.analyzer.loaded)
        self.assertEqual(self.analyzer.totalLines, 74)
        self.assertEqual(len(self.analyzer.logs), 59)

    def test_failed_logins(self):
        """Failed login counts and brute-force flag."""
        out = getOutput(self.analyzer.failedLoginReport)
        self.assertIn("Total failed login attempts: 9", out)
        self.assertIn("IP: 203.0.113.55 | Failed attempts: 3\n     -> Possible brute-force source!", out)
        self.assertIn("IP: N/A | Failed attempts: 3\n     -> IP is missing in the log", out)

    def test_query_summary(self):
        """Query counts by type."""
        out = getOutput(self.analyzer.queryActivitySummary)
        self.assertIn("Total Queries: 18", out)
        self.assertIn("SELECT : 7", out)
        self.assertIn("OTHER : 4", out)

    def test_slow_queries(self):
        """Slow queries are listed with their time."""
        out = getOutput(self.analyzer.slowQueryDetector)
        self.assertIn("1250 ms", out)
        self.assertIn("3 s", out)

    def test_transactions(self):
        """Deposits, withdrawals, declined and rollbacks."""
        out = getOutput(self.analyzer.transactionReport)
        self.assertIn("Deposits: 5", out)
        self.assertIn("Total deposited: 5850.24", out)
        self.assertIn("Withdrawals: 3", out)
        self.assertIn("Declined transactions: 2", out)
        self.assertIn("Rollbacks: 2", out)

    def test_critical_events(self):
        """All CRITICAL entries are listed."""
        out = getOutput(self.analyzer.criticalEventsReport)
        self.assertEqual(out.count("Level: CRITICAL"), 3)

    def test_user_activity(self):
        """Existing user and unknown user."""
        out = getOutput(self.analyzer.userActivityReport, "admin")
        self.assertIn("Successful login for user admin", out)
        out = getOutput(self.analyzer.userActivityReport, "nobody")
        self.assertIn("This user has no activities.", out)

    def test_sessions(self):
        """Login, logout and duration of a session."""
        out = getOutput(self.analyzer.loginLogoutSessionReport)
        self.assertIn("SESSION_1001 | Login: 2026-08-15 08:00:01 | Logout: 2026-08-15 08:08:00 | Duration: 0:07:59", out)

    def test_events_per_hour(self):
        """Events count for the busiest hour."""
        out = getOutput(self.analyzer.eventsPerHour)
        self.assertIn("08:00 - 08:59 | 9 events", out)


class TestMissingFile(unittest.TestCase):
    """Test for a log file that does not exist."""

    def test_missing_file(self):
        """Missing file gives no logs and loaded = False."""
        analyzer = LogAnalyzer("no_such_file.log")
        self.assertFalse(analyzer.loaded)
        self.assertEqual(analyzer.logs, [])


if __name__ == "__main__":
    unittest.main()
