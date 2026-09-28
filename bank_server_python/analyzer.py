import logging
import re
from datetime import datetime

from parser import parseLine


# Configure logging for internal program diagnostics
logging.basicConfig(
    filename="analyzer_internal.log",
    level=logging.WARNING,
    format="%(levelname)s: %(message)s"
)

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Analyze bank server log entries and generate reports."""

    def __init__(self, filename: str):
        """Initialize the analyzer with the given log filename."""

        self.filename = filename
        self.totalLines = 0
        self.loaded = True
        self.logs = self.parserLogs()

    # Helper function to read and parse the log file
    def parserLogs(self):
        """Read the log file and parse all valid log entries."""

        logs = []

        try:
            with open(self.filename, "r") as file:

                for lineNumber, line in enumerate(file, start=1):

                    self.totalLines += 1

                    log = parseLine(line)

                    if log is not None:
                        logs.append(log)

                    else:
                        logger.warning(
                            "Malformed log line skipped: line %d",
                            lineNumber
                        )

        except FileNotFoundError:
            logger.error(
                "Log file not found: %s",
                self.filename
            )
            print("Error: Log file not found.")
            self.loaded = False
            return []

        except PermissionError:
            logger.error(
                "Permission denied while reading: %s",
                self.filename
            )
            print("Error: Permission denied while reading the log file.")
            self.loaded = False
            return []

        except OSError as error:
            logger.error(
                "Error reading log file: %s",
                error
            )
            print("Error: Unable to read the log file.")
            self.loaded = False
            return []

        return logs

    # Report 1: Failed Login Report
    def failedLoginReport(self):
        """Generate a report of failed login attempts."""

        print("\n===== Failed Login Report =====")

        failedByIP = {}
        failedByUser = {}

        totalFailed = 0

        for log in self.logs:

            if (
                log.log_level == "ERROR"
                and log.module == "AUTH"
                and "failed login attempt" in log.message.lower()
            ):

                totalFailed += 1

                if log.client_ip not in failedByIP:
                    failedByIP[log.client_ip] = 0

                failedByIP[log.client_ip] += 1

                if log.user not in failedByUser:
                    failedByUser[log.user] = 0

                failedByUser[log.user] += 1

        print("Total failed login attempts:", totalFailed)

        if totalFailed == 0:
            print("There are no failed login attempts.")
            return

        print("\nFailed attempts by IP:")

        for IP, count in failedByIP.items():

            print(
                "IP:", IP,
                "| Failed attempts:", count
            )

            if IP == "N/A":
                print(
                    "     -> IP is missing in the log"
                )

            elif count >= 3:
                print(
                    "     -> Possible brute-force source!"
                )

        print("\nFailed attempts by User:")

        for User, count in failedByUser.items():

            print(
                "User:", User,
                "| Failed attempts:", count
            )

    # Report 2: Query Activity Summary
    def queryActivitySummary(self):
        """Generate a summary of database query activity."""

        print("\n===== Query Activity Summary =====")

        totalQueries = 0

        query = {
            "SELECT": 0,
            "UPDATE": 0,
            "INSERT": 0,
            "DELETE": 0,
            "OTHER": 0
        }

        for log in self.logs:

            if log.module == "QUERY":

                totalQueries += 1

                message = log.message.upper()

                if "SELECT" in message:
                    query["SELECT"] += 1

                elif "UPDATE" in message:
                    query["UPDATE"] += 1

                elif "INSERT" in message:
                    query["INSERT"] += 1

                elif "DELETE" in message:
                    query["DELETE"] += 1

                else:
                    query["OTHER"] += 1

        print("Total Queries:", totalQueries)

        print("\nQuery counts by type:")

        for queryType, count in query.items():
            print(
                queryType,
                ":",
                count
            )

    # Report 3: Slow Query Detector
    def slowQueryDetector(self):
        """Detect and report slow database queries."""

        print("\n===== Slow Query Detector =====")

        found = False

        for log in self.logs:

            if (
                log.module == "QUERY"
                and log.log_level == "WARNING"
                and "slow" in log.message.lower()
            ):

                executionTime = "N/A"

                match = re.search(
                    r"execution\s*time\s*[:=]?\s*"
                    r"(\d+(?:\.\d+)?)\s*(ms|seconds?|s)?",
                    log.message,
                    re.I
                )

                if match:

                    executionTime = match.group(1)

                    if match.group(2):
                        executionTime += " " + match.group(2)

                print(
                    "User:", log.user,
                    "| Execution Time:", executionTime
                )

                found = True

        if not found:
            print("No slow queries found.")

    # Report 4: Transaction Report
    def transactionReport(self):
        """Generate a report of transaction activity."""

        print("\n===== Transaction Report =====")

        deposits = 0
        withdrawals = 0
        declined = 0
        rollbacks = 0

        totalDeposited = 0.0
        totalWithdrawn = 0.0

        for log in self.logs:

            if log.module != "TRANSACTION":
                continue

            message = log.message.lower()

            if "deposit" in message:

                deposits += 1

                match = re.search(
                    r"deposit.*?(?:amount\s*)?[:=]?\s*"
                    r"(?:\$)?(\d+(?:\.\d+)?)",
                    log.message,
                    re.I
                )

                if match:
                    totalDeposited += float(match.group(1))

            elif "withdraw" in message:

                withdrawals += 1

                match = re.search(
                    r"withdraw.*?(?:amount\s*)?[:=]?\s*"
                    r"(?:\$)?(\d+(?:\.\d+)?)",
                    log.message,
                    re.I
                )

                if match:
                    totalWithdrawn += float(match.group(1))

            if "declined" in message:
                declined += 1

            if "rollback" in message:
                rollbacks += 1

        print("Deposits:", deposits)
        print("Total deposited:", round(totalDeposited, 2))

        print("Withdrawals:", withdrawals)
        print("Total withdrawn:", round(totalWithdrawn, 2))

        print("Declined transactions:", declined)
        print("Rollbacks:", rollbacks)

    # Report 5: Critical Events Report
    def criticalEventsReport(self):
        """Generate a report of critical log events."""

        print("\n===== Critical Events Report =====")

        found = False

        for log in self.logs:

            if log.log_level == "CRITICAL":

                print(
                    "Timestamp:", log.timestamp,
                    "| Level:", log.log_level,
                    "| Session:", log.session_id,
                    "| User:", log.user,
                    "| IP:", log.client_ip,
                    "| Module:", log.module,
                    "| Message:", log.message
                )

                found = True

        if not found:
            print("No critical events.")

    # Report 6: User Activity Report
    def userActivityReport(self, username: str):
        """Generate a report of all activities for a specific user."""

        print("\n===== User Activity Report =====")

        username = username.strip()

        if not username:
            print("Error: Username cannot be empty.")
            return

        activities = []

        for log in self.logs:

            if log.user == username:
                activities.append(log)

        if not activities:
            print("This user has no activities.")
            return

        activities.sort(
            key=lambda log: log.timestamp
        )

        for log in activities:

            print(
                "Time:", log.timestamp,
                "| Level:", log.log_level,
                "| Session:", log.session_id,
                "| User:", log.user,
                "| IP:", log.client_ip,
                "| Module:", log.module,
                "| Action:", log.message
            )

    # Report 7: Login/Logout Session Report
    def loginLogoutSessionReport(self):
        """Generate a report of login and logout sessions."""

        print("\n===== Login/Logout Session Report =====")

        sessions = {}

        for log in self.logs:

            sessionId = log.session_id

            if sessionId not in sessions:

                sessions[sessionId] = {
                    "login": None,
                    "logout": None
                }

            message = log.message.lower()

            if (
                "successful login" in message
                or "logged in" in message
            ):

                sessions[sessionId]["login"] = log.timestamp

            elif (
                "logout" in message
                or "logged out" in message
            ):

                sessions[sessionId]["logout"] = log.timestamp

        if not sessions:
            print("No sessions found.")
            return

        for sessionId, data in sessions.items():

            login = data["login"]
            logout = data["logout"]

            duration = "N/A"

            if login and logout:

                try:

                    loginTime = datetime.strptime(
                        login,
                        "%Y-%m-%d %H:%M:%S"
                    )

                    logoutTime = datetime.strptime(
                        logout,
                        "%Y-%m-%d %H:%M:%S"
                    )

                    duration = logoutTime - loginTime

                except ValueError:

                    duration = "N/A"

            print(
                "Session:", sessionId,
                "| Login:", login if login else "N/A",
                "| Logout:", logout if logout else "N/A",
                "| Duration:", duration
            )

    # Report 8: Events Per Hour
    def eventsPerHour(self):
        """Generate a report showing the number of events per hour."""

        print("\n===== Events Per Hour Report =====")

        hours = {}

        for log in self.logs:

            hour = log.timestamp[11:13]

            hours[hour] = hours.get(hour, 0) + 1

        for h in range(24):

            hour = f"{h:02d}"

            count = hours.get(hour, 0)

            print(
                f"{hour}:00 - {hour}:59 | {count} events"
            )

    # Report 9: General Log Summary
    def generalLogSummary(self):
        """Generate a general summary of the log file."""

        print("\n===== General Log Summary =====")

        levels = {
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "CRITICAL": 0
        }

        modules = {
            "AUTH": 0,
            "QUERY": 0,
            "TRANSACTION": 0,
            "BACKUP": 0
        }

        for log in self.logs:

            if log.log_level in levels:
                levels[log.log_level] += 1

            if log.module in modules:
                modules[log.module] += 1

        print("Total lines:", self.totalLines)

        print("\nEvents by level:")

        for level, count in levels.items():

            print(
                level,
                ":",
                count
            )

        busiestModule = max(
            modules,
            key=modules.get
        )

        print(
            "\nBusiest module:",
            busiestModule,
            "| Events:",
            modules[busiestModule]
        )