import re

from model import LogEntry


# Regex pattern for the bank server log format
Log_Regex = re.compile(
    r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+"
    r"\[(?P<log_level>INFO|WARNING|ERROR|CRITICAL)\]\s+"
    r"\[(?P<session_id>SESSION_\d{4})\]\s+"
    r"\[(?P<user>[a-zA-Z0-9_]+)\]\s+"
    r"(?:\[(?P<client_ip>"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
    r")\]\s+)?"
    r"\[(?P<module>AUTH|QUERY|TRANSACTION|BACKUP)\]\s+-\s+"
    r"(?P<message>.+)$"
)


# Match a line and create a LogEntry object
def parseLine(line: str):
    """Return a LogEntry for a valid line, or None if the line is malformed."""
    line = line.strip()

    match = Log_Regex.match(line)

    if not match:
        return None

    clientIp = match.group("client_ip")

    # Some lines have no IP: keep them and write N/A instead
    # (to treat them as malformed, replace the next 2 lines with: return None)
    if clientIp is None:
        clientIp = "N/A"

    return LogEntry(
        timestamp=match.group("timestamp"),
        log_level=match.group("log_level"),
        session_id=match.group("session_id"),
        user=match.group("user"),
        client_ip=clientIp,
        module=match.group("module"),
        message=match.group("message")
    )