from dataclasses import dataclass

#Build the structure model of the class
@dataclass
class LogEntry:
    """One line of the bank server log."""

    timestamp: str
    log_level: str
    session_id: str
    user: str
    client_ip: str
    module: str
    message: str