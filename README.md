# Bank Database Server Log Analyzer

Two implementations of a bank database server log analyzer, developed for **ENCS3130 Linux Laboratory** at Birzeit University (Summer 2025/2026):

- **Shell version**: Bash script using `grep`, `awk`, `sed`, `sort`, `uniq`, etc.
- **Python version**: modular package using `re`, `dataclasses`, `argparse`, and `logging`.

Both turn raw server logs into structured, human-readable reports.

## Log Format

Each line in `bank_server.log` is one event:

```
[TIMESTAMP] [LOG_LEVEL] [SESSION_ID] [USER] [CLIENT_IP] [MODULE] - MESSAGE
```

Example:

```
[2026-08-15 08:07:33] [ERROR] [SESSION_1003] [unknown] [203.0.113.55] [AUTH] - Failed login attempt for user root (invalid password)
```

- **Levels:** INFO, WARNING, ERROR, CRITICAL
- **Modules:** AUTH, QUERY, TRANSACTION, BACKUP

## Features

Both versions implement the same nine services:

1. **Failed Login Report**: failed attempts by IP and user; flags IPs with 3+ failures as possible brute-force sources
2. **Query Activity Summary**: total queries by type (SELECT, UPDATE, INSERT, DELETE)
3. **Slow Query Detector**: slow-query warnings with execution time and user
4. **Transaction Report**: deposits, withdrawals, declined transactions, rollbacks, and total amounts
5. **Critical Events Report**: all CRITICAL entries with timestamps
6. **User Activity Report**: all actions of a given user in chronological order
7. **Login/Logout Session Report**: login time, logout time, and duration per session
8. **Events-per-Hour Report**: event count per hour to find peak times
9. **General Log Summary**: total lines, events per level, busiest module

## Project Structure

```
bank-server-projects/
├── bank_server_shell/
│   ├── bank_analyzer.sh
│   └── bank_server.log
└── bank_server_python/
    ├── main.py            # Entry point (menu + CLI)
    ├── parser.py          # Regex-based log parsing
    ├── model.py           # LogEntry dataclass
    ├── analyzer.py        # LogAnalyzer class (the 9 services)
    ├── test_analyzer.py   # Unit tests
    ├── bank_server.log    # Sample log file
    └── README.md
```

## Usage

### Shell

```bash
cd bank_server_shell
chmod +x bank_analyzer.sh
./bank_analyzer.sh
```

Choose a service from the interactive menu, or run all of them to generate a full report.

### Python

```bash
cd bank_server_python
python main.py
```

The program shows an interactive menu and also supports command-line arguments. Run `python main.py --help` to see all options.

Run the tests:

```bash
python -m unittest test_analyzer.py
```

## Error Handling

- Missing log file, invalid menu choice, and unknown username are handled gracefully.
- Malformed log lines are skipped (Python version logs a warning using the `logging` module).

## Requirements

- Shell: Bash (Linux, macOS, or Git Bash on Windows)
- Python: Python 3.8+ (standard library only)

## Authors

- Hasan Sattouf
- *Partner name*
