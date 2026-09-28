# Bank Database Server Log Analyzer

Python project for ENCS3130 (Linux Laboratory) that reads a bank database server
log file and prints reports about it.

## Requirements
- Python 3.10 or newer (the project uses `match`)
- No external libraries (so there is no requirements.txt)

## Files
- `model.py`         : the `LogEntry` dataclass (one log line)
- `parser.py`        : the regex and `parseLine()` that converts a line to a `LogEntry`
- `analyzer.py`      : the `LogAnalyzer` class, one method for each report
- `main.py`          : interactive menu and command line (argparse)
- `test_analyzer.py` : unit tests
- `bank_server.log`  : sample log file used for testing

## How to run
Interactive menu:

    python main.py bank_server.log

Run one report from the command line:

    python main.py bank_server.log --report 1
    python main.py bank_server.log --report 6 --user admin

Run all reports (the user report is added only if `--user` is given):

    python main.py bank_server.log --report 10 --user admin

Run the tests:

    python -m unittest test_analyzer -v

## Reports
1. Failed Login Report (3 or more failures from one IP = possible brute-force)
2. Query Activity Summary
3. Slow Query Detector
4. Transaction Report
5. Critical Events Report
6. User Activity Report (needs a username)
7. Login/Logout Session Report
8. Events Per Hour Report
9. General Log Summary
10. Run all reports

## Notes
- Malformed lines are skipped and written as warnings to `analyzer_internal.log`
  (this file is created when the program runs).
- Some lines in the sample log have no IP address. They are kept and the IP is
  shown as `N/A` (an `N/A` IP is never flagged as a brute-force source).
- If the log file is missing or cannot be read, the program prints an error and stops.
