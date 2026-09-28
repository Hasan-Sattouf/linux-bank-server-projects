import argparse
import sys

from analyzer import LogAnalyzer


def showMenu():
    """Print the menu."""
    print("\n===== Bank Server Log Analyzer =====")
    print("1. Failed Login Report")
    print("2. Query Activity Summary")
    print("3. Slow Query Detector")
    print("4. Transaction Report")
    print("5. Critical Events Report")
    print("6. User Activity Report")
    print("7. Login/Logout Session Report")
    print("8. Events Per Hour Report")
    print("9. General Log Summary")
    print("10. Run All Reports")
    print("0. Exit")


def runReport(analyzer: LogAnalyzer, choice: str):
    """Run the report that has the given number."""

    match choice:

        case "1":
            analyzer.failedLoginReport()

        case "2":
            analyzer.queryActivitySummary()

        case "3":
            analyzer.slowQueryDetector()

        case "4":
            analyzer.transactionReport()

        case "5":
            analyzer.criticalEventsReport()

        case "6":
            username = input("Enter username: ")
            analyzer.userActivityReport(username)

        case "7":
            analyzer.loginLogoutSessionReport()

        case "8":
            analyzer.eventsPerHour()

        case "9":
            analyzer.generalLogSummary()

        case "10":
            analyzer.failedLoginReport()
            analyzer.queryActivitySummary()
            analyzer.slowQueryDetector()
            analyzer.transactionReport()
            analyzer.criticalEventsReport()

            username = input(
                "\nEnter username for User Activity Report: "
            )

            analyzer.userActivityReport(username)

            analyzer.loginLogoutSessionReport()
            analyzer.eventsPerHour()
            analyzer.generalLogSummary()

        case _:
            print("Invalid choice! Please try again.")


def interactiveMode(analyzer: LogAnalyzer):
    """Show the menu until the user chooses 0."""

    while True:

        showMenu()

        try:
            choice = input("Enter your choice: ")

        except (EOFError, KeyboardInterrupt):
            print("\nExiting program.")
            break

        if choice == "0":
            print("Exiting program.")
            break

        runReport(analyzer, choice)


def main():
    """Read the arguments and run the program."""

    #argparse handles missing or invalid command-line arguments automatically
    #no need to add try and except more
    
    parser = argparse.ArgumentParser(
        description="Bank Database Server Log Analyzer"
    )

    parser.add_argument(
        "filename",
        help="Path to the bank server log file"
    )

    parser.add_argument(
        "--report",
        help="Report number to run"
    )

    parser.add_argument(
        "--user",
        help="Username for User Activity Report"
    )

    args = parser.parse_args()

    analyzer = LogAnalyzer(args.filename)

    # Stop if the log file could not be read
    if not analyzer.loaded:
        sys.exit(1)

    if args.report:

        match args.report:

            case "1":
                analyzer.failedLoginReport()

            case "2":
                analyzer.queryActivitySummary()

            case "3":
                analyzer.slowQueryDetector()

            case "4":
                analyzer.transactionReport()

            case "5":
                analyzer.criticalEventsReport()

            case "6":

                if not args.user:
                    print(
                        "Error: --user is required for User Activity Report."
                    )
                    return

                analyzer.userActivityReport(args.user)

            case "7":
                analyzer.loginLogoutSessionReport()

            case "8":
                analyzer.eventsPerHour()

            case "9":
                analyzer.generalLogSummary()

            case "10":

                analyzer.failedLoginReport()
                analyzer.queryActivitySummary()
                analyzer.slowQueryDetector()
                analyzer.transactionReport()
                analyzer.criticalEventsReport()

                if args.user:
                    analyzer.userActivityReport(args.user)
                else:
                    print("User Activity Report skipped.")

                analyzer.loginLogoutSessionReport()
                analyzer.eventsPerHour()
                analyzer.generalLogSummary()

            case _:
                print("Invalid report number.")

    else:
        interactiveMode(analyzer)


if __name__ == "__main__":
    main()