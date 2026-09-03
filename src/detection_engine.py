import csv
import json
import os
import sys
from datetime import datetime


# ============================================================
# JSON LOADER
# ============================================================

def load_json(file_path):
    """
    Load JSON data from a file.
    """
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


# ============================================================
# VALUE NORMALIZATION
# ============================================================

def normalize(value):
    """
    Convert values to lowercase strings for
    case-insensitive comparison.
    """

    if value is None:
        return ""

    return str(value).lower()


# ============================================================
# CONDITION CHECKER
# ============================================================

def check_condition(event, field, operator, expected):
    """
    Check one rule condition against an event.
    """

    actual = event.get(field)

    # Example:
    # Image endswith \cmd.exe
    if operator == "endswith":
        return normalize(actual).endswith(
            normalize(expected)
        )

    # Example:
    # CommandLine contains .hta
    if operator == "contains":
        return normalize(expected) in normalize(actual)

    # Example:
    # EventID equals 4625
    if operator == "equals":
        return normalize(actual) == normalize(expected)

    # Example:
    # ScriptBlockText must contain multiple values.
    if operator == "contains_all":

        actual_normalized = normalize(actual)

        return all(
            normalize(item) in actual_normalized
            for item in expected
        )

    return False


# ============================================================
# RULE MATCHER
# ============================================================

def rule_matches(event, rule):
    """
    Return True only when ALL conditions
    in a rule match.
    """

    conditions = rule.get("conditions", [])

    for field, operator, expected in conditions:

        if not check_condition(
            event,
            field,
            operator,
            expected
        ):
            return False

    return True


# ============================================================
# DETECTION ENGINE
# ============================================================

def run_detection(events, rules):
    """
    Run all detection rules against all events.
    """

    alerts = []

    for event in events:

        for rule in rules:

            if rule_matches(event, rule):

                alert = {
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get(
                        "name",
                        "Unknown Rule"
                    ),
                    "severity": rule.get(
                        "severity",
                        "unknown"
                    ),
                    "mitre_attack": rule.get(
                        "mitre_attack",
                        "N/A"
                    ),
                    "event": event
                }

                alerts.append(alert)

    return alerts


# ============================================================
# TERMINAL ALERT OUTPUT
# ============================================================

def print_alert(alert):
    """
    Display one alert in the terminal.
    """

    event = alert["event"]

    print("=" * 70)

    print(
        f"ALERT [Rule {alert.get('rule_id')}]: "
        f"{alert.get('rule_name')}"
    )

    print(
        "Severity:",
        str(alert.get("severity", "unknown")).upper()
    )

    print(
        "MITRE ATT&CK:",
        alert.get("mitre_attack", "N/A")
    )

    print("EventID:", event.get("EventID"))
    print("Computer:", event.get("Computer"))
    print("Time:", event.get("TimeCreated"))

    important_fields = [
        "User",
        "TargetUserName",
        "TargetDomainName",
        "Image",
        "ImagePath",
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "Protocol",
        "SourceIp",
        "SourcePort",
        "DestinationIp",
        "DestinationPort",
        "TaskName",
        "TaskContent",
        "TargetObject",
        "Details",
        "ScriptBlockText"
    ]

    for field in important_fields:

        value = event.get(field)

        if value is not None and value != "":
            print(f"{field}: {value}")


# ============================================================
# TIMESTAMP
# ============================================================

def create_timestamp():
    """
    Create timestamp for unique report filenames.
    """

    return datetime.now().astimezone().strftime(
        "%Y%m%d_%H%M%S"
    )


# ============================================================
# JSON REPORT EXPORT
# ============================================================

def export_json_report(
    alerts,
    events_file,
    rules_file,
    timestamp
):
    """
    Export alerts to a timestamped JSON report.
    """

    os.makedirs(
        "reports",
        exist_ok=True
    )

    output_file = (
        f"reports/alerts_{timestamp}.json"
    )

    report = {
        "report": {
            "engine": "Cyberion ThreatShield",
            "report_version": "2.0",
            "generated_at": (
                datetime.now()
                .astimezone()
                .isoformat()
            ),
            "source_file": events_file,
            "rules_file": rules_file,
            "total_alerts": len(alerts)
        },
        "alerts": alerts
    }

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_file


# ============================================================
# CSV REPORT EXPORT
# ============================================================

def export_csv_report(
    alerts,
    timestamp
):
    """
    Export alert summary to a timestamped CSV file.
    """

    os.makedirs(
        "reports",
        exist_ok=True
    )

    output_file = (
        f"reports/alerts_{timestamp}.csv"
    )

    fieldnames = [
        "RuleID",
        "RuleName",
        "Severity",
        "MITRE_ATTACK",
        "EventID",
        "Computer",
        "TimeCreated",
        "User",
        "TargetUserName",
        "TargetDomainName",
        "Image",
        "ImagePath",
        "CommandLine",
        "ParentImage",
        "Protocol",
        "SourceIp",
        "SourcePort",
        "DestinationIp",
        "DestinationPort",
        "TargetObject",
        "Details"
    ]

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for alert in alerts:

            event = alert["event"]

            row = {
                "RuleID":
                    alert.get("rule_id"),

                "RuleName":
                    alert.get("rule_name"),

                "Severity":
                    alert.get(
                        "severity",
                        "unknown"
                    ),

                "MITRE_ATTACK":
                    alert.get(
                        "mitre_attack",
                        "N/A"
                    ),

                "EventID":
                    event.get("EventID"),

                "Computer":
                    event.get("Computer"),

                "TimeCreated":
                    event.get("TimeCreated"),

                "User":
                    event.get("User"),

                "TargetUserName":
                    event.get(
                        "TargetUserName"
                    ),

                "TargetDomainName":
                    event.get(
                        "TargetDomainName"
                    ),

                "Image":
                    event.get("Image"),

                "ImagePath":
                    event.get("ImagePath"),

                "CommandLine":
                    event.get("CommandLine"),

                "ParentImage":
                    event.get("ParentImage"),

                "Protocol":
                    event.get("Protocol"),

                "SourceIp":
                    event.get("SourceIp"),

                "SourcePort":
                    event.get("SourcePort"),

                "DestinationIp":
                    event.get(
                        "DestinationIp"
                    ),

                "DestinationPort":
                    event.get(
                        "DestinationPort"
                    ),

                "TargetObject":
                    event.get("TargetObject"),

                "Details":
                    event.get("Details")
            }

            writer.writerow(row)

    return output_file


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) != 3:

        print("Usage:")

        print(
            "python src/detection_engine.py "
            "<events.json> "
            "<rules.json>"
        )

        sys.exit(1)

    events_file = sys.argv[1]
    rules_file = sys.argv[2]

    # --------------------------------------------------------
    # Load files
    # --------------------------------------------------------

    try:

        events = load_json(
            events_file
        )

        rules = load_json(
            rules_file
        )

    except FileNotFoundError as error:

        print("File not found:")
        print(error)

        sys.exit(1)

    except json.JSONDecodeError as error:

        print("Invalid JSON:")
        print(error)

        sys.exit(1)

    # --------------------------------------------------------
    # Run detection
    # --------------------------------------------------------

    alerts = run_detection(
        events,
        rules
    )

    # --------------------------------------------------------
    # Terminal summary
    # --------------------------------------------------------

    print()

    print("Cyberion ThreatShield")

    print(
        "Automated Detection Engine v2"
    )

    print("-" * 40)

    print(
        f"Total Events: {len(events)}"
    )

    print(
        f"Total Rules: {len(rules)}"
    )

    print(
        f"Total Alerts: {len(alerts)}"
    )

    # --------------------------------------------------------
    # Print alerts
    # --------------------------------------------------------

    if len(alerts) == 0:

        print()

        print(
            "No detection matches found."
        )

    else:

        for alert in alerts:
            print_alert(alert)

    # --------------------------------------------------------
    # Generate one timestamp
    # --------------------------------------------------------

    timestamp = create_timestamp()

    # --------------------------------------------------------
    # Export JSON
    # --------------------------------------------------------

    json_report = export_json_report(
        alerts,
        events_file,
        rules_file,
        timestamp
    )

    # --------------------------------------------------------
    # Export CSV
    # --------------------------------------------------------

    csv_report = export_csv_report(
        alerts,
        timestamp
    )

    # --------------------------------------------------------
    # Report locations
    # --------------------------------------------------------

    print()

    print("-" * 40)

    print(
        "JSON report saved to:",
        json_report
    )

    print(
        "CSV report saved to:",
        csv_report
    )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":
    main()