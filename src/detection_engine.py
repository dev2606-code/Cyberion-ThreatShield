import json
import sys
import os
from datetime import datetime


def load_json(file_path):
    """
    Load JSON data from a file.
    """
    with open(file_path, "r") as f:
        return json.load(f)


def normalize(value):
    """
    Convert values to lowercase strings for
    case-insensitive comparison.
    """
    if value is None:
        return ""

    return str(value).lower()


def check_condition(event, field, operator, expected):
    """
    Check one detection condition against an event.
    """

    actual = event.get(field)

    if operator == "endswith":
        return normalize(actual).endswith(
            normalize(expected)
        )

    if operator == "contains":
        return normalize(expected) in normalize(actual)

    if operator == "equals":
        return normalize(actual) == normalize(expected)

    if operator == "contains_all":
        actual_normalized = normalize(actual)

        return all(
            normalize(item) in actual_normalized
            for item in expected
        )

    return False


def rule_matches(event, rule):
    """
    Return True only when all rule conditions match.
    """

    for field, operator, expected in rule["conditions"]:

        if not check_condition(
            event,
            field,
            operator,
            expected
        ):
            return False

    return True


def run_detection(events, rules):
    """
    Run every detection rule against every event.
    """

    alerts = []

    for event in events:

        for rule in rules:

            if rule_matches(event, rule):

                alerts.append(
                    {
                        "rule_id": rule.get("id"),
                        "rule_name": rule["name"],
                        "event": event
                    }
                )

    return alerts


def print_alert(alert):
    """
    Display one alert in the terminal.
    """

    event = alert["event"]

    print("=" * 70)

    print(
        f"ALERT [Rule {alert.get('rule_id')}]: "
        f"{alert['rule_name']}"
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


def export_alerts(alerts, events_file, rules_file):
    """
    Export detection results to reports/alerts.json.
    """

    os.makedirs("reports", exist_ok=True)

    report = {
        "report": {
            "engine": "Cyberion ThreatShield",
            "generated_at": datetime.now().astimezone().isoformat(),
            "source_file": events_file,
            "rules_file": rules_file,
            "total_alerts": len(alerts)
        },
        "alerts": alerts
    }

    output_file = "reports/alerts.json"

    with open(output_file, "w") as f:
        json.dump(
            report,
            f,
            indent=4,
            ensure_ascii=False
        )

    return output_file


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

    try:

        events = load_json(events_file)
        rules = load_json(rules_file)

    except FileNotFoundError as error:

        print("File not found:")
        print(error)

        sys.exit(1)

    except json.JSONDecodeError as error:

        print("Invalid JSON:")
        print(error)

        sys.exit(1)

    alerts = run_detection(
        events,
        rules
    )

    print()
    print("Cyberion ThreatShield")
    print("Automated Detection Engine")
    print("-" * 40)

    print(f"Total Events: {len(events)}")
    print(f"Total Rules: {len(rules)}")
    print(f"Total Alerts: {len(alerts)}")

    if len(alerts) == 0:

        print()
        print("No detection matches found.")

    else:

        for alert in alerts:
            print_alert(alert)

    output_file = export_alerts(
        alerts,
        events_file,
        rules_file
    )

    print()
    print("-" * 40)
    print(f"Alert report saved to: {output_file}")


if __name__ == "__main__":
    main()