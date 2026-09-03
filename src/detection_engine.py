import json
import sys


def load_events(json_file):
    with open(json_file, "r") as f:
        return json.load(f)


def normalize(value):
    return (value or "").lower()


def check_condition(event, field, operator, expected):
    actual = event.get(field)

    if operator == "endswith":
        return normalize(actual).endswith(normalize(expected))

    if operator == "contains":
        return normalize(expected) in normalize(actual)

    if operator == "equals":
        return normalize(actual) == normalize(expected)

    return False


RULES = [
    {
        "name": "Suspicious Command Shell Spawned by FTP",
        "conditions": [
            ("ParentImage", "endswith", "\\ftp.exe"),
            ("Image", "endswith", "\\cmd.exe"),
        ]
    },
    {
        "name": "MSHTA Execution of HTA File",
        "conditions": [
            ("Image", "endswith", "\\mshta.exe"),
            ("CommandLine", "contains", ".hta"),
        ]
    },
    {
        "name": "Command Shell Spawned by WMI Provider",
        "conditions": [
            ("ParentImage", "endswith", "\\wmiprvse.exe"),
            ("Image", "endswith", "\\cmd.exe"),
        ]
    }
]


def rule_matches(event, rule):
    for field, operator, expected in rule["conditions"]:
        if not check_condition(event, field, operator, expected):
            return False

    return True


def run_detection(events):
    alerts = []

    for event in events:
        for rule in RULES:
            if rule_matches(event, rule):
                alerts.append({
                    "rule": rule["name"],
                    "event": event
                })

    return alerts


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:")
        print("python src/detection_engine.py <events.json>")
        sys.exit(1)

    events = load_events(sys.argv[1])

    alerts = run_detection(events)

    print(f"Total Events: {len(events)}")
    print(f"Total Rules: {len(RULES)}")
    print(f"Total Alerts: {len(alerts)}")

    for alert in alerts:
        event = alert["event"]

        print("=" * 60)
        print("ALERT:", alert["rule"])
        print("Computer:", event.get("Computer"))
        print("Time:", event.get("TimeCreated"))
        print("User:", event.get("User"))
        print("Image:", event.get("Image"))
        print("CommandLine:", event.get("CommandLine"))
        print("ParentImage:", event.get("ParentImage"))