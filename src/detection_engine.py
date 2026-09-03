import json
import sys


def load_json(file_path):
    with open(file_path, "r") as f:
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


def rule_matches(event, rule):
    for field, operator, expected in rule["conditions"]:
        if not check_condition(event, field, operator, expected):
            return False

    return True


def run_detection(events, rules):
    alerts = []

    for event in events:
        for rule in rules:
            if rule_matches(event, rule):
                alerts.append({
                    "rule": rule["name"],
                    "event": event
                })

    return alerts


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print(
            "python src/detection_engine.py "
            "<events.json> <rules.json>"
        )
        sys.exit(1)

    events_file = sys.argv[1]
    rules_file = sys.argv[2]

    events = load_json(events_file)
    rules = load_json(rules_file)

    alerts = run_detection(events, rules)

    print(f"Total Events: {len(events)}")
    print(f"Total Rules: {len(rules)}")
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