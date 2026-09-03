import json
import sys


def load_events(json_file):
    with open(json_file, "r") as f:
        return json.load(f)


def endswith(value, suffix):
    return (value or "").lower().endswith(suffix.lower())


def contains(value, text):
    return text.lower() in (value or "").lower()


def rule_1_ftp_cmd(event):
    return (
        endswith(event.get("ParentImage"), "\\ftp.exe")
        and endswith(event.get("Image"), "\\cmd.exe")
    )


def rule_13_mshta(event):
    return (
        endswith(event.get("Image"), "\\mshta.exe")
        and contains(event.get("CommandLine"), ".hta")
    )


def rule_15_wmi_cmd(event):
    return (
        endswith(event.get("ParentImage"), "\\wmiprvse.exe")
        and endswith(event.get("Image"), "\\cmd.exe")
    )


RULES = [
    {
        "name": "Suspicious Command Shell Spawned by FTP",
        "rule": rule_1_ftp_cmd
    },
    {
        "name": "MSHTA Execution of HTA File",
        "rule": rule_13_mshta
    },
    {
        "name": "Command Shell Spawned by WMI Provider",
        "rule": rule_15_wmi_cmd
    }
]


def run_detection(events):
    alerts = []

    for event in events:
        for rule in RULES:
            if rule["rule"](event):
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