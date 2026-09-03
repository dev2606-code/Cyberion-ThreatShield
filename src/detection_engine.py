import json
import sys


def load_events(json_file):
    with open(json_file, "r") as f:
        return json.load(f)


def detect_suspicious_ftp_cmd(events):
    matches = []

    for event in events:
        parent_image = (event.get("ParentImage") or "").lower()
        image = (event.get("Image") or "").lower()

        if parent_image.endswith("\\ftp.exe") and image.endswith("\\cmd.exe"):
            matches.append(event)

    return matches


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:")
        print("python src/detection_engine.py <events.json>")
        sys.exit(1)

    json_file = sys.argv[1]

    events = load_events(json_file)

    matches = detect_suspicious_ftp_cmd(events)

    print(f"Total Events: {len(events)}")
    print(f"Detection Matches: {len(matches)}")

    for match in matches:
        print("=" * 60)
        print("ALERT: Suspicious Command Shell Spawned by FTP")
        print("Computer:", match.get("Computer"))
        print("Time:", match.get("TimeCreated"))
        print("User:", match.get("User"))
        print("ParentImage:", match.get("ParentImage"))
        print("Image:", match.get("Image"))
        print("CommandLine:", match.get("CommandLine"))