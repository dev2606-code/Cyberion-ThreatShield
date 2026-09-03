from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import json
import sys


def parse_evtx(file_path):
    events = []

    with Evtx(file_path) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())

            ns = {
                "e": "http://schemas.microsoft.com/win/2004/08/events/event"
            }

            event_id = root.find(".//e:EventID", ns)
            computer = root.find(".//e:Computer", ns)
            time_created = root.find(".//e:TimeCreated", ns)

            event = {
                "EventID": event_id.text if event_id is not None else None,
                "Computer": computer.text if computer is not None else None,
                "TimeCreated": (
                    time_created.attrib.get("SystemTime")
                    if time_created is not None
                    else None
                )
            }

            for data in root.findall(".//e:EventData/e:Data", ns):
                name = data.attrib.get("Name")

                if name:
                    event[name] = data.text

            events.append(event)

    return events


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage:")
        print("python src/evtx_parser.py <evtx_file> [output.json]")
        sys.exit(1)

    input_file = sys.argv[1]

    events = parse_evtx(input_file)

    print(f"Parsed Events: {len(events)}")

    for event in events:
        print("=" * 60)

        print("EventID:", event.get("EventID"))
        print("Computer:", event.get("Computer"))
        print("Time:", event.get("TimeCreated"))

        important_fields = [
            "User",
            "Image",
            "CommandLine",
            "ParentImage",
            "ParentCommandLine",
            "SourceIp",
            "SourcePort",
            "DestinationIp",
            "DestinationPort",
            "TargetUserName",
            "TargetObject",
            "Details"
        ]

        for field in important_fields:
            if event.get(field):
                print(f"{field}: {event[field]}")

    if len(sys.argv) >= 3:
        output_file = sys.argv[2]

        with open(output_file, "w") as f:
            json.dump(events, f, indent=4)

        print()
        print(f"JSON saved to: {output_file}")