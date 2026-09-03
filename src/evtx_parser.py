from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import sys

def parse_evtx(file_path):
    with Evtx(file_path) as log:
        for record in log.records():
            xml_data = record.xml()

            root = ET.fromstring(xml_data)

            ns = {
                "e": "http://schemas.microsoft.com/win/2004/08/events/event"
            }

            event_id = root.find(".//e:EventID", ns)
            computer = root.find(".//e:Computer", ns)
            time_created = root.find(".//e:TimeCreated", ns)

            event_data = {}

            for data in root.findall(".//e:EventData/e:Data", ns):
                name = data.attrib.get("Name")
                value = data.text

                if name:
                    event_data[name] = value

            print("=" * 60)

            print("EventID:",
                  event_id.text if event_id is not None else "N/A")

            print("Computer:",
                  computer.text if computer is not None else "N/A")

            if time_created is not None:
                print("Time:",
                      time_created.attrib.get("SystemTime"))

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
                "Details",
                "ScriptBlockText"
            ]

            for field in important_fields:
                if field in event_data:
                    print(f"{field}: {event_data[field]}")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:")
        print("python src/evtx_parser.py <evtx_file>")
        sys.exit(1)

    parse_evtx(sys.argv[1])