import json
import os
import sys
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    send_file
)

from werkzeug.utils import secure_filename


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SRC_DIR = os.path.join(
    BASE_DIR,
    "src"
)

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


from evtx_parser import parse_evtx

from detection_engine import (
    run_detection,
    export_json_report,
    export_csv_report
)


app = Flask(__name__)


UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

RULES_FILE = os.path.join(
    BASE_DIR,
    "config",
    "detection_rules.json"
)

REPORTS_FOLDER = os.path.join(
    BASE_DIR,
    "reports"
)


os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    REPORTS_FOLDER,
    exist_ok=True
)


app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["MAX_CONTENT_LENGTH"] = (
    50 * 1024 * 1024
)


latest_reports = {
    "json": None,
    "csv": None
}


# Latest 10 scans
scan_history = []


def load_rules():

    with open(
        RULES_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


@app.route("/")
def home():

    rules = load_rules()

    return render_template(
        "index.html",
        total_rules=len(rules),
        scan_history=scan_history
    )


@app.route(
    "/upload",
    methods=["POST"]
)
def upload_file():

    rules = load_rules()

    if "evtx_file" not in request.files:

        return render_template(
            "index.html",
            error="No file field received.",
            total_rules=len(rules),
            scan_history=scan_history
        )


    file = request.files["evtx_file"]


    if not file or file.filename == "":

        return render_template(
            "index.html",
            error="No EVTX file selected.",
            total_rules=len(rules),
            scan_history=scan_history
        )


    if not file.filename.lower().endswith(
        ".evtx"
    ):

        return render_template(
            "index.html",
            error="Only .evtx files are allowed.",
            total_rules=len(rules),
            scan_history=scan_history
        )


    filename = secure_filename(
        file.filename
    )


    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )


    file.save(
        save_path
    )


    try:

        # Parse EVTX
        events = parse_evtx(
            save_path
        )


        # Run detection engine
        alerts = run_detection(
            events,
            rules
        )


        # Report timestamp
        timestamp = (
            datetime.now()
            .astimezone()
            .strftime(
                "%Y%m%d_%H%M%S"
            )
        )


        # Export JSON report
        json_report = export_json_report(
            alerts,
            filename,
            RULES_FILE,
            timestamp
        )


        # Export CSV report
        csv_report = export_csv_report(
            alerts,
            timestamp
        )


        latest_reports["json"] = (
            os.path.abspath(
                json_report
            )
        )

        latest_reports["csv"] = (
            os.path.abspath(
                csv_report
            )
        )


        # Add scan history
        scan_entry = {
            "filename": filename,

            "total_events":
                len(events),

            "total_alerts":
                len(alerts),

            "timestamp":
                datetime.now()
                .astimezone()
                .strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        }


        scan_history.insert(
            0,
            scan_entry
        )


        # Keep only latest 10
        if len(scan_history) > 10:
            scan_history.pop()


        return render_template(
            "index.html",

            message=(
                f"{filename} "
                "scanned successfully."
            ),

            filename=filename,

            total_events=len(events),

            total_rules=len(rules),

            total_alerts=len(alerts),

            alerts=alerts,

            scan_history=scan_history,

            reports_ready=True
        )


    except Exception as error:

        return render_template(
            "index.html",

            error=(
                f"Scan failed: "
                f"{error}"
            ),

            total_rules=len(rules),

            scan_history=scan_history
        )


@app.route("/download/json")
def download_json():

    report = latest_reports.get(
        "json"
    )

    if not report:
        return (
            "No JSON report available.",
            404
        )

    if not os.path.exists(
        report
    ):
        return (
            "JSON report not found.",
            404
        )

    return send_file(
        report,
        as_attachment=True
    )


@app.route("/download/csv")
def download_csv():

    report = latest_reports.get(
        "csv"
    )

    if not report:
        return (
            "No CSV report available.",
            404
        )

    if not os.path.exists(
        report
    ):
        return (
            "CSV report not found.",
            404
        )

    return send_file(
        report,
        as_attachment=True
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )