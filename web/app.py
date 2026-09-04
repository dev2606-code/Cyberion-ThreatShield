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


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

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


# --------------------------------------------------
# FLASK APP
# --------------------------------------------------

app = Flask(__name__)


UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

REPORTS_FOLDER = os.path.join(
    BASE_DIR,
    "reports"
)

DATA_FOLDER = os.path.join(
    BASE_DIR,
    "data"
)

HISTORY_FILE = os.path.join(
    DATA_FOLDER,
    "scan_history.json"
)

RULES_FILE = os.path.join(
    BASE_DIR,
    "config",
    "detection_rules.json"
)


os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    REPORTS_FOLDER,
    exist_ok=True
)

os.makedirs(
    DATA_FOLDER,
    exist_ok=True
)


app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["MAX_CONTENT_LENGTH"] = (
    50 * 1024 * 1024
)


# --------------------------------------------------
# LATEST GENERATED REPORTS
# --------------------------------------------------

latest_reports = {
    "json": None,
    "csv": None
}


# --------------------------------------------------
# DETECTION RULES
# --------------------------------------------------

def load_rules():

    with open(
        RULES_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# --------------------------------------------------
# SCAN HISTORY
# --------------------------------------------------

def load_scan_history():

    if not os.path.exists(HISTORY_FILE):

        return []

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            history = json.load(file)

        if not isinstance(history, list):
            return []

        return history[:10]

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []


def save_scan_history(history):

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history[:10],
            file,
            indent=4,
            ensure_ascii=False
        )


scan_history = load_scan_history()
scan_history = load_scan_history()
def calculate_analytics():

    return {
        "total_scans": len(scan_history),

        "total_events": sum(
            scan.get("total_events", 0)
            for scan in scan_history
        ),

        "total_alerts": sum(
            scan.get("total_alerts", 0)
            for scan in scan_history
        ),

        "high_alerts": sum(
            scan.get("high_alerts", 0)
            for scan in scan_history
        ),

        "medium_alerts": sum(
            scan.get("medium_alerts", 0)
            for scan in scan_history
        ),

        "low_alerts": sum(
            scan.get("low_alerts", 0)
            for scan in scan_history
        )
    }


    


 # --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    rules = load_rules()
    analytics = calculate_analytics()

    return render_template(
        "index.html",
        total_rules=len(rules),
        scan_history=scan_history,
        analytics=analytics
    )


# --------------------------------------------------
# DETECTION RULES PAGE
# --------------------------------------------------
@app.route("/rules")
def rules_page():

    rules = load_rules()

    return render_template(
        "rules.html",
        rules=rules,
        total_rules=len(rules)
    )
# --------------------------------------------------
# EVTX UPLOAD + SCAN
# --------------------------------------------------

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
          scan_history=scan_history,
analytics=calculate_analytics()
        )


    file = request.files["evtx_file"]


    if not file or file.filename == "":

        return render_template(
            "index.html",
            error="No EVTX file selected.",
            total_rules=len(rules),
          scan_history=scan_history,
analytics=calculate_analytics()
        )


    if not file.filename.lower().endswith(
        ".evtx"
    ):

        return render_template(
            "index.html",
            error="Only .evtx files are allowed.",
            total_rules=len(rules),
           scan_history=scan_history,
analytics=calculate_analytics()
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

        # ------------------------------------------
        # PARSE EVTX
        # ------------------------------------------

        events = parse_evtx(
            save_path
        )


        # ------------------------------------------
        # RUN DETECTION ENGINE
        # ------------------------------------------

        alerts = run_detection(
            events,
            rules
        )


        # ------------------------------------------
        # TIMESTAMP
        # ------------------------------------------

        now = datetime.now().astimezone()

        report_timestamp = now.strftime(
            "%Y%m%d_%H%M%S"
        )

        display_timestamp = now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )


        # ------------------------------------------
        # GENERATE REPORTS
        # ------------------------------------------

        json_report = export_json_report(
            alerts,
            filename,
            RULES_FILE,
            report_timestamp
        )


        csv_report = export_csv_report(
            alerts,
            report_timestamp
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


        # ------------------------------------------
        # SAVE SCAN HISTORY
        # ------------------------------------------
        high_alerts = sum(
            1
            for alert in alerts
            if str(alert.get("severity", "")).lower() == "high"
        )

        medium_alerts = sum(
            1
            for alert in alerts
            if str(alert.get("severity", "")).lower() == "medium"
        )

        low_alerts = sum(
            1
            for alert in alerts
            if str(alert.get("severity", "")).lower() == "low"
        )

        scan_entry = {
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts": low_alerts,

            "filename": filename,

            "total_events":
                len(events),

            "total_alerts":
                len(alerts),

            "timestamp":
                display_timestamp
        }
        
        scan_history.insert(
            0,
            scan_entry
        )


        # Keep latest 10 scans only
        del scan_history[10:]


        save_scan_history(
            scan_history
        )


        # ------------------------------------------
        # RENDER RESULTS
        # ------------------------------------------

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
            analytics=calculate_analytics(),

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

          scan_history=scan_history,
analytics=calculate_analytics()
        )


# --------------------------------------------------
# DOWNLOAD JSON REPORT
# --------------------------------------------------

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


# --------------------------------------------------
# DOWNLOAD CSV REPORT
# --------------------------------------------------

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


# --------------------------------------------------
# START SERVER
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )
    