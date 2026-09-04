import json
import os
import sys
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for
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
LATEST_ALERTS_FILE = os.path.join(
    DATA_FOLDER,
    "latest_alerts.json"
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

latest_scan_result = {}

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
def load_latest_alerts():

    if not os.path.exists(LATEST_ALERTS_FILE):
        return []

    try:

        with open(
            LATEST_ALERTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            alerts = json.load(file)

        if not isinstance(alerts, list):
            return []

        return alerts

    except (
        json.JSONDecodeError,
        OSError
    ):
        return []


def save_latest_alerts(alerts):

    with open(
        LATEST_ALERTS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4,
            ensure_ascii=False
        )
scan_history = load_scan_history()
latest_alerts = load_latest_alerts()
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

    context = {
        "total_rules": len(rules),
        "scan_history": scan_history,
        "analytics": analytics
    }

    context.update(latest_scan_result)

    return render_template(
        "index.html",
        **context
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
# ALERTS PAGE
# --------------------------------------------------

@app.route("/alerts")
def alerts_page():

    rules = load_rules()

    return render_template(
        "alerts.html",
        alerts=latest_alerts,
        total_alerts=len(latest_alerts),
        total_rules=len(rules)
    )
# --------------------------------------------------
# SCAN HISTORY PAGE
# --------------------------------------------------

@app.route("/history")
def history_page():

    return render_template(
        "history.html",
        scan_history=scan_history,
        total_scans=len(scan_history)
    )
# --------------------------------------------------
# SYSTEM STATUS PAGE
# --------------------------------------------------
@app.route("/history/<int:scan_id>")
def history_detail(scan_id):

    if scan_id < 0 or scan_id >= len(scan_history):
        return "Scan not found", 404

    scan = scan_history[scan_id]

    return render_template(
        "history_detail.html",
        scan=scan,
        scan_id=scan_id
    )
@app.route("/status")
def status_page():

    rules = load_rules()
    analytics = calculate_analytics()

    latest_scan = (
        scan_history[0]
        if scan_history
        else None
    )

    return render_template(
        "status.html",
        total_rules=len(rules),
        total_scans=len(scan_history),
        total_alerts=len(latest_alerts),
        analytics=analytics,
        latest_scan=latest_scan
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

        latest_alerts.clear()
        latest_alerts.extend(alerts)
        save_latest_alerts(latest_alerts)

        latest_scan_result.clear()

        latest_scan_result.update({
            "message": (
                f"{filename} scanned successfully."
            ),
            "filename": filename,
            "total_events": len(events),
            "total_alerts": len(alerts),
            "alerts": alerts,
            "reports_ready": True
        })

        return redirect(
            url_for("home"),
            code=303
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
    