import json
import os
import sys

from flask import Flask, render_template, request
from werkzeug.utils import secure_filename


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from evtx_parser import parse_evtx
from detection_engine import run_detection


app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

RULES_FILE = os.path.join(
    BASE_DIR,
    "config",
    "detection_rules.json"
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


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
        total_rules=len(rules)
    )


@app.route("/upload", methods=["POST"])
def upload_file():

    rules = load_rules()

    if "evtx_file" not in request.files:
        return render_template(
            "index.html",
            error="No file field received.",
            total_rules=len(rules)
        )

    file = request.files["evtx_file"]

    if not file or file.filename == "":
        return render_template(
            "index.html",
            error="No EVTX file selected.",
            total_rules=len(rules)
        )

    if not file.filename.lower().endswith(".evtx"):
        return render_template(
            "index.html",
            error="Only .evtx files are allowed.",
            total_rules=len(rules)
        )

    filename = secure_filename(file.filename)

    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(save_path)

    try:
        events = parse_evtx(save_path)

        alerts = run_detection(
            events,
            rules
        )

        return render_template(
            "index.html",
            message=f"{filename} scanned successfully.",
            filename=filename,
            total_events=len(events),
            total_rules=len(rules),
            total_alerts=len(alerts),
            alerts=alerts
        )

    except Exception as error:
        return render_template(
            "index.html",
            error=f"Scan failed: {error}",
            total_rules=len(rules)
        )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )
