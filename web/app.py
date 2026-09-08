import json
import os
import sys
from datetime import datetime
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for,
    session
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
import resend
resend.api_key = os.environ.get("RESEND_API_KEY")
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

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "cyberion-dev-secret-key"
)
oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True

app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")

mail = Mail(app)
ADMIN_USERNAME = os.environ.get(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD"
  
)
reset_serializer = URLSafeTimedSerializer(app.secret_key)
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
USERS_FILE = os.path.join(
    DATA_FOLDER,
    "users.json"
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
# AUTHENTICATION
# --------------------------------------------------
# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}

    try:
        with open(
            USERS_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            users = json.load(file)

        if not isinstance(users, dict):
            return {}

        return users

    except (json.JSONDecodeError, OSError):
        return {}


def save_users(users):
    with open(
        USERS_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            users,
            file,
            indent=4
        )
def login_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if not session.get("logged_in"):
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


@app.route("/signup", methods=["GET", "POST"])
def signup():

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3:
            error = "Username must be at least 3 characters."

        elif not email:
            error = "Email address is required."

        elif len(password) < 6:
            error = "Password must be at least 6 characters."

        elif password != confirm_password:
            error = "Passwords do not match."

        else:
            users = load_users()


            if username in users:
                error = "Username already exists."

            elif any(
                user.get("email", "").lower() == email
                for user in users.values()
            ):
                error = "Email already registered."

            else:
                users[username] = {
                    "email": email,
                    "password_hash": generate_password_hash(password)
                }

                save_users(users)

                return redirect(url_for("login"))

    return render_template(
        "signup.html",
        error=error
    )
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    error = None
    message = None

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        users = load_users()
        print("DEBUG: user count =", len(users), flush=True)
        print(
            "DEBUG: submitted email found =",
            any(
                user.get("email", "").lower() == email
                for user in users.values()
            ),
            flush=True
        )
        username = None

        for name, user in users.items():
            if user.get("email", "").lower() == email:
                username = name
                break

        message = (
    "Reset request received. "
    "If this email is registered, a password reset link will arrive shortly."
)

        if username:
            token = reset_serializer.dumps(
                username,
                salt="password-reset"
            )

            reset_link = url_for(
                "reset_password",
                token=token,
                _external=True
            )
            try:
                resend.Emails.send({
                    "from": "Cyberion ThreatShield <onboarding@resend.dev>",
                    "to": [email],
                    "subject": "Cyberion ThreatShield - Password Reset",
                    "html": f"""
                        <h2>Hello {username},</h2>

                        <p>A password reset was requested for your Cyberion ThreatShield account.</p>

                        <p>
                            <a href="{reset_link}">
                                Reset your password
                            </a>
                        </p>

                        <p>This link expires in 15 minutes.</p>

                        <p>If you did not request a password reset, you can ignore this email.</p>
                    """
                })

                print("Password reset email sent.")

            except Exception as e:
                print(f"Email sending failed: {e}")
   
    return render_template(
        "forgot_password.html",
        error=error,
        message=message
    )
@app.route("/reset-password/<token>", methods=["GET", "POST"])

def reset_password(token):

    try:
        username = reset_serializer.loads(
            token,
            salt="password-reset",
            max_age=900
        )

    except SignatureExpired:
        return render_template(
            "reset_password.html",
            error="This password reset link has expired."
        )

    except BadSignature:
        return render_template(
            "reset_password.html",
            error="Invalid password reset link."
        )

    users = load_users()

    if username not in users:
        return render_template(
            "reset_password.html",
            error="Invalid password reset link."
        )

    error = None

    if request.method == "POST":

        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(password) < 6:
            error = "Password must be at least 6 characters."

        elif password != confirm_password:
            error = "Passwords do not match."

        else:
            users[username]["password_hash"] = (
                generate_password_hash(password)
            )

            save_users(users)

        return render_template("account_created.html")
    return render_template(
        "reset_password.html",
        error=error
    )
@app.route("/login/google")
def google_login():

    redirect_uri = url_for(
        "google_callback",
        _external=True
    )

    return google.authorize_redirect(redirect_uri)
    
@app.route("/login/google/callback")
def google_callback():

    print("DEBUG: GOOGLE CALLBACK EXECUTED")

    token = google.authorize_access_token()
    user_info = token.get("userinfo")

    if not user_info:
        return redirect(url_for("login"))

    email = user_info.get("email", "").strip().lower()
    name = user_info.get("name", "").strip()

    if not email:
        return redirect(url_for("login"))

    users = load_users()
    username = None

    # Check whether this email already exists
    for existing_username, user in users.items():
        if user.get("email", "").lower() == email:
            username = existing_username
            break

    # Existing account: link Google login
    if username is not None:
        users[username]["google_linked"] = True
        users[username]["name"] = name
        save_users(users)

    # New Google account
    else:
        base_username = email.split("@")[0] or "google_user"
        username = base_username
        counter = 1

        while username in users:
            username = f"{base_username}{counter}"
            counter += 1

        users[username] = {
            "email": email,
            "name": name,
            "auth_provider": "google",
            "google_linked": True
        }

        save_users(users)

    session["logged_in"] = True
    session["username"] = username
    session["email"] = email

    return redirect(url_for("home"))
@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        users = load_users()
        user = users.get(username)

        valid_admin = (
            ADMIN_PASSWORD
            and username == ADMIN_USERNAME
            and password == ADMIN_PASSWORD
        )

        valid_user = (
            user
            and check_password_hash(
                user.get("password_hash", ""),
                password
            )
        )

        if valid_admin or valid_user:
            session["logged_in"] = True
            session["username"] = username

            return redirect(url_for("home"))

        error = "Invalid username or password."

    return render_template(
        "login.html",
        error=error
    )

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))

    


 # --------------------------------------------------
# HOME PAGE
# --------------------------------------------------
@app.route("/")
@login_required
def home():

    rules = load_rules()
    analytics = calculate_analytics()

    context = {
        "total_rules": len(rules),
        "scan_history": scan_history,
        "analytics": analytics
    }

    # Show the latest scan result only once.
    # On browser refresh, temporary scan results are cleared.
    if latest_scan_result:
        context.update(latest_scan_result)
        latest_scan_result.clear()

    return render_template(
        "index.html",
        active_page="dashboard",
        **context
    )


# --------------------------------------------------
# DETECTION RULES PAGE
# --------------------------------------------------
@app.route("/rules")
@login_required
def rules_page():

    rules = load_rules()

    return render_template(
        "rules.html",
        active_page="rules",
        rules=rules,
        total_rules=len(rules)
    )


# --------------------------------------------------
# ALERTS PAGE
# --------------------------------------------------

@app.route("/alerts")
@login_required
def alerts_page():

    rules = load_rules()

    return render_template(
        "alerts.html",
        active_page="alerts",
        alerts=latest_alerts,
        total_alerts=len(latest_alerts),
        total_rules=len(rules)
    )
# --------------------------------------------------
# SCAN HISTORY PAGE
# --------------------------------------------------

@app.route("/history")
@login_required
def history_page():

    return render_template(
        "history.html",
        active_page="history",
        scan_history=scan_history,
        total_scans=len(scan_history)
    )
# --------------------------------------------------
# SYSTEM STATUS PAGE
# --------------------------------------------------
@app.route("/history/<int:scan_id>")
@login_required
def history_detail(scan_id):

    if scan_id < 0 or scan_id >= len(scan_history):
        return "Scan not found", 404

    scan = scan_history[scan_id]
    alerts = scan.get("alerts", [])

    return render_template(
        "history_detail.html",
        active_page="history",
        scan=scan,
        scan_id=scan_id,
        alerts=alerts
    )
@app.route("/status")
@login_required
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
        active_page="status",
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
@login_required
def upload_file():

    rules = load_rules()

    if "evtx_file" not in request.files:

        return render_template(
            "index.html",
            error="No file field received.",
            active_page="dashboard",
            total_rules=len(rules),
          scan_history=scan_history,
analytics=calculate_analytics()
        )


    file = request.files["evtx_file"]


    if not file or file.filename == "":

        return render_template(
            "index.html",
            error="No EVTX file selected.",
            active_page="dashboard",
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
            active_page="dashboard",
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

            "total_events": len(events),
            "total_alerts": len(alerts),

            "timestamp": display_timestamp,

            # Store alerts for this specific scan
            "alerts": alerts
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
@login_required
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
@login_required
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
        port=5001,
        debug=True,
        use_reloader=False
    )
    