# 🛡️ Cyberion ThreatShield

**Cyberion ThreatShield** is a Windows threat detection and threat-hunting project designed to analyze Windows EVTX logs, apply custom detection rules, identify suspicious activity, map detections to MITRE ATT&CK techniques, and display the results through a SOC-style web dashboard.

The project combines **Detection Engineering, Windows Event Log Analysis, Threat Hunting, Sigma Rules, MITRE ATT&CK, Python, and Flask** into a single security analysis platform.

---

## 🚀 Key Features

- 📂 Upload and scan Windows `.evtx` files
- 🔍 Automated Windows event log parsing
- 🛡️ Custom detection engine
- 📜 20 detection rules
- 🎯 MITRE ATT&CK technique mapping
- ⚠️ Alert severity classification
- 📊 SOC-style web dashboard
- 🔎 Alert search and severity filtering
- 🕒 Persistent scan history
- 📄 JSON report generation
- 📑 CSV report generation
- ⬇️ Downloadable detection reports
- 🧪 Sigma rule validation
- 💻 Command-line and web-based analysis

---

## 🏗️ Architecture

```text
                Windows EVTX File
                       │
                       ▼
                ┌──────────────┐
                │ EVTX Parser  │
                └──────┬───────┘
                       │
                       ▼
                Normalized Events
                       │
                       ▼
             ┌────────────────────┐
             │ Detection Engine   │
             └─────────┬──────────┘
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
       Detection Rules      MITRE ATT&CK
              │                 │
              └────────┬────────┘
                       ▼
                     Alerts
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       SOC Dashboard        JSON / CSV
                            Reports
```

---

## 🔄 Detection Workflow

```text
EVTX Upload
     ↓
EVTX Parsing
     ↓
Event Normalization
     ↓
20 Detection Rules
     ↓
Detection Engine
     ↓
Severity Classification
     ↓
MITRE ATT&CK Mapping
     ↓
SOC Dashboard
     ↓
Alert Search / Filtering
     ↓
Persistent Scan History
     ↓
JSON / CSV Reports
```

---

## 🧠 Detection Engineering

Cyberion ThreatShield uses rule-based detection logic to analyze Windows telemetry.

Detection conditions can evaluate fields such as:

- Event ID
- Process Image
- Command Line
- Parent Process
- Parent Command Line
- Network Protocol
- Destination Port
- Registry activity
- Windows security events

Supported condition operators include:

```text
equals
contains
contains_all
endswith
```

---

## 🛡️ Detection Rules

The project currently contains **20 custom detection rules** covering suspicious Windows activity.

Examples include:

| Rule | Detection |
|---|---|
| 1 | Suspicious Command Shell Spawned by FTP |
| 2 | Windows Failed Logon Attempt |
| 3 | RDP Network Connection |
| 4 | SMB Network Connection |
| 5 | IIS Worker Process Making RDP Connection |
| 6 | Process Spawned by Windows Remote Management Provider |
| 7 | PowerShell Script Block With Base64 Decoding |
| 8 | PowerShell Credential Access via GetNetworkCredential |
| 9 | PowerShell LSASS MiniDumpWriteDump Activity |
| 10 | Scheduled Task Creation Executing Command Shell |
| 11 | Winlogon Shell Registry Modification |
| 12 | PowerShell Execution Policy Changed to Unrestricted |
| 13 | MSHTA Execution of HTA File |
| 14 | Rundll32 PCWUTL LaunchApplication Execution |
| 15 | Command Shell Spawned by WMI Provider |
| 16 | New Windows Service Executing Command Shell |
| 17 | Member Added to Local Administrators Group |
| 18 | Remote Desktop Enabled via Registry |
| 19 | Windows Defender Threat Action Event |
| 20 | Regsvr32 Scrobj DLL Scriptlet Execution |

---

## 🎯 MITRE ATT&CK Integration

Detection alerts can include MITRE ATT&CK technique identifiers to help analysts understand the behavior represented by an alert.

Example:

```text
Rule 14
Rundll32 PCWUTL LaunchApplication Execution

Severity:
MEDIUM

MITRE ATT&CK:
T1218.011
```

This helps connect raw Windows telemetry with standardized adversary behavior.

---

## 🖥️ SOC Dashboard

Cyberion ThreatShield includes a Flask-based SOC dashboard that provides:

- Detection rule status
- EVTX scanner
- Events scanned
- Alerts found
- Detection details
- Severity information
- MITRE ATT&CK information
- Process and command-line evidence
- Recent scan history
- Alert search
- Severity filtering
- Report downloads

---

## 🔍 Example Detection

A Sysmon process creation event containing:

```text
Image:
C:\Windows\System32\rundll32.exe

CommandLine:
rundll32.exe pcwutl.dll,LaunchApplication
```

can trigger:

```text
Rule 14:
Rundll32 PCWUTL LaunchApplication Execution

MITRE ATT&CK:
T1218.011
```

The detection is then displayed on the web dashboard and included in generated reports.

---

## 📊 Scan History

Cyberion ThreatShield maintains recent scan information including:

- Filename
- Events scanned
- Alerts detected
- Scan timestamp

Scan history is stored locally so that recent scan information can survive Flask server restarts.

Runtime scan-history data is excluded from Git tracking.

---

## 📄 Detection Reports

After analysis, Cyberion ThreatShield can generate:

### JSON Report

Useful for:

- automation
- structured analysis
- integrations
- further processing

### CSV Report

Useful for:

- spreadsheets
- analyst review
- reporting
- filtering and investigation

Reports can be downloaded directly from the dashboard.

---

## 📁 Project Structure

```text
Cyberion-ThreatShield/
│
├── config/
│   └── detection_rules.json
│
├── data/
│   └── scan_history.json
│
├── datasets/
│   └── EVTX-ATTACK-SAMPLES/
│
├── reports/
│
├── sigma-rules/
│   └── *.yml
│
├── src/
│   ├── evtx_parser.py
│   └── detection_engine.py
│
├── uploads/
│
├── web/
│   ├── app.py
│   │
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   │
│   │   └── js/
│   │       └── app.js
│   │
│   └── templates/
│       └── index.html
│
├── .gitignore
└── README.md
```

> Runtime/generated files and large datasets may be excluded from Git using `.gitignore`.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/dev2606-code/Cyberion-ThreatShield.git
```

Move into the project:

```bash
cd Cyberion-ThreatShield
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

Activate it on macOS/Linux:

```bash
source venv/bin/activate
```

### 3. Install dependencies

Install the Python packages required by the project.

If a `requirements.txt` file is available:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Web Dashboard

Activate the virtual environment:

```bash
source venv/bin/activate
```

Start Flask:

```bash
python web/app.py
```

The development server will normally be available at:

```text
http://127.0.0.1:5000
```

Open the address in your browser.

---

## 🧪 Using Cyberion ThreatShield

1. Start the Flask server.
2. Open the dashboard.
3. Select a Windows `.evtx` file.
4. Click **Scan EVTX**.
5. Wait for parsing and detection analysis.
6. Review the generated alerts.
7. Search or filter alerts by severity.
8. Review recent scan history.
9. Download JSON or CSV reports when available.

---

## ✅ Validation

The project has been tested using Windows EVTX attack samples.

Development validation includes:

```bash
python -m py_compile src/*.py web/app.py
```

Detection-rule JSON validation:

```bash
python -m json.tool config/detection_rules.json
```

Sigma validation:

```bash
sigma check sigma-rules/
```

The Sigma rules have been validated without rule, condition, or validation errors in the tested project state.

---

## 🧪 Tested Detection Samples

Testing has included telemetry related to:

- Rundll32 execution
- Windows service creation
- Local Administrators group modification
- Remote Desktop configuration
- Windows Defender events
- Regsvr32/scrobj execution

These tests help verify detection behavior against different types of Windows telemetry rather than relying on a single EVTX sample.

---

## 🛠️ Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- Windows EVTX
- Sysmon telemetry
- Sigma
- MITRE ATT&CK
- Git
- GitHub

---

## 🔐 Security Note

Cyberion ThreatShield is intended for:

- cybersecurity education
- defensive security research
- detection engineering
- threat hunting
- SOC learning
- authorized security analysis

A detection represents an investigation signal and should be reviewed with additional context before classifying activity as malicious.

---

## 🗺️ Future Improvements

Planned improvements include:

- 📊 Detection analytics and charts
- 📋 Dedicated Detection Rules page
- 🔎 Advanced threat-hunting filters
- 📈 MITRE ATT&CK analytics
- 🗃️ Improved scan-history management
- 🧪 Additional detection rules
- ⚡ Performance improvements
- 🌐 Deployment for demonstration
- 🔐 Authentication and user management

---

## 👨‍💻 Author

**Devendra Sinha**

BCA Student | Cybersecurity Enthusiast  
Interested in Detection Engineering, Threat Hunting, SOC Operations and Security Analysis.

GitHub: [dev2606-code](https://github.com/dev2606-code)

---

## ⭐ Project Status

```text
Core Detection Engine     ✅
20 Detection Rules        ✅
Sigma Validation          ✅
MITRE ATT&CK Mapping      ✅
EVTX Web Scanner          ✅
SOC Dashboard             ✅
JSON / CSV Reports        ✅
Persistent Scan History   ✅
Alert Search & Filter     ✅
Analytics Dashboard       🚧
Rules Management UI       🚧
Deployment                🚧
```

---

## ⚠️ Disclaimer

This project is intended for educational and authorized defensive-security purposes. Analyze only systems, logs, and data that you own or are authorized to investigate.