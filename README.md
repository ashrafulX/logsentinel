# LogSentinel 🛡️

**A lightweight Python + Django tool for spotting suspicious activity in authentication logs.**

LogSentinel scans authentication logs (CSV format) and flags patterns that usually mean trouble — repeated failed logins and brute-force attempts — the kind of thing a SOC analyst wants to catch early. It ships two ways to run it: a **command-line tool** for quick local scans, and a **Django web app** with a drag-and-drop upload UI for visual analysis in the browser.

![LogSentinel Landing Page](screenshots/landingpage.png)

---

## ✨ Why LogSentinel?

Most log-monitoring stacks are heavyweight, need external services, or are overkill for a single server or small team. LogSentinel keeps things simple:

- **Minimal dependencies** — the core detection engine only uses Python's standard library
- **Two interfaces** — a CLI for scripting/automation, and a web UI for point-and-click analysis
- **Fast to set up** — clone, install, run
- **Readable output** — findings are shown in plain, actionable language
- **Extensible** — the detection logic lives in a few small, well-documented modules

---

## 🔍 How It Works

LogSentinel's core pipeline lives in the `logsentinel/` package and runs in three steps:

1. **Parse** (`parser.py`) — reads the CSV log file, strips a BOM if present, normalizes column names, skips empty rows, and validates that the required columns (`timestamp`, `user`, `ip_address`, `status`) exist. If anything's missing, it raises a clear error instead of failing silently.

2. **Detect** (`detector.py`) — runs two checks over the parsed events:
   - `detect_failed_logins()` counts every event with `status = FAILED`.
   - `detect_brute_force()` groups failed attempts by `(user, ip_address)` pair and flags any combination that hits a threshold (default: **5 failed attempts**) as a `HIGH` risk alert, complete with a human-readable reason.

3. **Report** (`report.py`) — takes the totals and alerts and builds a formatted text summary, which is both printed to the console and saved to a report file.

The **web app** (`analyzer/` Django app) wraps this exact same pipeline behind a browser UI: you upload a CSV, Django saves it to a temp file, runs it through `parser.py` and `detector.py`, and renders the results (total events, successful/failed counts, and any brute-force alerts) directly on the page — no page reload, no separate report file needed.

---

## 🗂️ Project Structure

```
logsentinel/
├── analyzer/           # Django app powering the web UI
│   ├── forms.py        # CSV upload form
│   ├── views.py        # Handles upload, parsing, and rendering results
│   ├── urls.py
│   └── tests.py
├── config/             # Django project settings
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
├── logsentinel/        # Core detection engine (used by both CLI and web app)
│   ├── main.py         # CLI entry point
│   ├── parser.py       # CSV log parsing
│   ├── detector.py     # Failed-login & brute-force detection
│   └── report.py       # Report generation
├── templates/
│   └── analyzer/
│       └── index.html  # Web UI (upload form + results dashboard)
├── sample_logs/
│   └── authentication_logs.csv  # Sample data to try things out
├── screenshots/
│   ├── landingpage.png
│   └── terminal-output.png
├── tests/
│   ├── test_detector.py
│   ├── test_detector_pytest.py
│   └── test_parser.py
├── manage.py
├── requirements.txt
├── LICENSE
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/ashrafulX/logsentinel.git
cd logsentinel
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

The web app needs a `SECRET_KEY` environment variable (read via `python-decouple`). Create a `.env` file in the project root:

```bash
SECRET_KEY=your-secret-key-here
```

---

## 🚀 Usage

### Option 1 — Command Line

Run the analyzer against the bundled sample log:

```bash
python logsentinel/main.py
```

This will:
- Parse `sample_logs/authentication_logs.csv`
- Print a security summary to the console
- Save a full report to `reports/security_report.txt`

### Option 2 — Web Interface

```bash
python manage.py migrate
python manage.py runserver
```

Then open **http://127.0.0.1:8000/** in your browser:

1. Drag and drop (or browse for) a CSV authentication log
2. Click **Analyze Logs**
3. View total events, successful/failed logins, and any brute-force alerts right on the page

---

## 📄 CSV Format

LogSentinel expects the following columns:

| Column       | Description                    |
|--------------|---------------------------------|
| `timestamp`  | Date and time of the event      |
| `user`       | Username involved in the event  |
| `ip_address` | Source IP address               |
| `status`     | `FAILED` or `SUCCESS`           |

Example:

```csv
timestamp,user,ip_address,status
2026-07-10 08:15:21,john,192.168.1.10,FAILED
2026-07-10 08:15:35,john,192.168.1.10,FAILED
2026-07-10 08:16:15,john,192.168.1.10,SUCCESS
```

If a required column is missing, the parser raises a `ValueError` naming exactly which column(s) are absent.

---

## 📋 Example Output (CLI)
```
========== SECURITY SUMMARY ==========
Total Events       : 14
Successful Logins  : 8
Failed Logins      : 6
Security Alerts    : 1

========== HIGH-RISK ALERTS ==========

Alert #1
User               : admin
IP Address         : 10.0.0.5
Failed Attempts    : 5
Risk Level         : HIGH
Reason             :
5 failed login attempts detected for user 'admin' from 10.0.0.5.

======================================

Report saved to: reports/security_report.txt
```

---

## 🧪 Running Tests

```bash
python -m pytest
python manage.py test analyzer.tests -v 2
```

---

## 🛣️ Roadmap

- [ ] Support for Apache/Nginx access logs
- [ ] HTML report export
- [ ] Configurable detection rules (threshold, time windows) via YAML or the web UI
- [ ] Slack/webhook alerting for flagged events
- [ ] Off-hours access detection

---

## 🙏 Credits

This project was originally inspired by [ThePreacherMan's python-soc-log-analyzer](https://github.com/ThePreacherMan/python-soc-log-analyzer). LogSentinel rebuilds the core idea with a refreshed structure, a Django-based web interface, and ongoing extensions, maintained by **Ashraful** ([@ashrafulX](https://github.com/ashrafulX)).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
