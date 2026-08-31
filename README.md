# LogSentinel 🛡️

**A lightweight Python tool for spotting suspicious activity in your system logs.**

LogSentinel scans authentication and access logs to flag patterns that usually mean 
trouble — repeated failed logins, brute-force attempts, and other red flags a SOC 
analyst would want to catch early. Built for anyone who wants quick, no-fuss log 
triage without spinning up a full SIEM stack.

---

## ✨ Why LogSentinel?

Most log-monitoring tools are heavyweight, require external services, or are 
overkill for a single server or small team. LogSentinel takes the opposite approach:

- **Zero external dependencies** — runs with just the Python standard library
- **Fast to set up** — clone, run, done
- **Readable output** — findings are presented in plain, actionable language
- **Extensible** — add your own detection rules with minimal code

---

## 🔍 What It Detects

| Pattern                        | Description                                      |
|--------------------------------|---------------------------------------------------|
| Repeated failed logins          | Flags accounts with multiple failed auth attempts |
| Brute-force indicators          | Detects rapid-fire login attempts from one source |
| Suspicious IP activity          | Highlights IPs behind unusual login patterns      |
| Off-hours access attempts       | (extendable) flags logins outside expected hours  |

---

## ⚙️ Installation

```bash
git clone git@github.com:ashrafulX/logsentinel.git
cd logsentinel
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt   # if any dependencies exist
```

No external dependencies are required for the core functionality — 
it runs on the Python standard library alone.

---

## 🚀 Usage

Run it against a log file directly:

```bash
python logsentinel/main.py --log-file /path/to/auth.log
```

Or use the bundled sample log to try it out immediately:

```bash
python logsentinel/main.py
```

### Options

| Flag                    | Description                                  |
|--------------------------|-----------------------------------------------|
| `--log-file`             | Path to the log file to analyze              |
| `--output-format`        | `text` (default) or `json`                   |
| `--severity-threshold`   | Minimum severity level to report              |

---

## 📋 Example Output

```
[LogSentinel Report]
Suspicious IP: 192.168.1.45
Failed attempts: 7
Status: FLAGGED — possible brute-force

Total events scanned: 320
Flagged events: 1
```

---

## 🗂️ Project Structure

```
logsentinel/
├── logsentinel/
│   ├── main.py
│   ├── parser.py
│   ├── detector.py
│   └── report.py
├── sample_logs/
│   └── authentication_logs.csv
├── tests/
│   ├── test_detector.py
│   ├── test_detector_pytest.py
│   └── test_parser.py
├── LICENSE
└── README.md
```

---

## 🧪 Running Tests

```bash
python -m pytest
```

---

## 🛣️ Roadmap

- [ ] Support for Apache/Nginx access logs
- [ ] HTML report export
- [ ] Configurable detection rules via YAML
- [ ] Slack/webhook alerting for flagged events

---

## 🙏 Credits

This project was originally inspired by 
[ThePreacherMan's python-soc-log-analyzer](https://github.com/ThePreacherMan/python-soc-log-analyzer). 
LogSentinel rebuilds the core idea with a refreshed structure, new features, and 
ongoing extensions, maintained by **Ashraful** ([@ashrafulX](https://github.com/ashrafulX)).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file 
for details.
