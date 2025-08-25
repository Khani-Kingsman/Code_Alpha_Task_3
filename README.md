# 🕵️ BugBountyGUI

BugBountyGUI is a lightweight, GUI-based bug bounty helper tool built with Python + Tkinter.
It allows security researchers and students to scan URLs for common misconfigurations & vulnerabilities, and scan code files for insecure patterns.
Findings can be exported as JSON or HTML reports, making it easy to share results or submit to platforms like HackerOne, Bugcrowd, or OpenBugBounty.

# ✨ Features
 🔗 URL Scanning

 1. Detects missing security headers (CSP, XFO, HSTS, etc.)
 2. Checks for exposed sensitive files (/.git/config, /.env, /server-status, /robots.txt)
 3. Reflected XSS testing with common payloads (?q=<payload>)
 4. Basic SQL Injection detection (error-based, ?id=<payload>)

# 📂 Code Scanning

Identifies risky patterns in Python / JavaScript / PHP / any code file

# Flags usage of:
```
Functions:
eval(), exec(), os.system(), subprocess.*
pickle.load(), yaml.load() (insecure deserialization)
requests(..., verify=False) (TLS disabled)
```
Detects hardcoded passwords, API keys, AWS keys
Finds SQL concatenation in code
Alerts on dangerous JavaScript sinks (innerHTML, document.write)

# 📊 Reporting
Interactive GUI with findings table
Export findings to:
JSON report (machine-readable)
HTML report (professional format for submissions)

# 🚀 Getting Started
🔹 Clone the Repository
```
git clone https://github.com/yourusername/BugBountyGUI.git
cd BugBountyGUI
```
🔹 Install Requirements
```
pip install -r requirements.txt
```

🔹 Run the Application
```
python app.py
```

💡 On Windows, you can also double-click app.py to launch the GUI.

# 🖥️ Usage
 🔗 Scan a URL
 Example
 Enter in the GUI: ' '
 Click "Scan URL"

# 📂 Scan Code
 Steps in GUI:
 1. Click "Browse"
 2. Select a code file (e.g., script.py, app.js, index.php)
 3. Click "Scan File"

# 📊 Export Report
 In GUI:
 - Export JSON → Save structured report
 - Export HTML → Save professional report (for bug bounty submission)

# ⚠️ Disclaimer

This project is for educational and research purposes only.
It is not a substitute for professional penetration testing tools.
Do not scan systems without explicit authorization.

# 🤝 Contributing

Pull requests are welcome!
You can add:
More payload sets
Extra vulnerability modules
Advanced reporting (CVSS, severity scoring)

Contributions make this tool better for the community 🚀

🔥 With BugBountyGUI, you can quickly demonstrate vulnerabilities in labs, CTFs, and beginner bug bounty research — all with a clean GUI and exportable reports.
