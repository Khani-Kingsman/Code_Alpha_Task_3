#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import queue
import re
import os
import sys
import json
import time
import html
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests

APP_NAME = "BugBountyGUI"
VERSION = "1.0"

SQLI_PAYLOADS = [
    "' or '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:3'--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>"
]

DB_ERROR_SIGS = [
    "sql syntax",
    "mysql",
    "mysqli",
    "psql",
    "postgresql",
    "ora-",
    "odbc",
    "sqlite",
    "syntax error",
    "unclosed quotation mark"
]

SEC_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
]

INTERESTING_PATHS = [
    "/.git/config",
    "/.env",
    "/server-status",
    "/robots.txt"
]

CODE_RULES = [
    # (regex, language hint, title, severity, recommendation)
    (r"eval\s*\(", "any", "Use of eval()", "high", "Avoid eval(); use safe parsing or whitelisting."),
    (r"\bexec\s*\(", "python", "Use of exec()", "high", "Avoid exec(); use functions or mappings."),
    (r"os\.system\s*\(", "python", "Command execution (os.system)", "high", "Use subprocess with list args and avoid untrusted input."),
    (r"subprocess\.(Popen|call|run)\s*\(", "python", "Command execution (subprocess)", "medium", "Validate and sanitize inputs. Prefer fixed arguments."),
    (r"pickle\.loads?\s*\(", "python", "Insecure deserialization (pickle)", "high", "Do not unpickle untrusted data."),
    (r"yaml\.load\s*\(", "python", "Insecure YAML load", "high", "Use yaml.safe_load for untrusted data."),
    (r"requests\.[a-z]+\([^)]*verify\s*=\s*False", "python", "TLS verification disabled", "medium", "Avoid verify=False; pin certificates in testing only."),
    (r"AKIA[0-9A-Z]{16}", "any", "Possible AWS Access Key", "high", "Rotate and remove secrets from code. Use a secrets manager."),
    (r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "any", "Hardcoded API key", "high", "Remove hardcoded secrets; use env vars/secrets manager."),
    (r"password\s*=\s*['\"][^'\"]+['\"]", "any", "Hardcoded password", "high", "Remove hardcoded credentials; use env vars."),
    (r"SELECT\s+.+\s+FROM\s+.+\s*\+\s*", "any", "SQL concatenation", "high", "Use parameterized queries."),
    (r"\.innerHTML\s*=", "js", "Dangerous assignment to innerHTML", "medium", "Sanitize/encode or use textContent."),
    (r"document\.write\s*\(", "js", "document.write()", "low", "Avoid document.write; use DOM APIs safely."),
]

def build_url_with_param(url, key, value):
    parts = list(urlparse(url))
    q = parse_qs(parts[4], keep_blank_values=True)
    q[key] = [value]
    parts[4] = urlencode(q, doseq=True)
    return urlunparse(parts)

def http_get(url, **kwargs):
    try:
        return requests.get(url, timeout=8, allow_redirects=True, **kwargs)
    except Exception as e:
        return None

def scan_url(target_url, progress_cb=None, stop_event=None):
    findings = []
    def add(title, sev, desc, evidence, cwe=None):
        findings.append({
            "target": target_url,
            "title": title,
            "severity": sev,
            "description": desc,
            "evidence": evidence,
            "cwe": cwe or "",
            "type": "url"
        })
    if progress_cb: progress_cb("Requesting target...")
    res = http_get(target_url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
    if res is None:
        add("Connection failed", "info", "Could not reach target URL.", "")
        return findings
    # Header checks
    missing = [h for h in SEC_HEADERS if h not in res.headers]
    if missing:
        add("Missing security headers", "medium",
            "Response is missing recommended security headers.",
            "Missing: " + ", ".join(missing), "CWE-693")
    # Interesting files
    for path in INTERESTING_PATHS:
        if stop_event and stop_event.is_set(): break
        test_url = target_url.rstrip("/") + path
        if progress_cb: progress_cb(f"Checking {path}")
        r = http_get(test_url)
        if r is not None and r.status_code < 400 and len(r.text) > 0:
            add("Interesting file exposed", "medium",
                f"Potentially sensitive path accessible: {path}",
                f"HTTP {r.status_code} at {test_url}", "CWE-540")
    # Reflected XSS (very naive)
    for p in XSS_PAYLOADS:
        if stop_event and stop_event.is_set(): break
        if progress_cb: progress_cb("Testing reflected XSS")
        test_url = build_url_with_param(target_url, "q", p)
        r = http_get(test_url)
        if r is not None and p in r.text:
            snippet = html.escape(p)
            add("Reflected XSS", "high",
                "Payload appears unencoded in the response. Verify manually.",
                f"Reflected payload: {snippet}", "CWE-79")
            break
    # SQLi (error-based)
    for p in SQLI_PAYLOADS:
        if stop_event and stop_event.is_set(): break
        if progress_cb: progress_cb("Testing SQLi errors")
        test_url = build_url_with_param(target_url, "id", p)
        r = http_get(test_url)
        if r is not None:
            body = r.text.lower()
            if any(sig in body for sig in DB_ERROR_SIGS):
                add("Possible SQL Injection (error-based)", "high",
                    "Database error strings detected after SQLi payload.",
                    f"Payload: {p}", "CWE-89")
                break
    return findings

def scan_code_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return [{
            "target": filepath,
            "title": "Read error",
            "severity": "info",
            "description": f"Could not read file: {e}",
            "evidence": "",
            "cwe": "",
            "type": "code"
        }]
    # Simple language hint
    ext = os.path.splitext(filepath)[1].lower().lstrip(".")
    lang = "python" if ext == "py" else ("js" if ext in ("js","jsx","ts","tsx") else ("php" if ext=="php" else "any"))
    for regex, hint, title, sev, rec in CODE_RULES:
        if hint != "any" and hint != lang: 
            continue
        for m in re.finditer(regex, content, flags=re.IGNORECASE):
            line_no = content.count("\n", 0, m.start()) + 1
            snippet = content[max(0, m.start()-60): m.end()+60].strip()
            findings.append({
                "target": filepath,
                "title": title,
                "severity": sev,
                "description": rec,
                "evidence": f"Line {line_no}: ...{snippet}...",
                "cwe": "",
                "type": "code"
            })
    return findings

def save_report(findings, outpath):
    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tool": APP_NAME,
        "version": VERSION,
        "findings": findings
    }
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return outpath

def save_report_html(findings, outpath):
    def esc(x): return html.escape(str(x))
    rows = []
    for f in findings:
        rows.append(f"""<tr>
            <td>{esc(f.get('severity',''))}</td>
            <td>{esc(f.get('title',''))}</td>
            <td>{esc(f.get('type',''))}</td>
            <td>{esc(f.get('target',''))}</td>
            <td>{esc(f.get('description',''))}</td>
            <td><pre>{esc(f.get('evidence',''))}</pre></td>
        </tr>""")
    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{APP_NAME} Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
h1 {{ margin-top: 0; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; vertical-align: top; }}
th {{ background: #f6f6f6; }}
.sev-high {{ color: #b00; font-weight: bold; }}
.sev-medium {{ color: #d2691e; font-weight: bold; }}
.sev-low {{ color: #777; }}
</style>
</head>
<body>
<h1>{APP_NAME} – Findings</h1>
<p>Generated at: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Type</th><th>Target</th><th>Description</th><th>Evidence</th></tr></thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="6">No findings</td></tr>'}
</tbody>
</table>
</body>
</html>"""
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return outpath

class App(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.pack(fill="both", expand=True)
        self.findings = []
        self.stop_event = threading.Event()
        self.queue = queue.Queue()
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        self.master.title(f"{APP_NAME} {VERSION}")
        # URL entry and buttons
        url_frame = ttk.LabelFrame(self, text="Scan a URL")
        url_frame.pack(fill="x", pady=(0,8))
        self.url_var = tk.StringVar()
        ttk.Entry(url_frame, textvariable=self.url_var).pack(side="left", fill="x", expand=True, padx=(8,8), pady=8)
        ttk.Button(url_frame, text="Scan URL", command=self.scan_url_clicked).pack(side="left", padx=(0,8), pady=8)
        # File selection
        file_frame = ttk.LabelFrame(self, text="Scan a Code File")
        file_frame.pack(fill="x", pady=(0,8))
        self.file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_var).pack(side="left", fill="x", expand=True, padx=(8,8), pady=8)
        ttk.Button(file_frame, text="Browse", command=self.pick_file).pack(side="left", padx=(0,8), pady=8)
        ttk.Button(file_frame, text="Scan File", command=self.scan_file_clicked).pack(side="left", padx=(0,8), pady=8)
        # Findings table
        table_frame = ttk.LabelFrame(self, text="Findings")
        table_frame.pack(fill="both", expand=True)
        cols = ("severity","title","type","target","description")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=150 if c!="description" else 280, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)
        # Buttons bottom
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Export JSON", command=self.export_json).pack(side="left", padx=4, pady=8)
        ttk.Button(btn_frame, text="Export HTML", command=self.export_html).pack(side="left", padx=4, pady=8)
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status_var).pack(fill="x")

    def add_findings(self, new_items):
        self.findings.extend(new_items)
        for f in new_items:
            self.tree.insert("", "end", values=(f["severity"], f["title"], f["type"], f["target"], f["description"]))

    def set_status(self, msg):
        self.status_var.set(msg)

    def pick_file(self):
        p = filedialog.askopenfilename(title="Select source code file",
                                       filetypes=[("All files","*.*"),("Python","*.py"),("JavaScript","*.js *.jsx *.ts *.tsx"),("PHP","*.php")])
        if p:
            self.file_var.set(p)

    def scan_url_clicked(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning(APP_NAME, "Please enter a URL (e.g., https://example.com).")
            return
        self.stop_event.clear()
        threading.Thread(target=self._scan_url_thread, args=(url,), daemon=True).start()

    def _scan_url_thread(self, url):
        self.queue.put(("status","Starting URL scan..."))
        items = scan_url(url, progress_cb=lambda m:self.queue.put(("status", m)), stop_event=self.stop_event)
        self.queue.put(("findings", items))
        self.queue.put(("status","URL scan finished."))

    def scan_file_clicked(self):
        path = self.file_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showwarning(APP_NAME, "Pick a valid file first.")
            return
        self.queue.put(("status","Scanning file..."))
        items = scan_code_file(path)
        self.add_findings(items)
        self.queue.put(("status","File scan finished."))

    def export_json(self):
        if not self.findings:
            messagebox.showinfo(APP_NAME, "No findings to export.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if not out: return
        save_report(self.findings, out)
        messagebox.showinfo(APP_NAME, f"Saved JSON report to:\n{out}")

    def export_html(self):
        if not self.findings:
            messagebox.showinfo(APP_NAME, "No findings to export.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if not out: return
        save_report_html(self.findings, out)
        messagebox.showinfo(APP_NAME, f"Saved HTML report to:\n{out}")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "status":
                    self.set_status(payload)
                elif kind == "findings":
                    self.add_findings(payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

def main():
    root = tk.Tk()
    style = ttk.Style()
    # Use default theme; keep it simple/portable
    app = App(root)
    root.geometry("1000x600")
    root.mainloop()

if __name__ == "__main__":
    main()
