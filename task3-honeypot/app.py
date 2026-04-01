"""
Task 3: Deception-Based Security Mechanism - Honeypot System
============================================================
This system creates a fake admin login portal to detect and log
any unauthorized access attempts. Every interaction is treated
as suspicious since this portal is not meant for real users.
"""

from flask import Flask, render_template, request, flash, redirect, url_for
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "honeypot-secret-key-2024"


# FILE PATHS

ALERTS_LOG   = "alerts.log"       # human-readable log
ALERTS_JSON  = "alerts.json"      # structured JSON log


# HELPER: load existing JSON alerts

def load_alerts():
    if os.path.exists(ALERTS_JSON):
        with open(ALERTS_JSON, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []


# HELPER: write a new alert entry to both log files

def log_alert(event_type, details: dict):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---------- plain text log ----------
    with open(ALERTS_LOG, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"[ALERT]  {timestamp}\n")
        f.write(f"Event  : {event_type}\n")
        for k, v in details.items():
            f.write(f"{k:<10}: {v}\n")
        f.write(f"{'='*60}\n")

    # ---------- JSON log ----------
    alerts = load_alerts()
    alerts.append({
        "timestamp": timestamp,
        "event_type": event_type,
        **details
    })
    with open(ALERTS_JSON, "w") as f:
        json.dump(alerts, f, indent=2)

    # ---------- console output ----------
    print(f"\n🚨 HONEYPOT ALERT [{timestamp}]")
    print(f"   Event : {event_type}")
    for k, v in details.items():
        print(f"   {k:<10}: {v}")


# ROUTE: fake login page (GET)

@app.route("/")
@app.route("/login")
def login_page():
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "Unknown")

    # Every page visit is suspicious — log it
    log_alert("PAGE_VISIT", {
        "IP"        : ip,
        "Path"      : request.path,
        "UserAgent" : ua,
        "Method"    : "GET"
    })

    return render_template("login.html")


# ROUTE: fake login form submission (POST)

@app.route("/login", methods=["POST"])
def login_submit():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    ip       = request.remote_addr
    ua       = request.headers.get("User-Agent", "Unknown")

    # Log the credential attempt — this is the core honeypot event
    log_alert("LOGIN_ATTEMPT", {
        "IP"        : ip,
        "Username"  : username,
        "Password"  : password,   # intentionally captured (honeypot purpose)
        "UserAgent" : ua
    })

    # Classify the attempt
    if _is_brute_force(ip):
        log_alert("BRUTE_FORCE_DETECTED", {
            "IP"     : ip,
            "Count"  : _attempt_count(ip)
        })
        flash("Too many attempts. Session locked.", "error")
    else:
        # Always deny — there is no valid credential
        flash("Access denied. Unauthorized activity has been recorded.", "warning")

    return redirect(url_for("login_page"))


# ROUTE: view all alerts (admin dashboard — for demo)

@app.route("/honeypot-dashboard")
def dashboard():
    alerts = load_alerts()
    total        = len(alerts)
    login_tries  = [a for a in alerts if a["event_type"] == "LOGIN_ATTEMPT"]
    page_visits  = [a for a in alerts if a["event_type"] == "PAGE_VISIT"]
    brute_force  = [a for a in alerts if a["event_type"] == "BRUTE_FORCE_DETECTED"]

    html = f"""
    <!DOCTYPE html><html><head>
    <title>Honeypot Dashboard</title>
    <style>
      body{{font-family:monospace;background:#050a0e;color:#a8c8d8;padding:30px}}
      h1{{color:#00ff88;letter-spacing:3px}}
      h2{{color:#00cc66;margin-top:30px;font-size:14px;letter-spacing:2px}}
      table{{border-collapse:collapse;width:100%;margin-top:10px;font-size:12px}}
      th{{background:#0a1520;color:#00ff88;padding:8px 12px;text-align:left;border:1px solid #0f2a3a}}
      td{{padding:8px 12px;border:1px solid #0f2a3a}}
      tr:hover{{background:#0a1520}}
      .badge{{padding:2px 8px;border-radius:3px;font-size:11px}}
      .LOGIN_ATTEMPT{{background:rgba(255,170,0,0.15);color:#ffaa00}}
      .PAGE_VISIT{{background:rgba(0,255,136,0.1);color:#00ff88}}
      .BRUTE_FORCE_DETECTED{{background:rgba(255,0,60,0.15);color:#ff003c}}
      .stat{{display:inline-block;background:#0a1520;border:1px solid #0f2a3a;
             padding:14px 24px;margin:6px;min-width:120px;text-align:center}}
      .stat-num{{font-size:28px;color:#00ff88}}
      .stat-label{{font-size:11px;color:#a8c8d8;letter-spacing:1px}}
    </style></head><body>
    <h1>🍯 HONEYPOT DASHBOARD</h1>
    <p style="color:#666;font-size:12px">All interactions logged below — none of these users should be here.</p>

    <div style="margin:20px 0">
      <div class="stat"><div class="stat-num">{total}</div><div class="stat-label">TOTAL EVENTS</div></div>
      <div class="stat"><div class="stat-num">{len(login_tries)}</div><div class="stat-label">LOGIN ATTEMPTS</div></div>
      <div class="stat"><div class="stat-num">{len(page_visits)}</div><div class="stat-label">PAGE VISITS</div></div>
      <div class="stat"><div class="stat-num" style="color:#ff003c">{len(brute_force)}</div><div class="stat-label">BRUTE FORCE</div></div>
    </div>

    <h2>// ALL ALERT EVENTS</h2>
    <table>
      <tr><th>Timestamp</th><th>Event</th><th>IP</th><th>Details</th></tr>
    """

    for a in reversed(alerts):
        event   = a.get("event_type", "")
        ts      = a.get("timestamp", "")
        ip_addr = a.get("IP", "-")
        details = {k: v for k, v in a.items()
                   if k not in ("event_type", "timestamp", "IP")}
        detail_str = " | ".join(f"{k}: {v}" for k, v in details.items())
        html += f"""
        <tr>
          <td>{ts}</td>
          <td><span class="badge {event}">{event}</span></td>
          <td>{ip_addr}</td>
          <td style="color:#667">{detail_str}</td>
        </tr>"""

    html += "</table></body></html>"
    return html


# BRUTE-FORCE HELPERS

def _attempt_count(ip: str) -> int:
    alerts = load_alerts()
    return sum(1 for a in alerts
               if a.get("event_type") == "LOGIN_ATTEMPT" and a.get("IP") == ip)

def _is_brute_force(ip: str, threshold: int = 5) -> bool:
    return _attempt_count(ip) >= threshold


# ENTRY POINT
if __name__ == "__main__":
    print("=" * 60)
    print("  🍯 HONEYPOT SYSTEM ACTIVE")
    print("  Fake login portal : http://127.0.0.1:5000/login")
    print("  Alert dashboard   : http://127.0.0.1:5000/honeypot-dashboard")
    print("  Logs written to   : alerts.log  &  alerts.json")
    print("=" * 60)
    app.run(debug=True, port=5000)