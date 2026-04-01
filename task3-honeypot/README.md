#  Task 3: Deception-Based Security Mechanism (Honeypot)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1.3-black?style=flat-square&logo=flask)
![Type](https://img.shields.io/badge/Type-Honeypot-red?style=flat-square)
![Detection](https://img.shields.io/badge/Detects-Brute%20Force-orange?style=flat-square)

---

##  What This Does

A **fake admin login portal** that looks like a real corporate infrastructure system but is really just a trap. Any time someone visits a page, tries to log in, or accesses it more than once, it is seen as suspicious and logged with full forensic detail right away.

This is the same concept used by:
-  **Enterprise security teams** for threat intelligence
-  **The Honeynet Project** for attack research
-  **Cloud providers** for detecting network scanning
-  **Government agencies** for early intrusion detection

---

##  How It Works

```
Attacker finds the portal
         ↓
Tries to log in with any credentials
         ↓
System captures: IP, timestamp, username, password, browser info
         ↓
Alert written to alerts.log and alerts.json
         ↓
After 5 attempts from same IP → BRUTE_FORCE_DETECTED
         ↓
Dashboard shows all events in real time
```

**Core principle:** Since no legitimate user should ever visit this portal, **any interaction at all is suspicious by definition.**

---

##  File Structure

```
task3-honeypot/
│
├── templates/
│ └── login.html          # Fake admin portal UI
│
├── README.md             # Documentation
│
└── app.py                # Flask backend (routing, detection logic)
> Note: Log files (`alerts.log`, `alerts.json`) are generated dynamically at runtime and are not included in the repository.

```

---

##  How to Run

**Install Flask (if not already installed):**
```bash
pip install flask
```

**Start the honeypot:**
```bash
cd task3-honeypot
python app.py
```

**Open in browser:**
| URL | What it shows |
|-----|---------------|
| `http://127.0.0.1:5000/login` | Fake login portal (the trap) |
| `http://127.0.0.1:5000/honeypot-dashboard` | Alert dashboard (your view) |

---

##  The Fake Login Portal

The portal is designed to look like a real corporate system:

- **Name:** SecureNet Infrastructure Management System
- **Live UTC clock** in the header
- **Animated glowing logo** with pulse effect
- **Unique session ID** generated on each visit
- **TLS 1.3 SECURED** badge
- **Node identifier** (SN-CORE-01)
- **Dark terminal aesthetic** with green-on-black colour scheme

> The more convincing the portal looks, the more likely an attacker is to engage with it, giving the system more intelligence to collect.

---

##  What Gets Captured

### Page Visit Event
```
[ALERT]  2026-03-31 03:44:35
Event  : PAGE_VISIT
IP        : 127.0.0.1
Path      : /login
UserAgent : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
Method    : GET
```

### Login Attempt Event
```
[ALERT]  2026-03-31 03:47:05
Event  : LOGIN_ATTEMPT
IP        : 127.0.0.1
Username  : admin
Password  : admin123
UserAgent : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
```

### Brute Force Detection
```
[ALERT]  2026-03-31 03:49:12
Event  : BRUTE_FORCE_DETECTED
IP        : 127.0.0.1
Count     : 5
```

---

##  Alert Dashboard

Visit `http://127.0.0.1:5000/honeypot-dashboard` to see:

- **Statistics cards** — Total Events, Login Attempts, Page Visits, Brute Force count
- **Colour-coded event table** — Green for visits, Orange for attempts, Red for brute force
- **Full details** — timestamp, IP, credentials tried, browser fingerprint
- **Reverse chronological** order — newest events first

---

##  Key Design Decisions

**Why always deny access?**
There are no valid credentials, this is a trap. Always denying prevents automated tools from completing their attack flow and alerts human attackers that their activity is being recorded.

**Why log to both `.log` and `.json`?**
The `.log` file is human-readable for manual review. The `.json` file is machine-parseable for integration with other security tools or further analysis.

**Why capture passwords in the honeypot log?**
This is intentional and standard honeypot practice. Attackers often reuse passwords across systems. Capturing attempted credentials provides threat intelligence about common attack patterns and potentially compromised credential lists.

**Why was the UI designed so carefully?**
A poorly designed fake page would be ignored. A convincing-looking portal attracts real interaction, generating more useful threat intelligence.

---

##  Limitations

- Runs locally, all IPs show as `127.0.0.1` (real deployment on cloud shows actual attacker IPs)
- No real-time email/SMS alerts (would be added in production)
- Brute force uses total count, not time-windowed count
- No IP geolocation
- The dashboard is currently publicly accessible at: /honeypot-dashboard. This means anyone who discovers the route can view all captured events and logs. To solve this we can implement **Ip Whitelisting** or also a **secret token** in the URL to allow only authorized user to access it eg: Admin or Security Team

---

