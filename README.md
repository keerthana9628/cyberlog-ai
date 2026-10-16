# 🛡️ CYBERLOG AI - Intelligent Cybersecurity Log Analysis & Threat Detection

An **educational** web app: upload a security log, click **Analyze**, and get rule-based + AI (Isolation Forest) threat detection in a SOC-style dashboard. It only reads uploaded logs. It never scans, attacks or executes anything.

## How this project works (simple version)
1. You upload a log file in the browser.
2. The **Java backend** reads each line and turns it into a standard record (time, IP, user, URL, status, port, login success/fail).
3. **Rules** look for known patterns (many failed logins, many ports, restricted URLs, bursts).
4. The backend sends per-IP numbers (requests, failures, ports...) to the **Python AI service**, where an **Isolation Forest** finds IPs that behave very differently from a normal profile.
5. A **Calculated Risk Score** (0-100) is built from rule base + frequency + AI bonus, and a plain-English reason is generated from the real numbers.
6. Everything is saved in **SQLite** and shown with charts, tables, filters and a downloadable report.

## Architecture
Browser (HTML/CSS/JS + Chart.js) → Spring Boot REST API → LogParser → Detector (rules) → Flask AI service (Isolation Forest) → Risk scoring → SQLite → Dashboard/Report

## Folder structure
```
cyberlog-ai/
├── frontend/      index.html, css/style.css, js/app.js
├── backend/       pom.xml, src/main/java/com/cyberlog/*.java, resources/ (application.properties, schema.sql)
├── ai-service/    app.py, requirements.txt
├── sample-data/   5 synthetic logs + generate_samples.py
├── database/      cyberlog.db is created here automatically
├── start-ai.bat, start-backend.bat
```

## Setup on Windows (one time)
Open **PowerShell** and run:
```powershell
winget install EclipseAdoptium.Temurin.17.JDK
winget install Apache.Maven
winget install Python.Python.3.11
```
Close and reopen PowerShell, then check: `java -version`, `mvn -v`, `python --version`.
(If `winget` is missing, install Temurin JDK 17, Maven and Python 3.11 from their websites; tick "Add Python to PATH".)

## Run locally (two terminals, in the `cyberlog-ai` folder)
**Terminal 1: AI service** → `.\start-ai.bat` (wait for "Running on http://127.0.0.1:5000")
**Terminal 2: backend + website** → `.\start-backend.bat` (first run downloads libraries; wait for "Started CyberLogApplication")

Open **http://localhost:8080**. Demo: *Upload Logs* → choose `sample-data/sample_mixed_attack.log` → **ANALYZE LOG** → explore Dashboard, Threat Detection (click a row), AI Analysis, IP Analysis, Log Explorer, Reports.
If the AI service is not running, the app still works (rules only) and tells you.

## Configuration (`backend/src/main/resources/application.properties`)
`cyberlog.bf.max-fails` / `bf.window-sec` (default 5 fails in 60 s), `cyberlog.scan.min-ports` / `scan.window-sec` (default 10 ports in 60 s), `cyberlog.ai.url`, upload limit 10 MB.

## Supported log formats
Apache/Nginx access log · SSH `auth.log` · firewall lines (`SRC=… DPT=…`) · CSV with a header (columns like `timestamp,ip,user,method,url,status,port,action,event_id`; Windows event 4625 = failed login, 4624 = success) · JSON (array or one object per line).

## API
| Method | Path | Purpose |
|---|---|---|
| POST | /api/logs/upload | multipart `file` → session info (name, size, records, format) |
| POST | /api/logs/analyze | `{"sessionId":1}` → run analysis |
| GET | /api/dashboard | totals, chart data, AI summary |
| GET | /api/threats?severity=&type=&ip=&q=&from=&to= | filtered threats |
| GET | /api/threats/{id} | one threat with score factors |
| GET | /api/ip-analysis | per-IP statistics |
| GET | /api/logs?q=&ip=&severity=&type=&from=&to= | raw log explorer (max 500) |
| GET | /api/reports | Markdown report |
| GET | /api/health | status |

Errors return `{"error":"friendly message"}` with 400 / 404 / 413 / 500.

## Detection rules
Brute Force (failed logins in window) · Port Scan (distinct ports in window) · Request Spike (a minute ≥ max(30, 5× average)) · Unauthorized Access (≥5 hits on /admin, /private, /etc/passwd, /.env…) · Suspicious Login (success after ≥5 failures in 10 min). 401/403/404 alone are never treated as attacks.

## AI methodology
Per-IP features: requests, failed/successful logins, unique ports, unique URLs, requests/minute, error rate, failure rate. Scikit-learn `IsolationForest` is fitted on a small synthetic "normal" baseline plus the uploaded data; IPs with a clearly negative decision value are flagged. Explanations compare features to the baseline. **Educational model, not a certified security system.**

## Risk score ("Calculated Risk Score")
Rule base (25-55 by type) + frequency (0-25) + AI anomaly (0-20), capped at 100. 0-25 LOW, 26-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL. A transparent heuristic, not validated.

## Database (SQLite, auto-created)
`sessions` (uploads/results), `logs` (parsed events), `threats`, `ip_statistics` (incl. AI result per IP).

## Deployment (free)
- **AI service → Render** (Web Service, root `ai-service`, build `pip install -r requirements.txt`, start `gunicorn app:app`).
- **Backend → Render** (Docker needed for Java: add a `Dockerfile` using a Maven build image + JRE 17 and run `java -jar target/cyberlog-backend-1.0.0.jar`). Set env vars `AI_URL=https://<your-ai>.onrender.com` and `DB_PATH=/tmp/cyberlog.db`. The backend also serves the frontend if `FRONTEND_DIR` points to the frontend folder.
- **Frontend → Netlify/Vercel** (publish the `frontend` folder) and add before `js/app.js` in `index.html`: `<script>window.API_BASE="https://<your-backend>.onrender.com";</script>`
- **SQLite on free Render:** the disk is temporary, so data resets on restart/redeploy and sessions are lost. That's fine for demos. For permanent data use a free Postgres (Neon/Supabase) and swap the JDBC driver. Free services also "sleep" and take ~50 s to wake: open `/api/health` and the AI `/health` first.

## Limitations
Educational heuristics and model; no real-time streaming; naive CSV splitting (no quoted commas); SSH logs without a year assume the current year; uploaded sessions are held in memory until the backend restarts; no user login.

## Future enhancements
Login with hashed passwords, real-time log tailing, GeoIP, more formats (Windows EVTX), PDF reports, Postgres.
