# 🔐 Automated Web Vulnerability Scanner (AWVS)

> **Final Year Project — Cybersecurity / Computer Science**
> A full-stack Python web application for automated web security vulnerability assessment.

---

## 📋 Overview

AWVS is a deployable, multi-module web vulnerability scanner built with:
- **Backend**: Python 3.11, Flask, SQLAlchemy, SQLite
- **Scanner Engine**: Custom BFS Crawler + XSS, SQLi, CSRF, Header, Open Redirect detectors
- **Reporting**: ReportLab PDF + Styled HTML reports
- **Frontend**: Premium dark-mode UI with real-time scan progress

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────┐
│         Presentation Layer (Flask)          │
│  Web UI · Real-time polling · Auth · API   │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│          Core Engine Layer                  │
│  ┌──────────────┐  ┌──────────────────────┐ │
│  │ BFS Crawler  │→ │   URL / Form Queue   │ │
│  └──────┬───────┘  └──────────────────────┘ │
│         ▼                                   │
│  ┌──────────────────────────────────────┐   │
│  │     Vulnerability Scanner Modules    │   │
│  │  XSS · SQLi · CSRF · Headers · Redir│   │
│  └──────────────────────────────────────┘   │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│              Data Layer (SQLite)            │
│  USER · SCAN · RECON · CRAWLED · VULN      │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│         Reporting Layer (ReportLab)         │
│         PDF + HTML Executive Reports        │
└─────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
Automated Web Vulnerability Scanner/
├── app.py                    # Flask application factory
├── config.py                 # Configuration (env vars)
├── database.py               # SQLAlchemy ORM models
├── run.py                    # Entry point
├── requirements.txt          # Dependencies
├── .env.example              # Environment template
├── Dockerfile                # Docker build
├── docker-compose.yml        # Docker Compose
├── test_target_app.py        # Deliberately vulnerable test app
│
├── scanner/
│   ├── __init__.py
│   ├── recon.py              # DNS, port scan, fingerprinting
│   ├── crawler.py            # BFS web crawler
│   ├── engine.py             # Vulnerability detection engine
│   ├── report_gen.py         # PDF + HTML report generator
│   └── scan_controller.py   # Orchestration + threading
│
├── routes/
│   ├── auth.py               # Login, register, logout
│   ├── scan.py               # Scan CRUD + API endpoints
│   └── report.py             # Report download
│
├── templates/
│   ├── layout.html           # Base layout with sidebar
│   ├── dashboard.html        # Main dashboard
│   ├── auth/
│   │   ├── login.html
│   │   └── register.html
│   └── scan/
│       ├── new_scan.html     # Scan configuration
│       ├── scan_detail.html  # Real-time scan monitoring
│       └── scan_list.html    # Scan history
│
└── static/
    ├── css/style.css         # Premium dark-mode design system
    └── js/main.js            # Live polling + UI interactions
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+ installed
- pip

### 1. Install Dependencies

```bash
cd "d:\Automated Web Vernablity Scanner"
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
copy .env.example .env
# Edit .env if needed (default settings work out of the box)
```

### 3. Run the Application

```bash
python run.py
```

Open your browser at: **http://127.0.0.1:5000**

### 4. Register & Login
- Go to `/register` → create your account
- Login and start scanning!

---

## 🧪 Testing with the Vulnerable Test App

To test the scanner against a controlled vulnerable application:

**Terminal 1 — Start test target:**
```bash
python test_target_app.py
# Runs on http://127.0.0.1:8888
```

**Terminal 2 — Start AWVS:**
```bash
python run.py
# Runs on http://127.0.0.1:5000
```

Then in AWVS, create a new scan targeting `http://127.0.0.1:8888`.

The scanner should detect: Reflected XSS, SQL Error Disclosure, Missing CSRF Token, Open Redirect, Missing Security Headers.

---

## 🐳 Docker Deployment

```bash
docker-compose up --build -d
```

Access at: **http://localhost:5000**

---

## 🛡️ Vulnerability Modules

| Module | Severity | Description |
|--------|----------|-------------|
| Reflected XSS | High | Tests GET/POST inputs for reflected script injection |
| SQL Injection | High | Error-based SQLi via boundary characters |
| CSRF | Medium | Detects POST forms missing CSRF tokens |
| Open Redirect | Medium | Tests redirect parameters for unvalidated external URLs |
| Security Headers | High/Med/Low | Evaluates CSP, HSTS, X-Frame-Options, etc. |
| Sensitive Disclosure | High/Med | Detects API keys, stack traces, passwords in responses |

---

## 📊 Database Schema

| Table | Description |
|-------|-------------|
| USER | Authentication and roles |
| SCAN | Scan configuration and lifecycle |
| RECON_RESULT | IP, open ports, tech stack |
| CRAWLED_PAGE | Discovered URLs and form structures |
| VULNERABILITY | Detected issues with evidence |
| REPORT | Generated report file references |

---

## ⚠️ Legal Disclaimer

This tool is developed for **academic research** and **authorized security testing** purposes only.
Only use it against web applications you own or have explicit written permission to test.
Unauthorized scanning is illegal under computer misuse laws in most jurisdictions.

---

## 👨‍💻 Academic Project Information

- **Project Type**: Final Year Project — B.E. / B.Tech Computer Science / Cybersecurity
- **Architecture**: 4-layer (Presentation → Engine → Data → Reporting)
- **Tech Stack**: Python, Flask, SQLAlchemy, SQLite, ReportLab, BeautifulSoup4
- **Scanner Pattern**: BFS Crawl → Passive/Active Detection → PDF Report

---

*Built systematically following OWASP testing guidelines.*
