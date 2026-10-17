# AI-Cybersecurity Assistant v2.5 (Enterprise Work Edition)

An enterprise-ready, AI-powered network security auditor, OSINT intelligence platform, and attack surface monitoring suite designed for security engineers, penetration testers, and SOC analysts. It combines `nmap` reconnaissance, deep HTTP security posture checks, subdomain mapping, multi-source OSINT (DNS, Whois, GeoIP, SSL/TLS), and Google Gemini AI to produce structured threat assessments, automated hardening scripts, and client-ready audit reports.

---

## 🚀 Key Features

- **Enterprise Scan Engine & Target Normalization**:
  - **First-Class Domain Name & URL Support**: Enter domain names (`scanme.nmap.org`), full URLs (`https://example.com/login`), hostnames with custom ports (`example.com:8443`), or raw IPs. Targets are automatically normalized, resolving clean hostnames and extracting custom ports.
  - **Work Scan Profiles**: Fast Recon (`-F`), Deep Service & OS (`-sV -O`), Web App Audit (`http-*`), Full Stealth SYN (`-sS -Pn`), Vulnerability Audit (`--script vuln`), and Full 65,535 Port Sweep (`-p-`).
  - **Custom Port Range Selector**: Specify exact ports or ranges (e.g. `80,443`, `1-1024`, `22,3389,8080`) safely without limitation.
- **Domain Intelligence & DNS Profile Engine**:
  - Automatically resolves IPv4 (`A`), IPv6 (`AAAA`), Canonical aliases (`CNAME`), Mail Servers with priorities (`MX`), Name Servers (`NS`), Text verification records (`TXT`), and Zone Start of Authority (`SOA`).
- **Email Security & Anti-Spoofing Assessment**:
  - Evaluates **SPF** (`v=spf1 ...`) records, identifying strictness (`-all` HardFail, `~all` SoftFail, `?all` Neutral, `+all` Critical Vulnerability).
  - Evaluates **DMARC** (`_dmarc.<domain>`) records, parsing policy (`p=reject`, `p=quarantine`, `p=none`), percentage coverage (`pct=`), and aggregate forensic report mailboxes (`rua=`).
  - Automatically rates domain spoofing exposure (`PROTECTED`, `PARTIALLY PROTECTED`, or `VULNERABLE TO SPOOFING`).
- **Cloud / CDN & Reverse Proxy Detection**:
  - Identifies whether the domain is behind Cloudflare, AWS CloudFront, Akamai, Fastly, Azure Front Door, or Imperva Incapsula via CNAME and HTTP headers.
  - Notifies analysts and Gemini AI whether port scans reflect edge proxy nodes rather than the origin server.
- **Deep SSL/TLS Certificate Audit**:
  - Connects using SNI hostname and extracts Certificate Authority (Issuer), Subject, Subject Alternative Names (SANs), TLS protocol versions, cipher suites, and expiry date with an automated **days remaining** countdown.
- **HTTP Security Headers & Web Posture Audit**:
  - Automatically evaluates HTTP/HTTPS web endpoints on targets for essential security headers: `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
  - Computes a security rating (Grades A-F) with color-coded pass/fail badges.
  - Flags sensitive banner leaks (`Server`, `X-Powered-By`) and inspects Cookie security flags (`Secure`, `HttpOnly`, `SameSite`).
- **Subdomain Reconnaissance & Attack Surface Mapping**:
  - Maps corporate and infrastructure subdomains (`api`, `dev`, `staging`, `vpn`, `app`, `admin`, `portal`, `auth`, `corp`, `cdn`, `beta`, `sso`, `gitlab`, `jenkins`, `dashboard`, `internal`, `db`, `smtp`, `origin`, `m`, etc.) with resolved IP addresses.
  - 1-click **"Scan Target"** button on discovered subdomains.
- **Automated Remediation & Hardening Script Generator**:
  - Instantly generates production-ready, battle-tested **Bash** (UFW, iptables, sysctl, SSH hardening) or **PowerShell** (NetFirewall rules) hardening scripts tailored specifically to the open ports and vulnerabilities found.
  - 1-click **Copy** and **Download Script** (`.sh` or `.ps1`).
- **Client / Engagement Tagging & Analyst Notes**:
  - Tag scans by organization, project, or audit engagement (e.g. `Acme Corp - Q3`, `Internal Audit`).
  - Add persistent auditor commentary, false positive documentation, or verification notes stored in the database.
  - Quick-search filter by target or client tag in the scan history.
- **Dual Work Interfaces**: 
  - **Modern Cyber Dashboard** (`app.py`): Glassmorphism responsive UI with real-time feedback, Domain Posture cards, Markdown report rendering, interactive chat advisor, and export to PDF/JSON.
  - **Interactive Terminal Console** (`cli.py`): Rich CLI with colored port tables, Domain & DNS profile tables, Email Anti-Spoofing tables, SSL/TLS certificate tables, HTTP audit tables, subdomain tables, and instant domain deep-dive option `[4]`.
- **LAN & Subnet Sweeper**: Discover live hosts across subnets or CIDR ranges (`nmap -sn`) with hardware vendor detection.
- **Continuous Monitoring & Attack Surface Diffing**:
  - Scheduled target monitoring with port change detection.
  - Instant **Discord/Slack Webhook alerts** when changes occur.

---

## 🛠️ Automated Setup in WSL (Recommended)

Because the project is located on your Windows drive (`C:..`), it is automatically mounted in WSL Ubuntu at:
```bash
/mnt/c..
```

### 1-Click Automated Setup
Inside your WSL terminal, navigate to the folder and run:
```bash
cd ..
chmod +x setup_wsl.sh
./setup_wsl.sh
```
This automatically:
1. Installs `nmap`, `python3`, `python3-venv`, and system dependencies via `apt-get`.
2. Creates and activates the Linux virtual environment (`.venv_wsl`).
3. Installs all Python dependencies.
4. Executes the automated test suite (`python -m unittest tests/test_suite.py`) to verify everything is working.

---

## 💻 Running the Assistant in WSL

### 🌐 Web Dashboard
```bash
source .venv_wsl/bin/activate
python app.py
```
Open your browser on Windows and navigate to:
👉 **[http://127.0.0.1:5001](http://127.0.0.1:5001)**

### ⌨️ Terminal CLI
```bash
source .venv_wsl/bin/activate
python cli.py
```

---

## 📁 Project Structure

```
AI_Assistant/
├── .env                 # Environment variables (GEMINI_API_KEY)
├── app.py               # Flask web server, REST API, & APScheduler cron jobs
├── cli.py               # Rich interactive command-line interface
├── db.py                # SQLite database management (history, diffs, watchlists)
├── utils.py             # Reconnaissance engine (Nmap, OSINT, AI, Subnet sweeper)
├── templates/
│   └── index.html       # Single-page web dashboard (Tailwind, Marked.js, html2pdf)
├── pyproject.toml       # Project configuration and dependencies
└── README.md            # Documentation
```
