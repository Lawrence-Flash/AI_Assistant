# AI Cybersecurity Assistant

**Author:** [Lawrence Tshabalala](https://github.com/Lawrence-Flash)

A local lab tool for authorized network and domain checks. It runs Nmap, collects DNS, WHOIS, GeoIP, SPF/DMARC, TLS, and HTTP-header data, stores the results in SQLite, and can ask Google Gemini to write a structured summary. The same API backs a browser dashboard, a terminal menu, and a small Android client.

The Python package version in `pyproject.toml` is **1.0.0**. Python **3.11+** is required.

Use it only on systems you own or have written permission to test. `scanme.nmap.org` is Nmap's public demonstration host and is the safe example used below.

## What it does

One scan from the dashboard, CLI, or `POST /scan` does the following:

1. Normalizes the target. A URL, a `host:port` value, or a bracketed IPv6 address is reduced to a host, and an explicit port is kept for Nmap.
2. Rejects strings that are not an IP address, `localhost`, or a domain name.
3. Runs Nmap with one of six profiles, or with a caller-supplied port list.
4. Collects OSINT for that host (details below).
5. Sends the Nmap text and the OSINT JSON to Gemini, when `GEMINI_API_KEY` is set.
6. Reads a risk label from the model text (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFORMATIONAL`) and stores the scan.

Without an API key, Nmap and the local checks still run. The AI field then contains the message that no key was found.

## Features

### Nmap profiles

`run_nmap_scan` in `utils.py` builds the argument list. A custom port list replaces `-F` or an existing `-p` value when it matches `80`, `80,443`, `1-1024`, or `22,80-90,443` style input. Ports must be between 1 and 65535.

| Profile | Flags when the process is root | Flags otherwise |
| --- | --- | --- |
| `fast` (default) | `-F` | `-F` |
| `advanced` | `-sV -O -T4` | `-sV --version-all -T4` |
| `web` | `-sV -p 80,443,8080,8443,3000,5000,8000 --script http-title,http-headers,http-methods,ssl-cert` | same |
| `stealth` | `-sS -sV -Pn -T4 --top-ports 1000` | `-sT` instead of `-sS` |
| `vuln` | `-sV -T4 --script vuln` | same |
| `full` | `-p- -T4 -sV` | same |

If Nmap exits with "requires root privileges", the function retries once: it drops `-O` and replaces `-sS` with `-sT`. Each Nmap invocation has a 600 second timeout. Host discovery (`nmap -sn`) has a 120 second timeout.

Host discovery parses "Nmap scan report" lines, latency, and `MAC Address` lines (address and vendor text when Nmap prints them). It accepts a CIDR such as `192.168.1.0/24` or a single valid host.

### Domain and IP intelligence

For a domain, `run_osint` gathers:

- WHOIS via `python-whois` (registrar, created date, expiry, emails, org when the library returns them).
- DNS `A`, `AAAA`, `CNAME`, `MX` (with preference), `NS`, `TXT`, and `SOA` via dnspython. Resolver lifetime is 2.5 seconds.
- SPF and DMARC (see below).
- CDN / reverse-proxy hints from CNAME text.
- A TLS certificate read on port 443 using the hostname as SNI.
- GeoIP for the first IPv4 answer, from `http://ip-api.com/json/...`.
- An HTTP header audit.
- Subdomain `A` lookups against a fixed wordlist.

For an IP address it tries `A`, `MX`, `NS`, `TXT`, and a PTR lookup, plus GeoIP. Private and loopback addresses skip the GeoIP request and are labeled as local.

`POST /domain_audit` runs this OSINT path and returns it. It does not run Nmap.

### SPF and DMARC

`analyze_email_security` reads the domain's TXT records and `_dmarc.<domain>`:

- SPF `-all` and `~all` are `PASS`. `?all` is `WEAK`. `+all` is `CRITICAL`. A record with no `all` qualifier is `WARNING`. No record is `MISSING`.
- DMARC `p=reject` and `p=quarantine` are `PASS`. `p=none` is `WARNING`. The parser also keeps `pct` and `rua`.
- Combined label: `PROTECTED` when both are `PASS`, `PARTIALLY PROTECTED` when SPF passes and DMARC is `WARNING` or `MISSING`, otherwise `VULNERABLE`.

### TLS certificate check

`get_detailed_ssl_cert` connects to port 443 and records issuer, subject CN, up to 15 DNS subject-alternative names, not-before, not-after, TLS version, and cipher. Remaining lifetime is computed from the certificate date. Status is `ACTIVE`, `EXPIRING_SOON` (30 days or fewer), `EXPIRED`, `UNTRUSTED_OR_EXPIRED`, or `UNAVAILABLE`.

A second helper, `get_ssl_cert_info`, records only TLS version, cipher name, and whether a certificate was presented. Domain OSINT stores the detailed certificate and this short probe. IP OSINT stores the short probe.

### HTTP header audit

`analyze_http_security` strips any explicit port from the host, then requests `https://<host>` and, if that fails, `http://<host>` (3 second timeout, redirects followed, certificate verification disabled). It checks:

- `Strict-Transport-Security` (25)
- `Content-Security-Policy` (25)
- `X-Frame-Options` (15)
- `X-Content-Type-Options: nosniff` (15)
- `Referrer-Policy` (10)
- `Permissions-Policy` (10)

The score maps to a grade: A at 85 or above, B at 70, C at 50, D at 30, otherwise F. The audit also records `Server` and `X-Powered-By` when those headers are present, and notes the `Secure`, `HttpOnly`, and `SameSite` flags on cookies in the response.

### Subdomain wordlist

`enumerate_subdomains` resolves `A` records for 32 prefixes: `www`, `api`, `mail`, `dev`, `staging`, `admin`, `vpn`, `app`, `portal`, `auth`, `corp`, `cdn`, `test`, `remote`, `gateway`, `cloud`, `secure`, `status`, `beta`, `sso`, `gitlab`, `jenkins`, `dashboard`, `internal`, `db`, `smtp`, `stage`, `origin`, `m`, `docs`, `support`, `mx`. IP addresses return an empty list. Each lookup uses a 1.5 second lifetime.

### CDN name matching

`detect_cdn_proxy` flags a target when a CNAME contains `cloudflare`, `cloudfront.net`, `akamai`, `edgekey.net`, `fastly`, `azureedge.net`, `azurefd.net`, `incapdns.net`, or `sucuri`. It also recognizes the header names `cf-ray`, `x-amz-cf-id`, `x-fastly-request-id`, and `x-azure-ref`, and a `Server` header that contains `cloudflare`. During a normal OSINT run the CNAME list is what gets passed in. A follow-up call passes the header-audit map, whose keys are the six security-header names above, so that follow-up does not see the raw CDN headers.

### Gemini summaries, chat, and hardening text

`call_gemini_with_fallback` tries, in order:

1. `GEMINI_MODEL` if set, otherwise `gemini-3.6-flash`
2. `gemini-3.5-flash-lite`
3. `gemini-flash-latest`
4. `gemini-pro-latest`

Scan analysis asks the model for a markdown report with a `Risk Level:` line, an executive summary, exposed services, domain and web posture, recommendations, and a remediation checklist. `extract_risk_score` reads that line. If it is missing, a few keyword checks can still return `CRITICAL`, `HIGH`, or `MEDIUM`; otherwise the stored level is `LOW`.

`POST /chat` answers one message with optional prior turns. The web UI and the CLI send `{role, content}` history, which is the shape `chat_with_ai` reads. The Android client sends the new message with an empty history list.

`POST /remediation` asks the model for a Bash script (`platform=linux`) or a PowerShell script (`platform=windows`) from the scan text. Fenced code is unwrapped when the model returns it. With no API key, every platform receives the same short Bash stub: UFW default deny incoming, default allow outgoing, allow TCP/22, then `ufw enable`. The repository never executes that text.

`POST /audit_config` is meant to send a pasted config snippet to `audit_local_config`. The route calls that function, and the function is defined in `utils.py`, but `app.py` does not import it. Calling the route raises `NameError` until that import is added.

### CVE keyword search

`POST /search_cve` queries `https://cve.circl.lu/api/search/<keyword>` with a 10 second timeout. When the body is a list, the route returns the first five items with `id`, `cvss`, and a summary cut at 200 characters. The Android help text calls this the National Vulnerability Database. The handler that actually runs is the CIRCL search URL.

### History, notes, and watchlist

SQLite file `cybersecurity.db` is created in the process working directory. Tables:

- `scan_results` — target, raw text, Nmap text, OSINT JSON, AI text, risk level, client tag, analyst notes, timestamp
- `watchlist` — target (unique), scan type, `interval_hours` (default 24), last scanned time
- `diff_logs` — target, diff text, alert level, timestamp (the reader returns the latest 50)
- `settings` — key/value store; the webhook URL is stored under `webhook_url`
- `osint_results` — a separate copy of OSINT JSON written on each full scan

`POST /scan/<id>/notes` updates analyst notes and, when supplied, the client tag. History can be filtered in the browser by target or client tag.

APScheduler starts with the Flask process and runs `run_watchlist_scans` every hour. That job scans every watchlist row with the stored scan type. It does not read `interval_hours`. On a changed Nmap text blob it asks Gemini for a comparison, writes a `diff_logs` row at level `warning`, and POSTs a Discord-style embed to the saved webhook URL. `POST /watchlist/scan/<id>` does the same comparison on demand.

The webhook payload is a JSON body with `content` and `embeds`. Success is HTTP 200 or 204. `POST /test_webhook` sends a fixed test embed.

### Browser dashboard

`templates/index.html` is one page styled with Tailwind from the Tailwind CDN, icons from Font Awesome, Markdown via Marked, and PDF export via html2pdf.js. Tabs:

- **Scanner** — target, profile, client tag, optional ports, history, port table, HTTP grade, subdomain table, domain/SPF/DMARC/TLS cards, WHOIS and GeoIP text, analyst notes, raw Nmap output, JSON download, PDF download, hardening-script panel, and a chat box tied to the scan on screen.
- **Discovery** — subnet form, default placeholder `192.168.1.0/24`, table of hosts returned by `POST /discover`.
- **Monitoring** — webhook URL, test button, watchlist form (fast or advanced profile; interval choices 1, 6, or 24 hours), and the diff-log list.

The page title in the HTML is "Enterprise AI Cyber Assistant". The server listens on port **5001**.

### Terminal client

`python cli.py` is a Rich menu:

1. Nmap plus OSINT plus Gemini, then optional hardening text and a chat loop
2. Hardening text from a typed summary
3. Subnet discovery, with an option to scan a discovered host
4. Domain OSINT only
5. Subdomain wordlist, with an option to scan one result
6. History: view, edit notes, generate hardening text, or delete
7. Check whether `nmap` is on `PATH`
8. Exit

### Android client

`app/` is a Jetpack Compose app (`com.example.aiassistant`, minSdk 24, compileSdk and targetSdk 34, versionName `1.0`). It uses Retrofit and Gson with 60 second connect, read, and write timeouts. `AndroidManifest.xml` allows cleartext HTTP.

`ApiClient.kt` points at a fixed base URL: `http://192.168.2.110:5001/`. Change that constant to the machine that is running `app.py` before installing the app. The phone or emulator has to reach that address.

The terminal screen accepts `help`, `scan <target> [-p ports] [-t type]`, `subdomains`, `dns` / `whois`, `searchcve` / `cve`, `audit "<text>"`, `history`, `chat`, and `clear`. The dashboard screen shows the latest in-memory scan (target, risk color, and the AI text cut at 300 characters with `...` appended) and can request a Linux hardening script. History loaded in the terminal is also shown there.

The Gradle wrapper properties request Gradle **9.7.1**. The Android Gradle Plugin is **9.4.0** and the Compose compiler plugin is **2.4.20**. `gradle/wrapper/gradle-wrapper.jar` is not in the repository. Android Studio can regenerate the wrapper; a command-line build needs that jar or a local Gradle install. `local.properties` in the tree points at one Windows SDK path and is specific to that machine.

### Earlier voice sketch

`attached_assets/assistant.py` is a separate voice-and-text loop that shells out to `nmap -F`. It imports `speech_recognition` and `pyttsx3`, which are not listed in `requirements.txt`, and `app.py` does not import this file.

## Architecture

```
templates/index.html          browser dashboard
cli.py                        Rich menu
app/ (Jetpack Compose)        Android client, Retrofit
        |                             |
        +---------- HTTP -------------+
                      |
                   app.py             Flask on 0.0.0.0:5001
                      |               APScheduler, hourly watchlist job
          +-----------+-----------+
          |                       |
       utils.py                  db.py
       nmap, DNS, WHOIS,         SQLite cybersecurity.db
       TLS, HTTP, Gemini,
       CIRCL CVE search,
       webhooks
```

External calls made by the server, when the matching feature runs:

| Destination | When |
| --- | --- |
| The scan target (Nmap, TCP/443, HTTP) | Scan, discovery, TLS, HTTP audit, watchlist |
| DNS resolvers | Domain OSINT and subdomain wordlist |
| WHOIS | Domain OSINT |
| `http://ip-api.com` | Public IP GeoIP |
| `https://cve.circl.lu` | `POST /search_cve` |
| Google Gemini | Scan summary, chat, hardening text, config audit, diff summary |
| The saved webhook URL | Watchlist change or webhook test |

## Project layout

```
app.py                  Flask routes and the hourly watchlist job
cli.py                  Terminal menu
utils.py                Nmap, OSINT, Gemini, webhooks
db.py                   SQLite schema and queries
templates/index.html    Dashboard
tests/test_suite.py     unittest suite
setup_wsl.sh            apt packages, venv, requirements, tests
requirements.txt        Runtime Python dependencies
pyproject.toml          Package metadata (version 1.0.0, Python >= 3.11)
app/                    Android Compose client
gradle/                 Gradle wrapper properties only
attached_assets/        Unused voice-command sketch
```

`.replit` still launches `gunicorn ... main:app` on port 5000. This repository's module is `app:app`, and the development server in `app.py` uses port 5001. Gunicorn is not in `requirements.txt`.

## Quick start (WSL or Ubuntu)

Run this on Ubuntu, including Ubuntu under WSL. You need `sudo`, `apt`, and outbound network access. On Windows, open the Ubuntu app, `cd` to the clone, and use the Linux Python there. The Windows browser can open `http://127.0.0.1:5001` when WSL localhost forwarding is on, which is the usual WSL 2 default.

Install Python 3.11 or newer if `python3 --version` is older. Ubuntu 24.04's `python3` package meets that. The setup script installs the distro `python3` and does not upgrade it.

```bash
sudo apt-get update
sudo apt-get install -y nmap python3 python3-pip python3-venv dnsutils
python3 --version

chmod +x setup_wsl.sh
./setup_wsl.sh
```

`setup_wsl.sh` refuses to run when `uname -s` is not `Linux`. It then:

1. Installs `nmap`, `python3`, `python3-pip`, `python3-venv`, and `dnsutils`.
2. Creates `.venv_wsl` if it is missing, and activates it.
3. Installs `requirements.txt`, then runs `pip install -e . --no-deps`.
4. Runs `python -m unittest tests/test_suite.py`.

Create a `.env` file in the project root if you want Gemini output:

```bash
GEMINI_API_KEY=your-key-here
# optional, overrides the first model name in utils.py
# GEMINI_MODEL=gemini-3.6-flash
```

`.env` is gitignored. `python-dotenv` loads it when `utils.py` is imported.

Start the dashboard:

```bash
source .venv_wsl/bin/activate
python app.py
```

The first `app.run` call binds `0.0.0.0:5001` with `debug=True` and the reloader off. A second `app.run` sits below it and does not execute.

Start the terminal UI in another shell after activating the same virtualenv:

```bash
python cli.py
```

Run the tests alone:

```bash
source .venv_wsl/bin/activate
python -m unittest tests/test_suite.py
```

The suite covers target, subnet, and port validation, Nmap text parsing, risk-label extraction, SQLite insert/update/delete, several Flask routes with the test client, target normalization, SPF scoring, and CDN name matching. `test_advanced_security_features` opens a short HTTP connection to `192.0.2.1` (TEST-NET-1) and expects that call to fail. That test needs no listening web server, and it can take a few seconds while the timeouts expire.

Manual install, if you prefer not to run the script:

```bash
python3 -m venv .venv_wsl
source .venv_wsl/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Dependencies: `rich`, `flask`, `google-generativeai`, `python-dotenv`, `Flask-APScheduler`, `python-whois`, `dnspython`, `requests`.

## Usage examples

Confirm Nmap is visible to the server:

```bash
curl -s http://127.0.0.1:5001/check_nmap
```

Domain checks without Nmap. These contact DNS, WHOIS, and the target's port 443 and HTTP ports:

```bash
curl -s -X POST http://127.0.0.1:5001/domain_audit \
  -H 'Content-Type: application/json' \
  -d '{"domain":"scanme.nmap.org"}'

curl -s -X POST http://127.0.0.1:5001/http_audit \
  -H 'Content-Type: application/json' \
  -d '{"target":"scanme.nmap.org"}'

curl -s -X POST http://127.0.0.1:5001/subdomains \
  -H 'Content-Type: application/json' \
  -d '{"domain":"scanme.nmap.org"}'
```

A fast Nmap scan plus OSINT. This sends packets to the target:

```bash
curl -s -X POST http://127.0.0.1:5001/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://scanme.nmap.org/","scan_type":"fast","client_tag":"lab","analyst_notes":"demo"}'
```

Other accepted `scan_type` values are `advanced`, `web`, `stealth`, `vuln`, and `full`. `custom_ports` overrides the profile's port selection:

```bash
curl -s -X POST http://127.0.0.1:5001/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"scanme.nmap.org","scan_type":"fast","custom_ports":"22,80"}'
```

History and a saved report:

```bash
curl -s http://127.0.0.1:5001/history
curl -s http://127.0.0.1:5001/scan/1
```

Ping sweep on a local subnet you are allowed to probe:

```bash
curl -s -X POST http://127.0.0.1:5001/discover \
  -H 'Content-Type: application/json' \
  -d '{"subnet":"192.168.1.0/24"}'
```

CVE keyword search (the keyword is sent to CIRCL):

```bash
curl -s -X POST http://127.0.0.1:5001/search_cve \
  -H 'Content-Type: application/json' \
  -d '{"keyword":"openssl"}'
```

Android terminal, after `ApiClient.BASE_URL` matches the Flask host:

```text
scan scanme.nmap.org -t fast -p 22,80
dns scanme.nmap.org
subdomains scanme.nmap.org
searchcve openssl
history
```

## Security notes

These are properties of the code as it is checked in.

- **Authorization is the operator's job.** The API will scan any host the machine can reach. There is no login, API token, or target allowlist. `vuln` runs Nmap's `vuln` script set, and `full` passes `-p-`.
- **The development server listens on all interfaces.** `app.py` uses `host="0.0.0.0"`, `port=5001`, and `debug=True`. Anyone who can open that port can start scans, read history, change the webhook URL, and read stored notes.
- **The Flask secret is a fixed string** in source: `cybersecurity-ai-assistant-secret`.
- **TLS verification is turned off** for the HTTP header audit (`verify=False`), and urllib3's insecure-request warning is disabled in `utils.py`. The detailed certificate reader uses the default verification context first, then retries with verification disabled and records `UNTRUSTED_OR_EXPIRED`.
- **Secrets and third parties.** `GEMINI_API_KEY` is read from the environment. Scan text, including open ports and WHOIS, is sent to Gemini when a key is set. GeoIP uses plain HTTP to ip-api.com. CVE search sends the keyword to cve.circl.lu. The webhook URL is stored in SQLite and receives scan-diff text.
- **Generated scripts are untrusted output.** Review any Bash or PowerShell the model returns before running it. The offline fallback is a minimal UFW snippet, and it opens TCP/22.
- **The database holds client tags, analyst notes, Nmap output, and the webhook URL** in `cybersecurity.db` in the working directory. `*.db` is gitignored for new files. One older database file is already tracked; see the pull request notes.
- **The Android app allows cleartext** and ships with a LAN base URL in source. Traffic to that URL is HTTP.

## Known limitations

- `POST /audit_config` fails with `NameError` because `audit_local_config` is not imported in `app.py`.
- Watchlist intervals of 1, 6, and 24 hours are stored and shown in the UI. The background job still scans every watchlist target once per hour.
- The Android `SubdomainItem` model reads `ip`. The API returns `ips` (a list), so the terminal prints `Unknown IP`.
- The Android `dns` command prints DNS keys `A`, `MX`, `NS`, and `TXT`, and email field `protection_status`. Domain OSINT uses `ipv4` / `mx` / `ns` / `txt` and email field `overall`. `MX`, `NS`, and `TXT` still line up.
- Android chat sends the new message only. The web client is the one that sends prior `{role, content}` turns.
- CDN header checks inside `run_osint` do not receive the raw response headers.
- `setup_wsl.sh` prints "v2.5". `pyproject.toml` says `1.0.0`.
- `attached_assets/assistant.py` and the Replit workflow are not part of the running Flask app.

## Roadmap

Work that matches gaps in the current tree:

1. Add an import for `audit_local_config` on `/audit_config`, and cover that route in `tests/test_suite.py`.
2. Require an API token, bind the development server to localhost unless a flag says otherwise, and turn debug off outside local use.
3. Honor `interval_hours` in the scheduler, and compare parsed ports instead of the whole Nmap text blob.
4. Pass the raw HTTP response headers into `detect_cdn_proxy`.
5. Move the Android base URL to a build setting, require HTTPS for anything beyond a lab LAN, and match the API field names (`ips`, `ipv4`, `overall`).
6. Point the CVE client and the Android help text at the same source, and keep using a keyless public API only while the response shape is documented.
7. Add a CI job that runs `python -m unittest tests/test_suite.py` on Ubuntu with Python 3.11.
8. Untrack the Android build tree, APKs, and the stray SQLite file already in history, now that `.gitignore` covers new ones.
9. Replace the Replit launch command so it targets `app:app` on port 5001, or remove that workflow if Replit is unused.
10. Keep generated hardening scripts behind an explicit review step, and mark the offline UFW sample as a stub.

## License

No license file is included in this repository.
