# What this repository can actually do

This is an honest description of the AI_Assistant repository as it is in the code today. It is written so it can be turned into a PDF. It covers two separate tools that share one repository:

1. The **Security Threat Brief** in `threat-brief/`. A free, static briefing and a local network-to-inventory helper. It does not use Google, Gemini, or a paid API.
2. The **cybersecurity assistant** in `app.py`, `cli.py`, `utils.py`, and the Android app. A Flask dashboard and terminal that run nmap and a set of domain checks, and that can send text to Google Gemini when an API key is configured.

The root `README.md` describes the assistant in stronger marketing language ("enterprise-ready", "battle-tested", "attack surface monitoring suite"). This file describes what the code does. Where those differ, this file is the one to trust.

Nothing here is a certification, an audit, a penetration test, or a POPIA compliance product.

## How to read this

Each section says who it helps, an example use, and what exists today. The last sections list what is only an unused interface, and what neither tool does. "Today" means the behaviour in this repository, not a plan.

## Who it helps

| Person | What they can use today | Example |
| --- | --- | --- |
| Owner of a small South African business | The threat brief, the browser checker, and the local scan report | "Which public bugs mention WordPress, our router brand, or Windows, and which of our office machines match?" |
| Someone who looks after that business's IT | The same brief, plus the assistant's nmap, DNS, and header checks | "What is listening on the office LAN, and does our domain publish SPF and DMARC?" |
| A consultant keeping notes for a client | The assistant's scan history, client tag, and analyst notes | "Save this scan under the client name and look it up later." |
| A phone user on the same LAN as the PC | The Android app, as a remote control for the Flask server | "Run the same scan command from the phone while the PC is on." |

The brief is aimed at a non-specialist. The assistant assumes someone is willing to run nmap and read raw output. The assistant will scan a public name the user types. The threat-brief scanner will not, unless an extra override is passed.

---

## 1. Daily threat brief

**Exists today.**

A Python program, using only the standard library, downloads public feeds and writes two JSON files:

- The full CISA Known Exploited Vulnerabilities catalog.
- Recent **High** and **Critical** CVEs from the NVD CVE API 2.0, for the last 7 days, without an API key. It waits between NVD requests. It does not download every CVE published that week.
- FIRST EPSS scores for that recent NVD set, plus KEV entries added in the last 30 days. Older KEV rows often have no EPSS and no CVSS in this dataset. The stored reasons say when a part is missing.
- Three RSS feeds (the list is configurable). A headline that names a CVE is attached to that CVE. Headlines are not fact-checked.

Duplicates are removed. Each CVE gets a score out of 100 and a template sentence. No language model writes the summary.

The score id is `smb-sa-v1`. Default weights, stored in `threat-brief/config/settings.json`:

| Part | Points | Rule |
| --- | --- | --- |
| CVSS | up to 40 | `(base score / 10) × 40`, preferring CVSS 4.0, then 3.1, then 3.0, then 2.0. Missing = 0. |
| CISA KEV | 25 or 0 | Being in the catalog is 25. A ransomware flag is mentioned and does not add points. |
| EPSS | up to 20 | `probability × 20`. Missing = 0. |
| Small-business software | 15 or 0 | Vendor or product matches `threat-brief/config/smb_software.json`. |

Each part is rounded to one decimal and the total is capped at 100. The reasons are stored with the number. News uses a separate relevance score capped at 20, so a headline stays below a serious CVE.

The labels "Patch soon", "Check this week", and "Lower on this list" are reading aids. They are not extra points. A known-exploited item is labelled "Patch soon" even when CVSS is missing.

The small-business list is a starting point: Microsoft 365 and Exchange, Windows, WordPress, Fortinet, MikroTik, TP-Link, and card machines. It is editable. It is not a census of South African software. One-word names are matched against the vendor, product, and CPE identity, not against the whole CVE description, so "Exchange" does not match "Internet Key Exchange" and "pos" does not match "repository".

**Who it helps.** A business owner who wants a short public list, not a vulnerability-management product.

**Example.** Once a day, GitHub Actions refreshes the JSON and GitHub Pages serves the site. The owner opens the page, filters to WordPress, and reads the "what to do" line.

**Limits.** KEV is a US federal catalog, not a South African government feed. EPSS is a probability published by FIRST, not a prediction that this business will be attacked. The daily job is not a complete CVE database. The site does not know which business is affected until someone loads an inventory.

## 2. "Am I affected?" checker

**Exists today.**

The static page `affected.html` loads the catalog in the browser and compares it with a file the user picks. The file is not uploaded. The same matching rules exist in Python (`threat-brief/collector/match.py`) and in JavaScript (`threat-brief/site/js/match.js`).

The page accepts:

- A CSV with a `name` column and optional `vendor` and `version`. `host` and `port` are kept when present.
- An nmap XML file. In the browser, detected products become the same kind of rows. See section 3 for how names are normalised.

Version comparison is approximate. Dotted numbers are compared, and a missing part counts as 0, so 1.0 equals 1.0.0. NVD's AND/OR configuration trees are not evaluated. Many KEV rows have no version range, so a name match is labelled as approximate and still needs a person. A row whose version sits outside the published ranges is listed separately, and that clearance can be wrong because the range list is capped.

A catalog product that is only a vague name (`Server`, `HTTP Server`, `Core`, `Firmware`, or a name starting with `Multiple`) matches when the vendor also appears in the inventory row. That stops a printer banner reading "HP HTTP Server" from being listed as Apache or another vendor's "Server". It also means a TP-Link model can match a KEV row filed as "TP-Link Multiple Routers" or "Multiple Archer Devices". That vendor-level match can be broader than the exact model. The page says the match is approximate.

Equal scores are ordered with the newer catalog date first.

**Who it helps.** The same owner, or an IT person who can export a software list.

**Example.** Load the sample CSV. Exchange, Windows, WordPress, FortiOS, RouterOS, and a TP-Link model produce matches. The sample Yoco card machine and the office printer do not, because those names are not in the catalog. That is a naming gap, not a clean bill of health.

## 3. Local network scan, inventory, and report

**Exists today. It runs on your computer. The website does not scan.**

`python3 threat-brief/scan.py` does two jobs:

- `--from-xml file.xml` reads an nmap XML file and sends no packets.
- `--target 192.168.1.0/24 --i-own-this-network` runs nmap, if nmap is installed.

The live command is service and version detection only:

```text
nmap -sV -T3 --open --host-timeout 120s -oX -
```

Optional `--top-ports` asks nmap for its common-port list. There is no `-A`, no operating-system probe, and no NSE script. In particular it does not use the assistant's `--script vuln` profile.

Safety built into this command, not into the assistant:

- It prints a warning and exits unless `--i-own-this-network` is passed. The warning states that only a network you own, or one you have written permission to test, should be scanned, and it mentions South Africa's Cybercrimes Act 19 of 2020 in general terms. That text is not legal advice.
- It refuses public, multicast, and unspecified addresses. A hostname is resolved first and rejected if lookup fails or any address is public.
- `--allow-public` is a second flag for a public address you are actually allowed to test. It still requires the ownership flag.
- Targets that look like nmap flags are rejected. The target is passed as one argument, not through a shell.

Output, written under `threat-brief/scan-out/` and not committed:

- `inventory.csv` in the columns the checker accepts, including host and port.
- `report.html` and `report.md`. The HTML file contains the results, so it opens from disk without a web server.
- `nmap.xml`, a copy of the scan.

Names: when nmap prints a CPE, that CPE is used and the banner is not. `exchange_server` becomes "Exchange Server", `windows_10` becomes "Windows 10", `fortios` becomes "FortiOS", `routeros` becomes "RouterOS". A handful of vendors are capitalised the same way (`MikroTik`, `TP-Link`, `Fortinet`). If there is no CPE, a few vendors are guessed from the banner text (Microsoft, Fortinet, MikroTik, WordPress, TP-Link). Other banners are kept as nmap printed them. Closed ports and hosts that are down are omitted from the CSV.

The report lists, per host, the open services, up to five catalog matches per product, and a count of further matches. It also raises plain-English flags only from evidence in the XML:

| Flag | When | Level |
| --- | --- | --- |
| Telnet | Port 23 or service `telnet` | High |
| Cleartext FTP | Port 21 or service `ftp`, unless the service is FTPS, SFTP, or marked as SSL | High |
| Remote Desktop | Port 3389 | High |
| Database-style ports | 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 11211, or a matching service name, unless nmap called the port `http`, `https`, or `ssl` | High |
| Docker API | Port 2375 | High |
| SSH protocol 1 | The banner says so | High |
| SMB, VNC, SNMP, NFS | Those ports or service names | Check |
| Old OpenSSH | Banner major version 7, or older | Check |
| Old TLS | The banner text contains SSLv2, SSLv3, TLS 1.0, or TLS 1.1 | Check |

OpenSSH 8 and 9 are not flagged. HTTPS with no old-protocol string gets a note that TLS was not tested. The advice is defensive: turn the service off, or do not forward it to the internet. The tool does not try to exploit the service. A flag is not proof that a particular bug is present.

**Who it helps.** An owner or IT person who can run a scan on a network they control and then read a short report.

**Example.** In WSL, after `sudo apt install nmap python-is-python3`, run the sample file (`--from-xml threat-brief/site/sample-nmap.xml`) to see the report with no packets. For a real LAN, find the Windows IPv4 range with `ipconfig` and pass that range. WSL2 often sees only its own `172.x` virtual network. If it cannot reach the LAN, run Nmap or Zenmap on Windows and pass the saved XML with `--from-xml`.

**Limits.** A quiet host is invisible. Version banners can be wrong or hidden. CPE vendor strings sometimes disagree with the catalog (OpenSSH is usually vendor `openbsd` in the CPE). The catalog built for this repository on 14 October 2026 had no OpenSSH row at all, so those hosts show the version flag only. The report lists five catalog matches per product and says how many more exist; the browser page lists the rest. This scan is separate from the assistant's nmap profiles below.

## 4. Assistant network scans

**Exists today, in a different tool, with different safety rules.**

`utils.run_nmap_scan` shells out to nmap. The web dashboard (`app.py` on port 5001), the terminal (`cli.py`), and the Android app all call it. Profiles:

| Profile | What the code runs |
| --- | --- |
| fast | `nmap -F` (nmap's short port list) |
| advanced | `nmap -sV -O -T4` as root; without root, `-sV --version-all -T4` |
| web | `-sV` on ports 80, 443, 8080, 8443, 3000, 5000, 8000, plus NSE scripts `http-title`, `http-headers`, `http-methods`, `ssl-cert` |
| stealth | SYN scan `-sS` as root, otherwise TCP connect `-sT`, with `-sV -Pn -T4 --top-ports 1000` |
| vuln | `-sV -T4 --script vuln` |
| full | all TCP ports, `-p- -T4 -sV` |

A custom port list replaces the default ports. Targets can be an IP, a hostname, or a URL; the host and an optional port are extracted. If nmap complains about root privileges, the code retries without `-O` and with `-sT` instead of `-sS`. The timeout is 10 minutes.

There is also a ping sweep, `nmap -sn`, labelled as host discovery. It parses hostname, IP, latency, and MAC vendor from the text output.

**This assistant does not refuse public targets.** Typing a public hostname scans that host. The `vuln` profile runs nmap's vulnerability scripts, which are more intrusive than a version scan. The threat-brief scanner does not do that.

If `GEMINI_API_KEY` is set, the nmap text is sent to Google Gemini for a written analysis and a risk label. Without the key, the scan can still run and the AI analysis fails.

**Who it helps.** A person doing their own reconnaissance who already understands that they must have permission.

**Example.** From the CLI, choose a fast scan of a host on the office LAN, then read the open-port table.

**Limits.** Output is nmap's text, not the inventory CSV. It is not tied to the threat-brief catalog or score. A scan is not proof of compromise.

## 5. Domain, DNS, email, and CDN checks

**Exists today, in the assistant.**

For a domain, `run_osint` and `analyze_domain` collect:

- WHOIS, via the `whois` Python package. If the lookup fails, the error string is stored.
- DNS records: A, AAAA, CNAME, MX, NS, TXT, SOA, and a reverse lookup. This uses `dnspython`.
- SPF and DMARC. The code classifies SPF (`-all`, `~all`, `?all`, `+all`) and DMARC policy (`reject`, `quarantine`, `none`) into labels such as protected, partially protected, or vulnerable to spoofing. That is a reading of the published DNS record, not a test that spoofed mail was blocked.
- A CDN or reverse-proxy guess from CNAME and headers: Cloudflare, CloudFront, Akamai, Fastly, Azure Front Door, Imperva. It is a heuristic. It tells the reader that a port scan may be hitting the edge, not the origin. It can be wrong.
- GeoIP from `http://ip-api.com` (country, city, ISP, organisation, AS). The target is sent to that third party over plain HTTP. Private addresses are not sent. This is location data, not a threat-intelligence feed.

**Who it helps.** Someone checking whether a domain they administer publishes basic anti-spoofing DNS.

**Example.** Ask the dashboard for a domain audit and read the SPF and DMARC lines.

**Limits.** It does not send mail, does not test DKIM alignment end to end, and does not monitor a domain over time except through the watchlist in section 10.

## 6. TLS certificate checks

**Exists today, in two different strengths.**

- `get_ssl_cert_info` connects with certificate verification turned off (`CERT_NONE`). It reports the negotiated TLS version, the cipher name, and whether a certificate was presented. It does not tell you that the certificate is valid, who issued it, or when it expires.
- `get_detailed_ssl_cert` tries a normal verified connection first and, on success, records issuer, subject, up to 15 DNS subject-alternative names, not-before, not-after, and days remaining. If verification fails, it retries with verification off and keeps the TLS version and cipher, but it does not then parse the certificate subject. The status becomes `UNTRUSTED_OR_EXPIRED` with the error text.

**Who it helps.** Someone who wants a quick expiry warning for a site they operate.

**Example.** The domain audit shows days remaining and "expiring soon" when the verified certificate expires within 30 days.

**Limits.** This is not a cipher audit. It does not test TLS 1.0 by negotiating it, and it does not grade the certificate chain beyond Python's default trust store.

## 7. HTTP header grade

**Exists today, in the assistant.**

`analyze_http_security` requests `https://` and then `http://` the host, with TLS verification disabled (`verify=False`), and scores a short header list:

| Header | Points |
| --- | --- |
| Strict-Transport-Security | 25 |
| Content-Security-Policy | 25 |
| X-Frame-Options | 15 |
| X-Content-Type-Options: nosniff | 15 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |

Grade A is 85 or above, then B, C, D, and F. It also notes a `Server` or `X-Powered-By` banner and whether cookies on that response look `Secure`, `HttpOnly`, and `SameSite`.

**Who it helps.** Someone checking a site they run for missing headers.

**Example.** A site with HSTS and CSP but nothing else scores 50, grade C.

**Limits.** The grade is header presence, not a test for cross-site scripting, injection, or authentication bugs. A grade A does not mean the site is safe. Cookie parsing depends on what the HTTP library exposes and can miss flags.

## 8. Subdomain wordlist

**Exists today, in the assistant.**

`enumerate_subdomains` looks up about 30 fixed names (`www`, `api`, `mail`, `dev`, `staging`, `admin`, `vpn`, and similar) as DNS A records, with a 1.5 second timeout each. Names that answer are listed. IP addresses are skipped.

**Who it helps.** Someone who wants a quick look for obvious hostnames on a domain they administer.

**Example.** `dev.example.com` resolves, so it appears in the list, and the dashboard can offer to scan it.

**Limits.** This is not a full subdomain enumeration. It does not use certificate transparency, zone transfers, or a large wordlist. Most real hostnames will be missed.

## 9. Keyword CVE search

**Exists today, in the assistant. It is not the threat brief.**

`POST /search_cve` sends the keyword to `https://cve.circl.lu/api/search/` and returns up to five results (id, CVSS, a short summary) when the response is a list. No API key. No scoring formula. No KEV or EPSS join.

The comment in `app.py` and the Android help text say "National Vulnerability Database". The request that actually runs is the CIRCL search URL. Treat CIRCL as the source.

**Who it helps.** Someone who wants a quick public lookup while using the assistant.

**Example.** Search the keyword `apache 2.4.49` and read the top rows.

**Limits.** Keyword search is noisy. It is not the scored catalog from section 1, and a hit is not confirmation that the scanned host is vulnerable.

## 10. Gemini features, and what happens with no key

**Exists today, only when `GEMINI_API_KEY` is set.** These calls send the prompt, including scan text, to Google. They are not part of the free threat brief, and they are not free of a Google account and quota.

| Feature | With a key | Without a key |
| --- | --- | --- |
| Written analysis of an nmap scan | Gemini, using `GEMINI_MODEL` or a short built-in fallback list of model names | The scan output remains; the analysis call fails |
| Chat about a scan | The conversation and scan context are sent to Gemini | The call fails |
| Domain-audit write-up | The collected OSINT text is sent to Gemini | The raw checks can still be shown; the write-up fails |
| Config snippet audit (`/audit_config`) | The pasted text is sent to Gemini | Returns "Analysis failed: No API key found." |
| Hardening script | Gemini is asked for a Bash or PowerShell script from the scan summary | A four-line UFW example: default deny incoming, allow outgoing, allow 22/tcp, enable. It is not tailored to the scan |
| Watchlist diff | The old and new nmap text are sent to Gemini, which is asked what changed | The diff call fails; the new scan can still be saved |

The model list and the prompt text live in `utils.py`. This repository does not include a key.

**Who it helps.** Someone who has chosen to send that text to Google and has a key.

**Example.** After a LAN scan, ask the chat box what the open database port implies. The answer is model output, not a measured finding.

**Limits.** The offline hardening stub is not a production script. A generated script is not reviewed by this repository. Do not run a generated script on a machine without reading it.

## 11. History, notes, watchlist, and webhooks

**Exists today, in the assistant.**

SQLite file `cybersecurity.db` stores scan text, a client tag, analyst notes, OSINT JSON, a watchlist, diff logs, and a webhook URL setting.

The watchlist job is an APScheduler task inside `app.py`. It fires every hour **while that process is running**. It scans every watchlist row. The `interval_hours` value stored on the row (default 24) is not what the loop checks. Nothing is monitored when the Flask process is stopped. There is no separate always-on service.

If the new nmap text differs from the latest saved scan, the diff is sent to Gemini when a key exists, stored, and posted to a Discord or Slack webhook when one is configured. The webhook payload is a short embed. Delivery is a single HTTP POST with a five-second timeout.

**Who it helps.** A consultant who wants yesterday's scan text next to a client name, and a ping in chat if the text changed.

**Example.** Tag a scan "Northwind - October", add a note that port 3389 is intentional, and look it up in history.

**Limits.** "Continuous monitoring" in the root README means this hourly loop inside the web process. It is not a SOC platform.

## 12. Android client

**Exists today, as a remote control.**

The Compose app in `app/src/main/java/com/example/aiassistant/` talks to the Flask API. The base URL is hardcoded to `http://192.168.2.110:5001/` in `ApiClient.kt`. It does not scan by itself. The phone must be able to reach that PC. A comment in the scan error text mentions the emulator address `10.0.2.2`; that address is not the URL the app uses.

Commands typed in the phone: `scan`, `subdomains`, `dns`, `searchcve`, `audit`, `history`, `chat`. The dashboard tab can request a remediation script. Timeouts are 60 seconds, which is shorter than the server's 10-minute nmap timeout, so a long scan can fail on the phone while the server is still working.

**Who it helps.** Someone standing away from the PC, on a network that can reach that hardcoded address.

**Example.** Type `dns example.com` on the phone and read the WHOIS and SPF lines the PC fetched.

**Limits.** Change the hardcoded URL before it will work on another network. It is not a standalone scanner and it does not include the threat brief.

## 13. Terminal CLI

**Exists today.**

`python cli.py` is a menu over the same functions as the website: scan profiles, hardening script, subnet sweep, domain audit, subdomain list, history, and an nmap-installed check. It prints tables in the terminal. It has the same Gemini and permission behaviour as the website.

---

## What is only an interface

`threat-brief/collector/summarise.py` exposes `get_summariser()`. The only engine that works is `rules-v1`, the template summariser. Asking for `gemini` or `openai` raises an error. No model is called. There is no schedule, no budget, and no promise that another engine will be added.

No other "planned" feature is implemented. This document does not invent a roadmap.

## What neither tool does

- Endpoint detection, a SIEM, or log collection from PCs.
- Phishing simulation, dark-web monitoring, or stolen-credential search.
- A full software inventory. The brief sees only the CSV or the services nmap printed. The assistant sees only what its scan and DNS checks returned.
- Automatic patching.
- Proof that a CVE is exploitable on a host. Name matching and version banners are approximate.
- A POPIA programme, a cyber-insurance report, or a certification.
- Guaranteed detection of an intrusion. A quiet host, a patched banner, and a missing CSV row all look like "nothing to show".

## How the two tools sit together

They do not call each other. The practical order for a business is:

1. Read the threat brief for public issues that match the software you know you run.
2. Optionally, on a network you own, run `threat-brief/scan.py` and open `report.html`. Upload the CSV to the checker if you want the full match list.
3. Use the assistant when you want a deeper nmap profile, DNS and header checks, or notes stored on the PC. Remember that the assistant will scan public names, that the `vuln` profile is more intrusive, and that Gemini features send text to Google.

Legal use is the same for both scanners: only test systems you own or have written permission to test. The Cybercrimes Act 19 of 2020 is relevant in South Africa. This document is not legal advice.
