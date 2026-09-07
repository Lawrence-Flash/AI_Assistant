import subprocess
import shutil
import re
import logging
import os
import json
import socket
import ssl
import ipaddress
import urllib.parse
from datetime import datetime
import requests
import whois
import dns.resolver
import dns.reversename
import urllib3
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

def normalize_target(target):
    """
    Normalizes a user-provided target string.
    Handles raw IP/domain, URLs with schemes (http/https/ftp), trailing slashes, paths, and ports.
    Returns a tuple (cleaned_target, extracted_port):
      - cleaned_target: clean IP or domain name (e.g. 'scanme.nmap.org', '192.168.1.1')
      - extracted_port: port string if specified in target (e.g. '8080'), else None
    """
    if not target or not isinstance(target, str):
        return "", None
    
    target = target.strip()
    extracted_port = None
    
    # 1. Check if URL scheme is present or starts with //
    if "://" in target or target.startswith("//"):
        url_to_parse = target if "://" in target else f"http:{target}"
        parsed = urllib.parse.urlparse(url_to_parse)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        target = netloc
    
    # Strip any trailing path, query or fragment if someone typed domain.com/path
    if "/" in target:
        target = target.split("/")[0]
    if "?" in target:
        target = target.split("?")[0]
    if "#" in target:
        target = target.split("#")[0]
        
    target = target.strip()
    
    # 2. Handle IPv6 with brackets [::1]:8080 or [::1]
    if target.startswith("[") and "]" in target:
        bracket_end = target.index("]")
        ipv6_part = target[1:bracket_end]
        rest = target[bracket_end+1:]
        if rest.startswith(":"):
            port_cand = rest[1:]
            if port_cand.isdigit():
                extracted_port = port_cand
        return ipv6_part, extracted_port
        
    # 3. Handle host:port (distinguishing from raw IPv6 containing multiple colons)
    if ":" in target and target.count(":") == 1:
        host_part, port_cand = target.split(":", 1)
        if port_cand.isdigit() and 1 <= int(port_cand) <= 65535:
            extracted_port = port_cand
            target = host_part.strip()
            
    return target, extracted_port

def is_valid_target(target):
    """
    Validates if the provided string is a valid IP address, domain name, or localhost.
    """
    if not target or not isinstance(target, str):
        return False
    
    target = target.strip()
    if target.lower() == "localhost":
        return True

    # Check valid IP (IPv4 or IPv6)
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # If target is composed only of numbers and dots, it is an invalid IP, not a domain
    if re.match(r"^[\d\.]+$", target):
        return False

    # Domain pattern (including subdomains) - TLD must contain letters
    domain_pattern = r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
    return re.match(domain_pattern, target) is not None

def is_domain_target(target):
    """
    Returns True if target is a valid domain name (not an IP address and not localhost).
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if target.lower() == "localhost":
        return False
    try:
        ipaddress.ip_address(target)
        return False
    except ValueError:
        pass
    return is_valid_target(target)

def is_valid_subnet(subnet):
    """
    Validates if the provided string is a valid CIDR network (e.g. 192.168.1.0/24).
    """
    if not subnet or not isinstance(subnet, str):
        return False
    try:
        ipaddress.ip_network(subnet.strip(), strict=False)
        return True
    except ValueError:
        return False

def is_valid_port_spec(port_str):
    """
    Validates port specifications like '80', '80,443', '1-1000', '22,80-90,443'.
    """
    if not port_str or not isinstance(port_str, str):
        return False
    port_str = port_str.strip()
    if not re.match(r"^[0-9,\-\s]+$", port_str):
        return False
    
    parts = [p.strip() for p in port_str.split(",") if p.strip()]
    if not parts:
        return False
        
    for part in parts:
        if "-" in part:
            subparts = part.split("-")
            if len(subparts) != 2:
                return False
            try:
                start, end = int(subparts[0]), int(subparts[1])
                if not (1 <= start <= end <= 65535):
                    return False
            except ValueError:
                return False
        else:
            try:
                val = int(part)
                if not (1 <= val <= 65535):
                    return False
            except ValueError:
                return False
    return True

def check_nmap():
    """
    Checks if Nmap is installed and available on the system.
    """
    return shutil.which("nmap") is not None

def parse_nmap_ports(nmap_output):
    """
    Parses open/filtered ports, protocols, services, and versions from Nmap raw output.
    Returns a list of dictionaries.
    """
    ports = []
    if not nmap_output:
        return ports

    lines = nmap_output.splitlines()
    in_port_section = False
    
    for line in lines:
        stripped = line.strip()
        if re.match(r"^PORT\s+STATE\s+SERVICE", stripped):
            in_port_section = True
            continue
        
        if in_port_section:
            if not stripped or stripped.startswith("Nmap done:") or stripped.startswith("MAC Address:"):
                in_port_section = False
                continue
            
            # Match: 80/tcp open http Apache httpd 2.4.41
            match = re.match(r"^(\d+/(?:tcp|udp|sctp))\s+(\S+)\s+(\S+)(?:\s+(.*))?$", stripped)
            if match:
                port_proto = match.group(1)
                state = match.group(2)
                service = match.group(3)
                version = match.group(4) or "N/A"
                ports.append({
                    "port": port_proto,
                    "state": state,
                    "service": service,
                    "version": version.strip()
                })
    return ports

def extract_risk_score(ai_text):
    """
    Extracts structured risk level from AI analysis text.
    Returns one of: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.
    """
    if not ai_text:
        return "LOW"
    match = re.search(r"Risk Level:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)", ai_text, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    
    # Heuristic fallback based on strong keywords
    upper_text = ai_text.upper()
    if "CRITICAL VULNERABILITY" in upper_text or "CRITICAL RISK" in upper_text or "REMOTE CODE EXECUTION" in upper_text:
        return "CRITICAL"
    if "HIGH RISK" in upper_text or "HIGH SEVERITY" in upper_text or "EXPLOITABLE" in upper_text:
        return "HIGH"
    if "MEDIUM RISK" in upper_text or "MODERATE RISK" in upper_text:
        return "MEDIUM"
    return "LOW"

def is_root_user():
    """Checks if the current process has root/superuser privileges."""
    try:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False

def run_nmap_scan(target, scan_type="fast", custom_ports=None):
    """
    Runs an Nmap scan on the specified target.
    Supports fast, advanced, web, stealth, vuln, full profiles and custom port ranges.
    Automatically adapts flags for non-root users (gracefully replacing -O and -sS).
    """
    if not check_nmap():
        logging.error("Nmap is not installed or not found in system PATH")
        return False, "Nmap is not installed or not found in your system PATH."
    
    clean_target, extracted_port = normalize_target(target)
    if not is_valid_target(clean_target):
        logging.error(f"Invalid target: {target}")
        return False, "Invalid target. Please provide a valid IP address or domain name."
    
    target = clean_target
    if not custom_ports and extracted_port:
        custom_ports = extracted_port
    
    try:
        logging.debug(f"Starting Nmap scan of {target} (profile: {scan_type})")
        
        is_root = is_root_user()
        flags = ["-F"]
        if scan_type == "advanced":
            # -O requires raw socket privileges (root). If unprivileged, use deep version & banner OS fingerprinting.
            flags = ["-sV", "-O", "-T4"] if is_root else ["-sV", "--version-all", "-T4"]
        elif scan_type == "web":
            flags = ["-sV", "-p", "80,443,8080,8443,3000,5000,8000", "--script", "http-title,http-headers,http-methods,ssl-cert"]
        elif scan_type == "stealth":
            # -sS requires raw sockets (root). If unprivileged, use -sT (TCP Connect scan)
            flags = ["-sS", "-sV", "-Pn", "-T4", "--top-ports", "1000"] if is_root else ["-sT", "-sV", "-Pn", "-T4", "--top-ports", "1000"]
        elif scan_type == "vuln":
            flags = ["-sV", "-T4", "--script", "vuln"]
        elif scan_type == "full":
            flags = ["-p-", "-T4", "-sV"]
            
        if custom_ports and is_valid_port_spec(custom_ports):
            # Cleanly replace any existing -p specification
            new_flags = []
            skip_next = False
            for f in flags:
                if skip_next:
                    skip_next = False
                    continue
                if f == "-p":
                    skip_next = True
                    continue
                new_flags.append(f)
            # Remove -F if custom ports are specified
            if "-F" in new_flags:
                new_flags.remove("-F")
            flags = new_flags + ["-p", custom_ports.strip()]
            
        result = subprocess.run(["nmap"] + flags + [target], 
                               capture_output=True, 
                               text=True, 
                               timeout=600)
        
        # Reactive Fallback: If Nmap failed because of root privilege requirements (e.g. raw socket OS scan)
        err_output = (result.stderr or "") + " " + (result.stdout or "")
        if result.returncode != 0 and "requires root privileges" in err_output.lower():
            logging.warning("Nmap raw socket operation requires root privileges. Retrying with unprivileged fallback...")
            fallback_flags = []
            for f in flags:
                if f == "-O":
                    continue # Drop raw OS fingerprinting
                elif f == "-sS":
                    fallback_flags.append("-sT") # Use TCP Connect scan
                else:
                    fallback_flags.append(f)
            if "-sV" not in fallback_flags:
                fallback_flags.append("-sV")
                
            result = subprocess.run(["nmap"] + fallback_flags + [target], 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=600)
            if result.returncode == 0:
                notice = "\n[Notice: Running as non-root user. TCP/IP raw OS packet fingerprinting (-O) was gracefully replaced with service banner detection. To enable raw packet OS fingerprinting, run with sudo].\n"
                return True, result.stdout + notice

        if result.returncode == 0:
            logging.info(f"Nmap scan of {target} completed successfully")
            return True, result.stdout
        else:
            logging.error(f"Nmap scan failed with return code {result.returncode}")
            return False, f"Nmap scan failed: {result.stderr or result.stdout}"
            
    except subprocess.TimeoutExpired:
        logging.error(f"Nmap scan of {target} timed out")
        return False, "Scan timed out. The target may be unreachable or blocking scans."
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap error: {str(e)}")
        return False, f"Nmap error: {e.stderr}"
    except Exception as e:
        logging.error(f"Unexpected error during scan: {str(e)}")
        return False, f"An unexpected error occurred: {str(e)}"

def run_host_discovery(subnet):
    """
    Runs an Nmap ping sweep (-sn) across a subnet or CIDR range to find active hosts.
    """
    if not check_nmap():
        return False, "Nmap is not installed or not found in system PATH."
    
    subnet = subnet.strip()
    if not is_valid_subnet(subnet) and not is_valid_target(subnet):
        return False, "Invalid subnet/range. Please provide a valid CIDR (e.g. 192.168.1.0/24) or target."

    try:
        result = subprocess.run(["nmap", "-sn", subnet], 
                                capture_output=True, 
                                text=True, 
                                timeout=120)
        if result.returncode != 0:
            return False, f"Host discovery failed: {result.stderr}"

        # Parse hosts from output
        hosts = []
        raw_output = result.stdout
        current_host = {}

        for line in raw_output.splitlines():
            line_str = line.strip()
            # Example: Nmap scan report for 192.168.1.1
            # Example: Nmap scan report for router.local (192.168.1.1)
            report_match = re.match(r"^Nmap scan report for (?:([^\(\)\s]+)\s+\(([^\(\)\s]+)\)|([^\(\)\s]+))$", line_str)
            if report_match:
                if current_host and current_host.get("ip"):
                    hosts.append(current_host)
                
                if report_match.group(1) and report_match.group(2):
                    current_host = {"hostname": report_match.group(1), "ip": report_match.group(2), "status": "up"}
                else:
                    target_val = report_match.group(3)
                    current_host = {"hostname": target_val, "ip": target_val, "status": "up"}
            
            # Match latency or state: Host is up (0.0010s latency).
            latency_match = re.search(r"Host is up \(([^)]+)\)", line_str)
            if latency_match and current_host:
                current_host["latency"] = latency_match.group(1)

            # Match MAC Address: MAC Address: 00:11:22:33:44:55 (Vendor Name)
            mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]+)(?:\s+\((.*)\))?", line_str)
            if mac_match and current_host:
                current_host["mac"] = mac_match.group(1)
                if mac_match.group(2):
                    current_host["vendor"] = mac_match.group(2)

        if current_host and current_host.get("ip"):
            hosts.append(current_host)

        return True, hosts
    except Exception as e:
        return False, str(e)

def call_gemini_with_fallback(prompt):
    """
    Executes a prompt against Gemini with graceful automatic fallback across
    active models (gemini-3.6-flash, gemini-3.5-flash-lite, gemini-flash-latest).
    """
    models_to_try = [
        os.getenv("GEMINI_MODEL", "gemini-3.6-flash"),
        "gemini-3.5-flash-lite",
        "gemini-flash-latest",
        "gemini-pro-latest"
    ]
    last_err = None
    for model_name in models_to_try:
        try:
            m = genai.GenerativeModel(model_name)
            resp = m.generate_content(prompt)
            return resp.text
        except Exception as e:
            last_err = e
            continue
    raise last_err or Exception("All Gemini model candidates failed.")

def analyze_scan_with_ai(nmap_output):
    """
    Passes Nmap output and OSINT data to the AI model for cybersecurity analysis.
    Instructs the AI to provide a standardized Risk Level and structured remediations.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "AI analysis failed: No API key found. Please set the GEMINI_API_KEY environment variable in your .env file."
        
    try:
        genai.configure(api_key=api_key)
        prompt = (
            "You are a Senior Principal Cybersecurity Analyst and Penetration Tester. "
            "Analyze the following Nmap scan and OSINT intelligence data.\n\n"
            "Produce a structured, professional security assessment report formatted with markdown headers:\n"
            "1. **Risk Level**: Output exactly one of: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL on this line: "
            "'Risk Level: [LEVEL]'.\n"
            "2. **Executive Summary**: High-level posture analysis in 2-3 sentences (including domain / CDN context if applicable).\n"
            "3. **Exposed Services & Attack Surface Analysis**: Breakdown of detected open ports, running services, and versions.\n"
            "4. **Domain & Web Posture**: Evaluate DNS, Email Security (SPF/DMARC spoofing defense), SSL/TLS certificate validity, and HTTP security headers (if applicable).\n"
            "5. **Identified Vulnerabilities & Threat Vectors**: Potential CVEs, misconfigurations, default credentials, or OSINT exposures.\n"
            "6. **Actionable Remediation Checklist**: Specific, priority-ranked steps (including firewall rules, DNS/DMARC hardening, service updates) to secure the target.\n\n"
            f"--- SCAN & OSINT TARGET DATA ---\n{nmap_output}"
        )
        return call_gemini_with_fallback(prompt)
    except Exception as e:
        return f"AI analysis error: {str(e)}"

def chat_with_ai(chat_history, new_message, scan_context):
    """
    Handles interactive chat with the AI advisor, maintaining scan context.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "Chat failed: No API key found."
        
    try:
        genai.configure(api_key=api_key)
        system_context = (
            "You are an expert Cybersecurity Advisor and Security Operations Center (SOC) Specialist. "
            "You are assisting a security engineer investigating the results of a network scan and OSINT assessment. "
            "Provide concise, actionable, and technically rigorous explanations. "
            "Reference specific ports, protocols, CVEs, or firewall configurations when answering.\n\n"
            f"--- ACTIVE SCAN CONTEXT ---\n{scan_context}\n----------------------------\n\n"
        )
        
        conversation = system_context
        for msg in chat_history:
            role = "User: " if msg["role"] == "user" else "Advisor: "
            conversation += f"{role}{msg['content']}\n"
            
        conversation += f"User: {new_message}\nAdvisor: "
        return call_gemini_with_fallback(conversation)
    except Exception as e:
        return f"Chat error: {str(e)}"

def get_ssl_cert_info(host, port=443, timeout=3):
    """
    Extracts SSL/TLS certificate metadata for a host.
    """
    try:
        # Resolve target to verify connection capability
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                # When verify_mode is CERT_NONE, getpeercert returns empty dict, so get binary DER
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "has_certificate": der is not None and len(der) > 0,
                    "status": "active"
                }
    except Exception as e:
        return {"error": f"SSL not available or port {port} closed ({str(e)})"}

def get_geoip_info(target):
    """
    Fetches geolocation and ISP info for a target (IP or domain).
    """
    try:
        # Check if target is a private IP address
        try:
            ip_obj = ipaddress.ip_address(target)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "is_private": True,
                    "ip": target,
                    "info": "Private / Local Network IP (No public GeoIP available)"
                }
        except ValueError:
            pass

        # Query free public IP-API
        resp = requests.get(
            f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,regionName,city,zip,isp,org,as,query",
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "region": data.get("regionName"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as")
                }
    except Exception as e:
        logging.warning(f"GeoIP resolution failed for {target}: {e}")
    return None

def get_domain_dns_details(domain):
    """
    Performs comprehensive DNS reconnaissance on a domain name.
    Resolves A (IPv4), AAAA (IPv6), CNAME, MX, NS, TXT, and SOA records.
    """
    clean_domain, _ = normalize_target(domain)
    dns_data = {
        "domain": clean_domain,
        "ipv4": [],
        "ipv6": [],
        "cnames": [],
        "mx": [],
        "ns": [],
        "txt": [],
        "soa": None
    }
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.5
    resolver.timeout = 2.0
    
    # 1. A (IPv4)
    try:
        answers = resolver.resolve(clean_domain, 'A')
        dns_data["ipv4"] = [rdata.to_text() for rdata in answers]
    except Exception:
        pass
        
    # 2. AAAA (IPv6)
    try:
        answers = resolver.resolve(clean_domain, 'AAAA')
        dns_data["ipv6"] = [rdata.to_text() for rdata in answers]
    except Exception:
        pass
        
    # 3. CNAME
    try:
        answers = resolver.resolve(clean_domain, 'CNAME')
        dns_data["cnames"] = [rdata.target.to_text().rstrip('.') for rdata in answers]
    except Exception:
        pass
        
    # 4. MX
    try:
        answers = resolver.resolve(clean_domain, 'MX')
        sorted_mx = sorted(answers, key=lambda r: r.preference)
        dns_data["mx"] = [f"{r.exchange.to_text().rstrip('.')} (priority {r.preference})" for r in sorted_mx]
    except Exception:
        pass
        
    # 5. NS
    try:
        answers = resolver.resolve(clean_domain, 'NS')
        dns_data["ns"] = [rdata.target.to_text().rstrip('.') for rdata in answers]
    except Exception:
        pass
        
    # 6. TXT
    try:
        answers = resolver.resolve(clean_domain, 'TXT')
        dns_data["txt"] = ["".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings]) for rdata in answers]
    except Exception:
        pass
        
    # 7. SOA
    try:
        answers = resolver.resolve(clean_domain, 'SOA')
        if answers:
            soa = answers[0]
            dns_data["soa"] = {
                "mname": soa.mname.to_text().rstrip('.'),
                "rname": soa.rname.to_text().rstrip('.'),
                "serial": soa.serial
            }
    except Exception:
        pass
        
    return dns_data

def analyze_email_security(domain, txt_records=None):
    """
    Evaluates SPF (Sender Policy Framework) and DMARC (Domain-based Message Authentication)
    records to audit email spoofing vulnerabilities and protection posture.
    """
    clean_domain, _ = normalize_target(domain)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.5
    resolver.timeout = 2.0
    
    if txt_records is None:
        try:
            answers = resolver.resolve(clean_domain, 'TXT')
            txt_records = ["".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings]) for rdata in answers]
        except Exception:
            txt_records = []
            
    # SPF check
    spf_record = None
    spf_policy = "MISSING"
    spf_status = "MISSING"
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            spf_record = txt
            break
            
    if spf_record:
        if "-all" in spf_record:
            spf_policy = "HardFail (-all) - Strict Enforcement"
            spf_status = "PASS"
        elif "~all" in spf_record:
            spf_policy = "SoftFail (~all) - Standard / Transitioning"
            spf_status = "PASS"
        elif "?all" in spf_record:
            spf_policy = "Neutral (?all) - Ineffective"
            spf_status = "WEAK"
        elif "+all" in spf_record:
            spf_policy = "Pass (+all) - CRITICAL VULNERABILITY (Allows any host to spoof)"
            spf_status = "CRITICAL"
        else:
            spf_policy = "Configured (No explicit 'all' qualifier)"
            spf_status = "WARNING"
            
    # DMARC check
    dmarc_record = None
    dmarc_policy = "MISSING"
    dmarc_pct = "100"
    dmarc_rua = None
    dmarc_status = "MISSING"
    try:
        answers = resolver.resolve(f"_dmarc.{clean_domain}", 'TXT')
        for rdata in answers:
            txt = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if "v=DMARC1" in txt:
                dmarc_record = txt
                p_match = re.search(r"p=(reject|quarantine|none)", txt, re.IGNORECASE)
                if p_match:
                    p_val = p_match.group(1).lower()
                    if p_val == "reject":
                        dmarc_policy = "p=reject (Maximum Enforcement: Unauthorized emails blocked)"
                        dmarc_status = "PASS"
                    elif p_val == "quarantine":
                        dmarc_policy = "p=quarantine (High Enforcement: Suspicious emails quarantined)"
                        dmarc_status = "PASS"
                    elif p_val == "none":
                        dmarc_policy = "p=none (Monitoring Only: No enforcement)"
                        dmarc_status = "WARNING"
                pct_match = re.search(r"pct=(\d+)", txt, re.IGNORECASE)
                if pct_match:
                    dmarc_pct = pct_match.group(1)
                rua_match = re.search(r"rua=mailto:([^\s;]+)", txt, re.IGNORECASE)
                if rua_match:
                    dmarc_rua = rua_match.group(1)
                break
    except Exception:
        pass

    if spf_status == "PASS" and dmarc_status == "PASS":
        overall = "PROTECTED"
        summary = "Domain has robust anti-spoofing defense (SPF & enforced DMARC active)."
    elif spf_status == "PASS" and dmarc_status in ["WARNING", "MISSING"]:
        overall = "PARTIALLY PROTECTED"
        summary = "SPF is configured but DMARC lacks strict enforcement (vulnerable to display-name / header spoofing)."
    else:
        overall = "VULNERABLE"
        summary = "Domain is vulnerable to email spoofing and phishing abuse (Missing SPF and/or DMARC enforcement)."

    return {
        "domain": clean_domain,
        "overall": overall,
        "summary": summary,
        "spf": {
            "record": spf_record,
            "policy": spf_policy,
            "status": spf_status
        },
        "dmarc": {
            "record": dmarc_record,
            "policy": dmarc_policy,
            "pct": dmarc_pct,
            "rua": dmarc_rua,
            "status": dmarc_status
        }
    }

def detect_cdn_proxy(domain, ips=None, cnames=None, headers=None):
    """
    Detects if the domain is fronted by a Content Delivery Network (CDN) or Cloud Reverse Proxy
    (Cloudflare, AWS CloudFront, Akamai, Fastly, Azure Front Door, Imperva, etc.).
    """
    domain = (domain or "").lower()
    cnames = [c.lower() for c in (cnames or [])]
    headers = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    
    providers = []
    
    # CNAME checks
    for cname in cnames:
        if "cloudflare" in cname:
            providers.append("Cloudflare")
        if "cloudfront.net" in cname:
            providers.append("AWS CloudFront")
        if "akamai" in cname or "edgekey.net" in cname:
            providers.append("Akamai")
        if "fastly" in cname:
            providers.append("Fastly")
        if "azureedge.net" in cname or "azurefd.net" in cname:
            providers.append("Azure Front Door / CDN")
        if "incapdns.net" in cname:
            providers.append("Imperva Incapsula")
        if "sucuri" in cname:
            providers.append("Sucuri")
            
    # Header checks
    if "cf-ray" in headers or ("server" in headers and "cloudflare" in headers["server"]):
        providers.append("Cloudflare")
    if "x-amz-cf-id" in headers:
        providers.append("AWS CloudFront")
    if "x-fastly-request-id" in headers:
        providers.append("Fastly")
    if "x-azure-ref" in headers:
        providers.append("Azure CDN")
        
    unique_providers = list(dict.fromkeys(providers))
    
    if unique_providers:
        provider_str = ", ".join(unique_providers)
        return {
            "is_proxied": True,
            "provider": provider_str,
            "notes": f"Target is fronted by {provider_str}. Scanned ports and headers reflect edge reverse proxy nodes rather than the origin server."
        }
    return {
        "is_proxied": False,
        "provider": "Direct / Origin Server",
        "notes": "No public CDN or cloud reverse proxy detected; traffic appears routed directly."
    }

def get_detailed_ssl_cert(host, port=443, timeout=3):
    """
    Extracts deep SSL/TLS certificate metadata using SNI hostname.
    Extracts Subject, Issuer CA, Expiry date, Days remaining, SANs, TLS version, and Cipher.
    """
    clean_host, _ = normalize_target(host)
    if not clean_host:
        clean_host = host.strip()
        
    cert_info = {
        "available": False,
        "host": clean_host,
        "port": port,
        "issuer": "Unknown",
        "subject": "Unknown",
        "sans": [],
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "status": "UNAVAILABLE",
        "tls_version": None,
        "cipher": None,
        "error": None
    }
    
    try:
        ctx = ssl.create_default_context()
        cert = None
        try:
            with socket.create_connection((clean_host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert = ssock.getpeercert()
                    cert_info["tls_version"] = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        cert_info["cipher"] = cipher[0]
                    cert_info["available"] = True
                    cert_info["status"] = "ACTIVE"
        except (ssl.SSLCertVerificationError, ssl.SSLError) as ve:
            cert_info["status"] = "UNTRUSTED_OR_EXPIRED"
            cert_info["error"] = str(ve)
            ctx_unver = ssl.create_default_context()
            ctx_unver.check_hostname = False
            ctx_unver.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((clean_host, port), timeout=timeout) as sock:
                    with ctx_unver.wrap_socket(sock, server_hostname=clean_host) as ssock:
                        cert_info["tls_version"] = ssock.version()
                        cipher = ssock.cipher()
                        if cipher:
                            cert_info["cipher"] = cipher[0]
                        cert_info["available"] = True
            except Exception:
                pass
            return cert_info

        if cert:
            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            cert_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
            
            subject_dict = dict(x[0] for x in cert.get("subject", ()))
            cert_info["subject"] = subject_dict.get("commonName") or "Unknown"
            
            sans = [val for key, val in cert.get("subjectAltName", ()) if key == "DNS"]
            cert_info["sans"] = sans[:15]
            
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            
            if not_before:
                cert_info["valid_from"] = not_before
            if not_after:
                cert_info["valid_until"] = not_after
                try:
                    exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    delta = (exp_date - datetime.utcnow()).days
                    cert_info["days_remaining"] = delta
                    if delta < 0:
                        cert_info["status"] = "EXPIRED"
                    elif delta <= 30:
                        cert_info["status"] = "EXPIRING_SOON"
                    else:
                        cert_info["status"] = "ACTIVE"
                except Exception:
                    pass
                    
        return cert_info
    except Exception as e:
        cert_info["error"] = f"SSL/TLS connection failed: {str(e)}"
        return cert_info

def analyze_domain(domain):
    """
    Dedicated comprehensive domain security & intelligence analyzer.
    Performs DNS, Email Anti-Spoofing (SPF/DMARC), CDN detection, SSL/TLS,
    HTTP Security headers, and Subdomain reconnaissance.
    """
    clean_domain, _ = normalize_target(domain)
    if not is_domain_target(clean_domain):
        return {
            "success": False,
            "error": f"'{domain}' is not a valid domain name."
        }
    
    osint_data = run_osint(clean_domain)
    return {
        "success": True,
        "domain": clean_domain,
        "data": osint_data
    }

def run_osint(target):
    """
    Gathers comprehensive OSINT data: Whois, DNS records (A, AAAA, MX, NS, TXT, Reverse PTR),
    GeoIP intelligence, SSL/TLS certificates, CDN detection, Email Security (SPF/DMARC),
    HTTP security headers, and Subdomains.
    """
    clean_target, _ = normalize_target(target)
    if not clean_target:
        clean_target = target.strip()
        
    results = {
        "target": clean_target,
        "is_domain": is_domain_target(clean_target)
    }
    
    # 1. Whois Intelligence
    try:
        w = whois.whois(clean_target)
        if w and w.get("domain_name"):
            results['whois'] = {
                "domain_name": w.get("domain_name"),
                "registrar": w.get("registrar"),
                "creation_date": str(w.get("creation_date")),
                "expiration_date": str(w.get("expiration_date")),
                "emails": w.get("emails"),
                "org": w.get("org")
            }
        else:
            results['whois'] = str(w) if w else "No whois data available"
    except Exception as e:
        results['whois'] = f"Whois lookup unavailable: {str(e)}"
    
    # 2. Domain-Specific vs IP-Specific Intelligence
    if results["is_domain"]:
        dns_intel = get_domain_dns_details(clean_target)
        results['dns'] = dns_intel
        results['email_security'] = analyze_email_security(clean_target, dns_intel.get("txt", []))
        results['cdn_proxy'] = detect_cdn_proxy(clean_target, ips=dns_intel.get("ipv4", []), cnames=dns_intel.get("cnames", []))
        detailed_ssl = get_detailed_ssl_cert(clean_target, port=443, timeout=3)
        results['ssl_cert_details'] = detailed_ssl
        if dns_intel.get("ipv4"):
            geoip = get_geoip_info(dns_intel["ipv4"][0])
            if geoip:
                results['geoip'] = geoip
    else:
        # IP Target: DNS & PTR
        dns_records = {}
        for rtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(clean_target, rtype, lifetime=2)
                dns_records[rtype] = [rdata.to_text() for rdata in answers]
            except Exception:
                pass
        try:
            ip_obj = ipaddress.ip_address(clean_target)
            rev_name = dns.reversename.from_address(clean_target)
            answers = dns.resolver.resolve(rev_name, 'PTR', lifetime=2)
            dns_records['PTR'] = [rdata.to_text() for rdata in answers]
        except Exception:
            pass
        results['dns'] = dns_records if dns_records else "No direct DNS records resolved"
        geoip = get_geoip_info(clean_target)
        if geoip:
            results['geoip'] = geoip

    # 3. Standard SSL/TLS basic metadata for backward compatibility
    ssl_info = get_ssl_cert_info(clean_target, port=443, timeout=2)
    if ssl_info and "error" not in ssl_info:
        results['ssl_tls'] = ssl_info

    # 4. HTTP Web Security Headers Audit
    http_sec = analyze_http_security(clean_target)
    if http_sec and http_sec.get("available"):
        results['http_security'] = http_sec
        # Re-check CDN with HTTP response headers if not previously detected
        if results.get("cdn_proxy") and not results["cdn_proxy"].get("is_proxied"):
            updated_cdn = detect_cdn_proxy(
                clean_target, 
                cnames=results.get("dns", {}).get("cnames", []) if isinstance(results.get("dns"), dict) else [],
                headers=http_sec.get("headers_audit", {})
            )
            if updated_cdn.get("is_proxied"):
                results["cdn_proxy"] = updated_cdn

    # 5. Subdomain Reconnaissance (for domains)
    if results["is_domain"]:
        subdomains = enumerate_subdomains(clean_target)
        if subdomains:
            results['subdomains'] = subdomains

    return results

def analyze_http_security(target):
    """
    Analyzes HTTP/HTTPS security headers, banner leaks, and cookie security flags.
    Returns a comprehensive audit dictionary with score and grade.
    """
    target = target.strip()
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        
    audit_results = {
        "target": clean_target,
        "available": False,
        "url": None,
        "status_code": None,
        "headers_audit": {},
        "server_leak": None,
        "powered_by": None,
        "cookies_audit": [],
        "score": 0,
        "grade": "F",
        "recommendations": []
    }
    
    resp = None
    used_url = None
    for scheme in ["https", "http"]:
        url = f"{scheme}://{clean_target}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=True, verify=False)
            resp = r
            used_url = url
            audit_results["available"] = True
            audit_results["url"] = used_url
            audit_results["status_code"] = r.status_code
            break
        except Exception:
            continue
            
    if not resp:
        audit_results["error"] = "No active HTTP/HTTPS service responded on target."
        return audit_results

    headers = {k.lower(): v for k, v in resp.headers.items()}
    score = 0
    recs = []

    # 1. HSTS
    if "strict-transport-security" in headers:
        audit_results["headers_audit"]["Strict-Transport-Security"] = {
            "status": "PASS",
            "value": headers["strict-transport-security"]
        }
        score += 25
    else:
        audit_results["headers_audit"]["Strict-Transport-Security"] = {
            "status": "MISSING",
            "value": None
        }
        recs.append("Enable HSTS (Strict-Transport-Security: max-age=31536000; includeSubDomains) to prevent SSL stripping attacks.")

    # 2. Content-Security-Policy
    if "content-security-policy" in headers:
        val = headers["content-security-policy"]
        audit_results["headers_audit"]["Content-Security-Policy"] = {
            "status": "PASS",
            "value": val[:100] + ("..." if len(val) > 100 else "")
        }
        score += 25
    else:
        audit_results["headers_audit"]["Content-Security-Policy"] = {
            "status": "MISSING",
            "value": None
        }
        recs.append("Configure Content-Security-Policy (CSP) to mitigate Cross-Site Scripting (XSS) and data injection.")

    # 3. X-Frame-Options
    if "x-frame-options" in headers:
        audit_results["headers_audit"]["X-Frame-Options"] = {
            "status": "PASS",
            "value": headers["x-frame-options"]
        }
        score += 15
    else:
        audit_results["headers_audit"]["X-Frame-Options"] = {
            "status": "MISSING",
            "value": None
        }
        recs.append("Set X-Frame-Options: SAMEORIGIN or DENY to protect against Clickjacking.")

    # 4. X-Content-Type-Options
    if headers.get("x-content-type-options", "").lower() == "nosniff":
        audit_results["headers_audit"]["X-Content-Type-Options"] = {
            "status": "PASS",
            "value": "nosniff"
        }
        score += 15
    else:
        audit_results["headers_audit"]["X-Content-Type-Options"] = {
            "status": "MISSING",
            "value": headers.get("x-content-type-options")
        }
        recs.append("Add X-Content-Type-Options: nosniff to prevent browser MIME-type sniffing.")

    # 5. Referrer-Policy
    if "referrer-policy" in headers:
        audit_results["headers_audit"]["Referrer-Policy"] = {
            "status": "PASS",
            "value": headers["referrer-policy"]
        }
        score += 10
    else:
        audit_results["headers_audit"]["Referrer-Policy"] = {
            "status": "MISSING",
            "value": None
        }
        recs.append("Specify Referrer-Policy (e.g. strict-origin-when-cross-origin) to protect sensitive URL parameters.")

    # 6. Permissions-Policy
    if "permissions-policy" in headers:
        audit_results["headers_audit"]["Permissions-Policy"] = {
            "status": "PASS",
            "value": headers["permissions-policy"][:80]
        }
        score += 10
    else:
        audit_results["headers_audit"]["Permissions-Policy"] = {
            "status": "MISSING",
            "value": None
        }

    # Leaks detection
    server_val = headers.get("server")
    if server_val:
        audit_results["server_leak"] = server_val
        recs.append(f"Web server version banner exposed: '{server_val}'. Consider suppressing the Server header.")

    powered_by = headers.get("x-powered-by")
    if powered_by:
        audit_results["powered_by"] = powered_by
        recs.append(f"Backend technology leaked: 'X-Powered-By: {powered_by}'. Remove this header in production.")

    # Cookies check
    for c in resp.cookies:
        audit_results["cookies_audit"].append({
            "name": c.name,
            "secure": c.secure,
            "has_httponly": bool(getattr(c, 'has_nonstandard_attr', lambda x: False)('HttpOnly') or getattr(c, '_rest', {}).get('HttpOnly') is not None),
            "samesite": getattr(c, '_rest', {}).get('SameSite')
        })

    # Grade calculation
    audit_results["score"] = score
    if score >= 85:
        audit_results["grade"] = "A"
    elif score >= 70:
        audit_results["grade"] = "B"
    elif score >= 50:
        audit_results["grade"] = "C"
    elif score >= 30:
        audit_results["grade"] = "D"
    else:
        audit_results["grade"] = "F"

    audit_results["recommendations"] = recs
    return audit_results

def enumerate_subdomains(target):
    """
    Performs fast DNS reconnaissance on common subdomains for a domain.
    """
    clean_target, _ = normalize_target(target)
    if not clean_target:
        clean_target = target.strip()
        
    try:
        ipaddress.ip_address(clean_target)
        return [] # Skip IP targets
    except ValueError:
        pass
        
    clean_domain = clean_target
    
    candidates = [
        "www", "api", "mail", "dev", "staging", "admin", "vpn",
        "app", "portal", "auth", "corp", "cdn", "test", "remote",
        "gateway", "cloud", "secure", "status", "beta", "sso",
        "gitlab", "jenkins", "dashboard", "internal", "db", "smtp",
        "stage", "origin", "m", "docs", "support", "mx"
    ]
    
    discovered = []
    for sub in candidates:
        subdomain = f"{sub}.{clean_domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=1.5)
            ips = [rdata.to_text() for rdata in answers]
            if ips:
                discovered.append({
                    "subdomain": subdomain,
                    "ips": ips,
                    "status": "online"
                })
        except Exception:
            continue
            
    return discovered

def generate_hardening_script(target, scan_summary, platform="linux"):
    """
    Generates an automated, production-ready remediation and hardening script (Bash or PowerShell)
    using Gemini AI based on detected open ports, vulnerabilities, and OSINT.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return (
            f"#!/bin/bash\n# Hardening generator offline: GEMINI_API_KEY not configured.\n"
            f"# Basic recommended UFW rules for {target}:\n"
            "sudo ufw default deny incoming\n"
            "sudo ufw default allow outgoing\n"
            "sudo ufw allow 22/tcp\n"
            "sudo ufw enable\n"
        )
        
    try:
        genai.configure(api_key=api_key)
        script_lang = "Bash script" if platform == "linux" else "PowerShell script"
        prompt = (
            f"You are a Principal Security Automation Engineer. "
            f"Based on the following security scan findings for target '{target}', generate an executable, "
            f"battle-tested {script_lang} to remediate vulnerabilities and harden the host.\n\n"
            f"Requirements:\n"
            f"1. Generate valid, executable script code.\n"
            f"2. Include defensive firewall rules (e.g. UFW/iptables for Linux, New-NetFirewallRule for Windows) "
            f"blocking unnecessary open ports while preserving secure management access.\n"
            f"3. Include service hardening commands for detected exposed services (e.g. SSH PermitRootLogin no, disabling legacy protocols, closing database ports to public).\n"
            f"4. Add comments above each section explaining the rationale and safe rollback instructions.\n\n"
            f"--- SCAN FINDINGS ---\n{scan_summary}"
        )
        
        text = call_gemini_with_fallback(prompt)
        if "```" in text:
            parts = text.split("```")
            if len(parts) >= 3:
                clean_script = parts[1]
                lines = clean_script.splitlines()
                if lines and lines[0].lower().strip() in ["bash", "sh", "powershell", "ps1"]:
                    clean_script = "\n".join(lines[1:])
                return clean_script.strip()
        return text
    except Exception as e:
        return f"# Error generating hardening script: {str(e)}"

def send_webhook_alert(webhook_url, message, alert_level='info'):
    """
    Sends an alert to a configured webhook (e.g. Discord/Slack).
    """
    if not webhook_url:
        return False
        
    color = 16711680 if alert_level == 'warning' else 3447003 # Red or Blue
    
    payload = {
        "content": f"🛡️ **Cybersecurity Assistant Alert**\nLevel: `{alert_level.upper()}`",
        "embeds": [{
            "title": "Security Posture Update",
            "description": message[:2000], # Discord 2048 character embed limit
            "color": color
        }]
    }
    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        return response.status_code in (200, 204)
    except Exception as e:
        logging.error(f"Failed to send webhook: {e}")
        return False

def test_webhook(webhook_url):
    """
    Sends a test verification ping to the webhook URL.
    Returns (success: bool, message: str)
    """
    if not webhook_url:
        return False, "Webhook URL cannot be empty."
    
    payload = {
        "content": "🔔 **AI-Cybersecurity Assistant**: Webhook connection test successful!",
        "embeds": [{
            "title": "Webhook Verification",
            "description": "Your alert notifications are configured correctly. Changes detected on monitored targets will trigger alerts here.",
            "color": 65280 # Green
        }]
    }
    try:
        resp = requests.post(webhook_url.strip(), json=payload, timeout=5)
        if resp.status_code in (200, 204):
            return True, "Webhook test alert sent successfully!"
        else:
            return False, f"Webhook endpoint returned status code {resp.status_code}."
    except Exception as e:
        return False, f"Failed to deliver test alert: {str(e)}"
