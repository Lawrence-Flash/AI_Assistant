import sys
import json
import logging
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
from rich.markdown import Markdown

from utils import (
    run_nmap_scan,
    check_nmap,
    is_valid_target,
    is_valid_subnet,
    analyze_scan_with_ai,
    chat_with_ai,
    run_osint,
    parse_nmap_ports,
    extract_risk_score,
    run_host_discovery,
    analyze_http_security,
    enumerate_subdomains,
    generate_hardening_script,
    is_valid_port_spec,
    normalize_target,
    is_domain_target,
    analyze_domain,
    get_detailed_ssl_cert
)
from db import init_db, save_scan, get_history, get_scan_by_id, delete_scan, update_scan_notes

# Setup simple console logging instead of file logging for CLI
logging.basicConfig(level=logging.ERROR, format="%(message)s")

console = Console()

def display_header():
    console.clear()
    header = Text("🛡️  AI-CYBERSECURITY ASSISTANT (ENTERPRISE WORK TERMINAL)", style="bold cyan", justify="center")
    console.print(Panel(header, border_style="cyan"))
    console.print()

def display_domain_profile(target, osint_data):
    dns_data = osint_data.get("dns", {})
    cdn_data = osint_data.get("cdn_proxy", {})
    whois_data = osint_data.get("whois", {})
    
    table = Table(title=f"🌐 Domain & Infrastructure Profile: {target}", header_style="bold cyan")
    table.add_column("Property", style="bold white", width=24)
    table.add_column("Value", style="cyan")
    
    # IPv4
    ipv4s = dns_data.get("ipv4", []) if isinstance(dns_data, dict) else []
    table.add_row("Resolved IPv4", ", ".join(ipv4s) if ipv4s else "None resolved")
    
    # IPv6
    ipv6s = dns_data.get("ipv6", []) if isinstance(dns_data, dict) else []
    if ipv6s:
        table.add_row("Resolved IPv6", ", ".join(ipv6s))
        
    # CNAME
    cnames = dns_data.get("cnames", []) if isinstance(dns_data, dict) else []
    if cnames:
        table.add_row("Canonical Name (CNAME)", ", ".join(cnames))
        
    # CDN / Proxy
    if cdn_data.get("is_proxied"):
        table.add_row("Cloud / CDN Shield", f"[bold yellow]🛡️ {cdn_data.get('provider')} (Reverse Proxy)[/bold yellow]")
    else:
        table.add_row("Cloud / CDN Shield", "[green]Direct / Origin Server[/green]")
        
    # Mail Servers
    mx_list = dns_data.get("mx", []) if isinstance(dns_data, dict) else []
    if mx_list:
        table.add_row("Mail Servers (MX)", "\n".join(mx_list[:3]))
        
    # Name Servers
    ns_list = dns_data.get("ns", []) if isinstance(dns_data, dict) else []
    if ns_list:
        table.add_row("Name Servers (NS)", ", ".join(ns_list[:3]))
        
    # Registrar / Expiry
    if isinstance(whois_data, dict):
        if whois_data.get("registrar"):
            table.add_row("Registrar", str(whois_data.get("registrar")))
        if whois_data.get("expiration_date"):
            table.add_row("Domain Expiry", str(whois_data.get("expiration_date"))[:10])
            
    console.print(table)

def display_email_security(email_sec):
    if not email_sec:
        return
    overall = email_sec.get("overall", "UNKNOWN")
    overall_color = "green" if overall == "PROTECTED" else "yellow" if overall == "PARTIALLY PROTECTED" else "red"
    
    table = Table(
        title=f"📧 Email Anti-Spoofing & Domain Authentication ([{overall_color}]{overall}[/{overall_color}])",
        header_style="bold magenta"
    )
    table.add_column("Defense Protocol", style="bold white", width=20)
    table.add_column("Status", width=12)
    table.add_column("Configured Policy / Details", style="dim")
    
    # SPF
    spf = email_sec.get("spf", {})
    spf_status = spf.get("status", "MISSING")
    spf_color = "green" if spf_status == "PASS" else "yellow" if spf_status in ["WARNING", "WEAK"] else "red"
    table.add_row(
        "SPF (Sender Policy)",
        f"[{spf_color}]{spf_status}[/{spf_color}]",
        spf.get("policy") or "No TXT SPF record configured (vulnerable to spoofing)"
    )
    
    # DMARC
    dmarc = email_sec.get("dmarc", {})
    dmarc_status = dmarc.get("status", "MISSING")
    dmarc_color = "green" if dmarc_status == "PASS" else "yellow" if dmarc_status == "WARNING" else "red"
    dmarc_details = dmarc.get("policy") or "No _dmarc record found (unauthenticated mail allowed)"
    if dmarc.get("rua"):
        dmarc_details += f" | Reports: {dmarc.get('rua')}"
    table.add_row(
        "DMARC Enforcement",
        f"[{dmarc_color}]{dmarc_status}[/{dmarc_color}]",
        dmarc_details
    )
    console.print(table)

def display_ssl_cert(ssl_details):
    if not ssl_details or not ssl_details.get("available"):
        return
    status = ssl_details.get("status", "UNKNOWN")
    days = ssl_details.get("days_remaining")
    status_color = "green" if status == "ACTIVE" else "yellow" if status == "EXPIRING_SOON" else "red"
    
    title = f"🔒 SSL/TLS Certificate Audit ([{status_color}]{status}[/{status_color}])"
    if days is not None:
        title += f" — {days} days remaining"
        
    table = Table(title=title, header_style="bold cyan")
    table.add_column("Certificate Attribute", style="bold white", width=22)
    table.add_column("Value", style="cyan")
    
    table.add_row("Issuer (CA)", str(ssl_details.get("issuer", "Unknown")))
    table.add_row("Subject CN", str(ssl_details.get("subject", "Unknown")))
    table.add_row("Valid Until", str(ssl_details.get("valid_until", "Unknown")))
    if ssl_details.get("tls_version"):
        table.add_row("Protocol & Cipher", f"{ssl_details.get('tls_version')} ({ssl_details.get('cipher', 'Unknown')})")
    sans = ssl_details.get("sans", [])
    if sans:
        table.add_row("Covered SANs", ", ".join(sans[:5]) + (f" (+{len(sans)-5} more)" if len(sans) > 5 else ""))
        
    console.print(table)

def display_ports(ports):
    if ports:
        port_table = Table(title=f"Detected Open Ports ({len(ports)})", header_style="bold cyan")
        port_table.add_column("Port/Proto", style="bold yellow")
        port_table.add_column("State", style="bold green")
        port_table.add_column("Service", style="white")
        port_table.add_column("Version", style="dim")
        for p in ports:
            port_table.add_row(p["port"], p["state"], p["service"], p.get("version", "N/A"))
        console.print(port_table)
    else:
        console.print("[yellow]No open ports detected in raw Nmap output.[/yellow]")

def display_http_security(http_sec):
    if http_sec and http_sec.get("available"):
        grade = http_sec.get("grade", "F")
        grade_color = "green" if grade in ["A", "B"] else "yellow" if grade == "C" else "red"
        hdr_table = Table(title=f"HTTP Security Headers Audit (Grade: [{grade_color}]{grade}[/{grade_color}] | Score: {http_sec.get('score')}/100)", header_style="bold blue")
        hdr_table.add_column("Security Header", style="bold white")
        hdr_table.add_column("Status", width=10)
        hdr_table.add_column("Details", style="dim")
        for hname, hinfo in http_sec.get("headers_audit", {}).items():
            status = hinfo.get("status")
            scolor = "green" if status == "PASS" else "red"
            hdr_table.add_row(hname, f"[{scolor}]{status}[/{scolor}]", hinfo.get("value") or "Missing / Not Set")
        console.print(hdr_table)

def display_subdomains(subs):
    if subs:
        sub_table = Table(title=f"Discovered Subdomains ({len(subs)})", header_style="bold green")
        sub_table.add_column("Subdomain", style="bold cyan")
        sub_table.add_column("Resolved IP(s)", style="white")
        for s in subs:
            sub_table.add_row(s["subdomain"], ", ".join(s.get("ips", [])))
        console.print(sub_table)

def menu():
    while True:
        display_header()
        console.print("[1] 🌐 Comprehensive Target Scan (Nmap + Domain Recon + AI)", style="bold green")
        console.print("[2] 🛡️  Generate Hardening & Remediation Script", style="bold cyan")
        console.print("[3] 📡 Discover Hosts on Subnet (LAN Sweep)", style="bold blue")
        console.print("[4] 🔍 Domain Intelligence & Email Security Deep-Dive", style="bold yellow")
        console.print("[5] 🌍 Subdomain Reconnaissance", style="bold white")
        console.print("[6] 📜 View Scan History & Client Archives", style="bold magenta")
        console.print("[7] 🛠️  Check Nmap Status", style="dim")
        console.print("[8] ❌ Exit", style="bold red")
        console.print()
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
        
        if choice == "1":
            handle_scan()
        elif choice == "2":
            handle_hardening_standalone()
        elif choice == "3":
            handle_discovery()
        elif choice == "4":
            handle_domain_audit()
        elif choice == "5":
            handle_subdomains()
        elif choice == "6":
            handle_history()
        elif choice == "7":
            handle_check_nmap()
        elif choice == "8":
            console.print("Exiting... Stay secure! 👋", style="bold magenta")
            sys.exit(0)

def handle_scan(prefill_target=None):
    console.print("\n[bold cyan]--- Enterprise Security Scan ---[/bold cyan]")
    if prefill_target:
        raw_target = prefill_target
        console.print(f"Target: [bold green]{raw_target}[/bold green]")
    else:
        raw_target = Prompt.ask("Enter target IP, Hostname or Domain (e.g. scanme.nmap.org, 192.168.1.1, https://example.com)")
    
    clean_target, extracted_port = normalize_target(raw_target)
    if not clean_target:
        clean_target = raw_target.strip()
        
    if not is_valid_target(clean_target):
        console.print(f"[bold red]Invalid target '{raw_target}'. Please provide a valid IP address or domain name.[/bold red]")
        Prompt.ask("Press Enter to continue")
        return

    if clean_target != raw_target:
        console.print(f"[dim cyan]Normalized target:[/dim cyan] [bold green]{clean_target}[/bold green]" + (f" (Detected Port: {extracted_port})" if extracted_port else ""))

    target = clean_target
    client_tag = Prompt.ask("Client / Project Tag", default="General")
    scan_type = Prompt.ask("Select scan profile", choices=["fast", "advanced", "web", "stealth", "vuln", "full"], default="fast")
    default_port = extracted_port if extracted_port else ""
    custom_ports = Prompt.ask("Custom ports (optional, e.g. 80,443 or 1-1024, press Enter to skip)", default=default_port)

    # 1. Run Nmap
    ports_arg = custom_ports.strip() if custom_ports.strip() else None
    with console.status(f"[bold green]Running Nmap ({scan_type} profile) on {target}...[/bold green]"):
        success, result = run_nmap_scan(target, scan_type=scan_type, custom_ports=ports_arg)

    if not success:
        console.print(f"[bold red]Scan failed:[/bold red]\n{result}")
        Prompt.ask("\nPress Enter to return to menu")
        return

    # 2. Run OSINT & Domain Recon
    with console.status("[bold cyan]Gathering OSINT, DNS, Email Security, SSL & Subdomains...[/bold cyan]"):
        osint_data = run_osint(target)

    # 3. Domain Profile or IP Geolocation
    if is_domain_target(target):
        display_domain_profile(target, osint_data)
        display_email_security(osint_data.get("email_security"))
        display_ssl_cert(osint_data.get("ssl_cert_details"))
    elif osint_data.get("geoip"):
        geoip = osint_data["geoip"]
        geo_table = Table(title=f"📍 IP Geolocation & Network: {target}", header_style="bold blue")
        geo_table.add_column("Property", style="bold white", width=20)
        geo_table.add_column("Details", style="cyan")
        geo_table.add_row("Country / City", f"{geoip.get('country', 'N/A')} - {geoip.get('city', 'N/A')}")
        geo_table.add_row("ISP / Org", f"{geoip.get('isp', 'N/A')} ({geoip.get('org', 'N/A')})")
        geo_table.add_row("Autonomous System", geoip.get("as", "N/A"))
        console.print(geo_table)

    # 4. Display Open Ports
    ports = parse_nmap_ports(result)
    display_ports(ports)

    # 5. Display HTTP Security Headers Audit
    display_http_security(osint_data.get("http_security"))

    # 6. Display Subdomains
    display_subdomains(osint_data.get("subdomains"))

    # 7. AI Threat Analysis
    with console.status("[bold magenta]🤖 Synthesizing threat report with Gemini AI...[/bold magenta]"):
        ai_prompt = f"--- NMAP RAW ---\n{result}\n\n--- OSINT & DOMAIN RECON INTELLIGENCE ---\n{json.dumps(osint_data, indent=2)}"
        ai_analysis = analyze_scan_with_ai(ai_prompt)
        risk_level = extract_risk_score(ai_analysis)

    # Display AI Report
    risk_color = "red" if risk_level in ["CRITICAL", "HIGH"] else "yellow" if risk_level == "MEDIUM" else "green"
    console.print(Panel(
        Markdown(ai_analysis), 
        title=f"🧠 AI Cybersecurity Report | Risk Level: [{risk_color}]{risk_level}[/{risk_color}] | Tag: {client_tag}", 
        border_style=risk_color
    ))

    # Persist to database
    save_scan(
        target=target,
        result=f"{ai_prompt}\n\n--- AI ANALYSIS ---\n{ai_analysis}",
        nmap_result=result,
        osint_result=json.dumps(osint_data),
        ai_analysis=ai_analysis,
        risk_level=risk_level,
        client_tag=client_tag
    )
    console.print("[bold green]✅ Scan results and domain audit archived to database.[/bold green]")

    # Option to Generate Hardening Script immediately
    if Confirm.ask("\nGenerate an automated Hardening & Remediation Script for this target?", default=True):
        platform = Prompt.ask("Choose target OS", choices=["linux", "windows"], default="linux")
        with console.status(f"[bold cyan]Generating {platform} hardening script...[/bold cyan]"):
            script = generate_hardening_script(target, ai_analysis, platform=platform)
        console.print(Panel(script, title=f"🛡️ Hardening Script ({platform.upper()})", border_style="cyan"))

    # Interactive Chat Advisor Loop
    if Confirm.ask("\nWould you like to ask the AI Advisor questions about this scan?", default=False):
        chat_context = f"Target: {target}\nNmap:\n{result}\nAI Analysis:\n{ai_analysis}"
        chat_history = []
        console.print("[italic cyan]Type your question below (or 'exit' to return to menu):[/italic cyan]")
        while True:
            q = Prompt.ask("\n[bold cyan]You[/bold cyan]")
            if not q.strip() or q.strip().lower() in ["exit", "quit", "q"]:
                break
            with console.status("[magenta]AI Advisor thinking...[/magenta]"):
                reply = chat_with_ai(chat_history, q, chat_context)
            console.print(Panel(Markdown(reply), title="🤖 AI Cyber Advisor", border_style="cyan"))
            chat_history.append({"role": "user", "content": q})
            chat_history.append({"role": "model", "content": reply})

    Prompt.ask("\nPress Enter to return to menu")

def handle_domain_audit():
    console.print("\n[bold cyan]--- 🌐 Domain Intelligence & Email Security Deep-Dive ---[/bold cyan]")
    raw_domain = Prompt.ask("Enter target domain or URL (e.g. google.com, scanme.nmap.org, https://example.com/api)")
    clean_domain, _ = normalize_target(raw_domain)
    if not clean_domain:
        clean_domain = raw_domain.strip()
        
    if not is_domain_target(clean_domain):
        console.print(f"[bold red]'{raw_domain}' is not recognized as a valid domain name (IP addresses should be scanned via Option [1]).[/bold red]")
        Prompt.ask("Press Enter to continue")
        return
        
    with console.status(f"[bold cyan]Running rapid DNS, Email Security, CDN, SSL & Web Audit on {clean_domain}...[/bold cyan]"):
        audit_res = analyze_domain(clean_domain)
        
    if not audit_res.get("success"):
        console.print(f"[bold red]Audit failed:[/bold red] {audit_res.get('error')}")
        Prompt.ask("Press Enter to return")
        return
        
    data = audit_res["data"]
    
    # 1. Domain Profile
    display_domain_profile(clean_domain, data)
    
    # 2. Email Security
    display_email_security(data.get("email_security"))
    
    # 3. SSL/TLS Details
    display_ssl_cert(data.get("ssl_cert_details"))
    
    # 4. HTTP Headers
    display_http_security(data.get("http_security"))
    
    # 5. Subdomains
    display_subdomains(data.get("subdomains"))
    
    console.print("\n[bold green]✅ Domain intelligence audit complete.[/bold green]")
    
    # Quick action prompt
    action = Prompt.ask(
        "Next Action: [S]can ports with Nmap | [A]sk AI Advisor | [M]enu", 
        choices=["s", "a", "m"], 
        default="m"
    )
    if action == "s":
        handle_scan(prefill_target=clean_domain)
    elif action == "a":
        with console.status("[bold magenta]🤖 Consulting AI on domain security posture...[/bold magenta]"):
            prompt = f"--- DOMAIN INTELLIGENCE AUDIT FOR {clean_domain} ---\n{json.dumps(data, indent=2)}"
            analysis = analyze_scan_with_ai(prompt)
        console.print(Panel(Markdown(analysis), title=f"🤖 Domain Security Analysis: {clean_domain}", border_style="cyan"))
        Prompt.ask("\nPress Enter to return to menu")

def handle_hardening_standalone():
    console.print("\n[bold cyan]--- Automated Remediation Script Generator ---[/bold cyan]")
    target = Prompt.ask("Enter target IP or Hostname")
    if not is_valid_target(target):
        console.print("[bold red]Invalid target format.[/bold red]")
        Prompt.ask("Press Enter to continue")
        return
        
    findings = Prompt.ask("Describe detected services/vulnerabilities (e.g. Open SSH 22, Port 80 HTTP, Telnet 23)")
    platform = Prompt.ask("Target Platform", choices=["linux", "windows"], default="linux")
    
    with console.status(f"[bold cyan]Generating battle-tested {platform} hardening script...[/bold cyan]"):
        script = generate_hardening_script(target, findings, platform=platform)
    console.print(Panel(script, title=f"🛡️ Hardening Script for {target} ({platform.upper()})", border_style="cyan"))
    Prompt.ask("\nPress Enter to return to menu")

def handle_subdomains():
    console.print("\n[bold cyan]--- Subdomain Reconnaissance ---[/bold cyan]")
    domain = Prompt.ask("Enter base domain name (e.g. example.com)")
    
    with console.status(f"[bold yellow]Enumerating subdomains for {domain}...[/bold yellow]"):
        subs = enumerate_subdomains(domain)
        
    if not subs:
        console.print("[yellow]No active subdomains discovered from the standard list.[/yellow]")
    else:
        table = Table(title=f"Discovered Subdomains for {domain} ({len(subs)})", header_style="bold green")
        table.add_column("Subdomain", style="bold cyan")
        table.add_column("IP Address", style="white")
        for s in subs:
            table.add_row(s["subdomain"], ", ".join(s.get("ips", [])))
        console.print(table)
        
        if Confirm.ask("\nDo you want to run a scan on one of these subdomains?", default=False):
            choice = Prompt.ask(f"Select subdomain number (1-{len(subs)})")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(subs):
                    handle_scan(prefill_target=subs[idx]["subdomain"])
                    return
            except ValueError:
                pass
    Prompt.ask("\nPress Enter to return to menu")

def handle_discovery():
    console.print("\n[bold cyan]--- Local Subnet Host Sweeper ---[/bold cyan]")
    subnet = Prompt.ask("Enter CIDR network or range to sweep", default="192.168.1.0/24")
    
    if not is_valid_subnet(subnet) and not is_valid_target(subnet):
        console.print("[bold red]Invalid subnet format. Example: 192.168.1.0/24[/bold red]")
        Prompt.ask("Press Enter to continue")
        return

    with console.status(f"[bold blue]Sweeping {subnet} with Nmap ping sweep (-sn)...[/bold blue]"):
        success, hosts = run_host_discovery(subnet)

    if not success:
        console.print(f"[bold red]Host discovery failed:[/bold red] {hosts}")
        Prompt.ask("\nPress Enter to continue")
        return

    if not hosts:
        console.print("[yellow]No active hosts replied on the specified subnet.[/yellow]")
        Prompt.ask("\nPress Enter to return to menu")
        return

    table = Table(title=f"Discovered Live Hosts ({len(hosts)})", header_style="bold green")
    table.add_column("#", style="dim", width=4)
    table.add_column("IP Address", style="bold cyan")
    table.add_column("Hostname", style="white")
    table.add_column("Latency / Status", style="green")
    table.add_column("MAC / Vendor", style="yellow")

    for idx, h in enumerate(hosts, 1):
        table.add_row(
            str(idx),
            h.get("ip", ""),
            h.get("hostname", "Unknown"),
            h.get("latency", "Online"),
            h.get("vendor") or h.get("mac") or "N/A"
        )
    console.print(table)

    if Confirm.ask("\nDo you want to scan one of these discovered targets now?", default=True):
        choice = Prompt.ask(f"Select host number (1-{len(hosts)})")
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(hosts):
                handle_scan(prefill_target=hosts[choice_idx]["ip"])
                return
        except ValueError:
            pass
        console.print("[bold red]Invalid selection.[/bold red]")

    Prompt.ask("\nPress Enter to return to menu")

def handle_history():
    console.print("\n[bold cyan]--- Archived Scan History ---[/bold cyan]")
    history = get_history()
    
    if not history:
        console.print("No scan history found.", style="italic yellow")
        Prompt.ask("\nPress Enter to return to menu")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=5)
    table.add_column("Target", min_width=16, style="bold cyan")
    table.add_column("Client Tag", style="bold white", width=14)
    table.add_column("Risk Level", width=12)
    table.add_column("Timestamp", min_width=18)
    
    for row in history:
        # id, target, timestamp, result, risk_level, client_tag, analyst_notes
        risk = row[4] if len(row) > 4 and row[4] else "LOW"
        client_tag = row[5] if len(row) > 5 and row[5] else "General"
        risk_color = "red" if risk in ["CRITICAL", "HIGH"] else "yellow" if risk == "MEDIUM" else "green"
        table.add_row(str(row[0]), row[1], client_tag, f"[{risk_color}]{risk}[/{risk_color}]", row[2])
        
    console.print(table)
    
    action = Prompt.ask(
        "Choose an action",
        choices=["view", "notes", "remediate", "delete", "back"],
        default="view"
    )

    if action == "view":
        scan_id = Prompt.ask("Enter Scan ID to inspect")
        try:
            scan = get_scan_by_id(int(scan_id))
            if scan:
                console.print(Panel(
                    Markdown(scan["ai_analysis"]),
                    title=f"AI Report for {scan['target']} (#{scan['id']}) | Client: {scan['client_tag']} | Risk: {scan['risk_level']}",
                    border_style="magenta"
                ))
                if scan.get("analyst_notes"):
                    console.print(Panel(scan["analyst_notes"], title="📝 Analyst Notes", border_style="yellow"))
            else:
                console.print("[bold red]Scan ID not found.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid Scan ID.[/bold red]")

    elif action == "notes":
        scan_id = Prompt.ask("Enter Scan ID to attach/edit notes")
        try:
            scan = get_scan_by_id(int(scan_id))
            if scan:
                console.print(f"Current Notes: [italic]{scan.get('analyst_notes') or '(None)'}[/italic]")
                new_notes = Prompt.ask("Enter updated analyst notes")
                new_tag = Prompt.ask(f"Update Client Tag (current: {scan.get('client_tag', 'General')})", default=scan.get('client_tag', 'General'))
                update_scan_notes(int(scan_id), new_notes, new_tag)
                console.print("[bold green]✅ Documentation saved.[/bold green]")
            else:
                console.print("[bold red]Scan ID not found.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid Scan ID.[/bold red]")

    elif action == "remediate":
        scan_id = Prompt.ask("Enter Scan ID to generate hardening script")
        try:
            scan = get_scan_by_id(int(scan_id))
            if scan:
                platform = Prompt.ask("Platform", choices=["linux", "windows"], default="linux")
                with console.status("Generating hardening script..."):
                    script = generate_hardening_script(scan["target"], scan["ai_analysis"], platform=platform)
                console.print(Panel(script, title=f"🛡️ Hardening Script for {scan['target']} ({platform.upper()})", border_style="cyan"))
            else:
                console.print("[bold red]Scan ID not found.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid Scan ID.[/bold red]")
            
    elif action == "delete":
        scan_id = Prompt.ask("Enter Scan ID to delete")
        try:
            if delete_scan(int(scan_id)):
                console.print(f"[bold green]Scan #{scan_id} deleted successfully.[/bold green]")
            else:
                console.print("[bold red]Scan ID not found.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid Scan ID.[/bold red]")
            
    Prompt.ask("\nPress Enter to return to menu")

def handle_check_nmap():
    console.print("\n[bold cyan]--- Nmap Status ---[/bold cyan]")
    with console.status("Checking Nmap installation..."):
        is_installed = check_nmap()
        
    if is_installed:
        console.print("[bold green]✅ Nmap is installed and available in the system PATH.[/bold green]")
    else:
        console.print("[bold red]❌ Nmap is NOT installed or not found in the system PATH.[/bold red]")
        console.print("Please install Nmap to use the scanning features.")
        
    Prompt.ask("\nPress Enter to return to menu")

if __name__ == "__main__":
    init_db()
    try:
        menu()
    except KeyboardInterrupt:
        console.print("\nExiting... Goodbye! 👋", style="bold magenta")
        sys.exit(0)
