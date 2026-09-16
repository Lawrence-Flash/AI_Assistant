import json
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_apscheduler import APScheduler

from utils import (
    run_nmap_scan,
    check_nmap,
    analyze_scan_with_ai,
    chat_with_ai,
    run_osint,
    send_webhook_alert,
    test_webhook as test_webhook_conn,
    parse_nmap_ports,
    extract_risk_score,
    run_host_discovery,
    analyze_http_security,
    enumerate_subdomains,
    generate_hardening_script,
    is_valid_port_spec,
    normalize_target,
    is_domain_target,
    analyze_domain
)
from db import (
    init_db,
    save_scan,
    get_history,
    get_scan_by_id,
    delete_scan,
    update_scan_notes,
    add_to_watchlist,
    get_watchlist,
    get_watchlist_target,
    delete_from_watchlist,
    get_diff_logs,
    save_diff_log,
    update_watchlist_time,
    get_latest_scan,
    get_setting,
    set_setting,
    save_osint
)

app = Flask(__name__)
app.secret_key = "cybersecurity-ai-assistant-secret"

# Configure Scheduler
class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# Initialize database schema
init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(".", "generated-icon.png", mimetype="image/png")

import requests
import json
import logging

# ... (Keep existing imports and setup) ...

@app.route("/search_cve", methods=["POST"])
def search_cve():
    """
    Queries the National Vulnerability Database (NVD) via NIST API or CIRCL CVE API
    to find known exploits for a specific service or keyword.
    """
    data = request.json or {}
    keyword = data.get("keyword")
    if not keyword:
        return jsonify({"error": "Keyword (e.g., 'apache 2.4.49') is required."}), 400

    try:
        # Using CIRCL's public CVE API as it doesn't require an API key and is fast for mobile
        url = f"https://cve.circl.lu/api/search/{keyword.lower()}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            results = response.json()
            if hasattr(results, 'get') and results.get("error"):
                # Handle unexpected API errors gracefully
                 return jsonify({"success": True, "keyword": keyword, "cves": []})

            # Format the top 5 CVEs
            formatted_cves = []
            # CIRCL sometimes returns a dictionary depending on exact match vs full text search
            # We'll handle it if it returns a list of CVE objects
            if isinstance(results, list):
                for item in results[:5]:
                    formatted_cves.append({
                        "id": item.get("id", "Unknown"),
                        "cvss": item.get("cvss", "N/A"),
                        "summary": item.get("summary", "")[:200] + "..."
                    })
            return jsonify({"success": True, "keyword": keyword, "cves": formatted_cves})
        else:
            return jsonify({"error": f"CVE Database returned status {response.status_code}"}), 502
    except Exception as e:
        return jsonify({"error": f"Failed to query CVE database: {str(e)}"}), 500

@app.route("/audit_config", methods=["POST"])
def audit_config():
    data = request.json or {}
    config_text = data.get("config_text")
    if not config_text:
        return jsonify({"error": "Configuration text is required."}), 400

    analysis = audit_local_config(config_text)
    return jsonify({"success": True, "analysis": analysis})

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json or {}
    target = data.get("target")
    scan_type = data.get("scan_type", "fast")
    custom_ports = data.get("custom_ports")
    client_tag = data.get("client_tag", "General")
    analyst_notes = data.get("analyst_notes", "")
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    clean_target, extracted_port = normalize_target(target)
    if not clean_target:
        clean_target = target.strip()
    if not custom_ports and extracted_port:
        custom_ports = extracted_port
    target = clean_target
        
    # 1. Run Nmap scan with custom ports support
    success, nmap_result = run_nmap_scan(target, scan_type, custom_ports=custom_ports)
    if not success:
        return jsonify({"error": nmap_result}), 500
        
    # 2. Run OSINT intelligence gathering (includes HTTP audit & Subdomains)
    osint_result = run_osint(target)
    
    # 3. Parse structured ports
    ports = parse_nmap_ports(nmap_result)
    
    # 4. Run Gemini AI Security Analysis
    ai_prompt = f"--- NMAP RAW ---\n{nmap_result}\n\n--- OSINT & WEB INTELLIGENCE ---\n{json.dumps(osint_result, indent=2)}"
    ai_analysis = analyze_scan_with_ai(ai_prompt)
    risk_level = extract_risk_score(ai_analysis)
    
    # 5. Persist to database with client_tag and analyst_notes
    save_osint(target, json.dumps(osint_result))
    full_result = f"{ai_prompt}\n\n--- AI ANALYSIS ---\n{ai_analysis}"
    scan_id = save_scan(
        target=target,
        result=full_result,
        nmap_result=nmap_result,
        osint_result=json.dumps(osint_result),
        ai_analysis=ai_analysis,
        risk_level=risk_level,
        client_tag=client_tag,
        analyst_notes=analyst_notes
    )
    
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "target": target,
        "client_tag": client_tag,
        "analyst_notes": analyst_notes,
        "nmap_result": nmap_result,
        "osint_result": osint_result,
        "ai_analysis": ai_analysis,
        "ports": ports,
        "risk_level": risk_level
    })

@app.route("/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        return jsonify({"error": "Scan not found"}), 404
        
    # Parse ports from stored nmap_result or fallback result
    nmap_content = scan_data["nmap_result"] or scan_data["result"]
    ports = parse_nmap_ports(nmap_content)
    
    # Try parsing stored osint JSON
    osint_content = scan_data["osint_result"]
    try:
        osint_parsed = json.loads(osint_content) if osint_content else {}
    except Exception:
        osint_parsed = {"raw": osint_content}
        
    return jsonify({
        "id": scan_data["id"],
        "target": scan_data["target"],
        "timestamp": scan_data["timestamp"],
        "nmap_result": scan_data["nmap_result"] or scan_data["result"],
        "osint_result": osint_parsed,
        "ai_analysis": scan_data["ai_analysis"] or "No archived AI analysis available for this legacy scan.",
        "ports": ports,
        "risk_level": scan_data["risk_level"] or "LOW",
        "client_tag": scan_data.get("client_tag", "General"),
        "analyst_notes": scan_data.get("analyst_notes", "")
    })

@app.route("/scan/<int:scan_id>/notes", methods=["POST"])
def update_notes(scan_id):
    data = request.json or {}
    notes = data.get("analyst_notes", "")
    client_tag = data.get("client_tag")
    success = update_scan_notes(scan_id, notes, client_tag)
    if success:
        return jsonify({"success": True, "message": "Scan documentation updated successfully."})
    return jsonify({"error": "Scan record not found."}), 404

@app.route("/remediation", methods=["POST"])
def generate_remediation():
    data = request.json or {}
    target = data.get("target")
    scan_summary = data.get("scan_summary", "")
    platform = data.get("platform", "linux")
    
    if not target or not scan_summary:
        return jsonify({"error": "Target and scan findings are required."}), 400
        
    script = generate_hardening_script(target, scan_summary, platform=platform)
    return jsonify({"success": True, "script": script, "platform": platform})

@app.route("/subdomains", methods=["POST"])
def subdomains_recon():
    data = request.json or {}
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "Domain is required."}), 400
        
    discovered = enumerate_subdomains(domain)
    return jsonify({"success": True, "domain": domain, "subdomains": discovered})

@app.route("/http_audit", methods=["POST"])
def http_audit():
    data = request.json or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "Target is required."}), 400
        
    audit = analyze_http_security(target)
    return jsonify({"success": True, "audit": audit})

@app.route("/domain_audit", methods=["POST"])
def domain_audit():
    data = request.json or {}
    domain = data.get("domain") or data.get("target")
    if not domain:
        return jsonify({"error": "Domain name is required."}), 400
        
    clean_domain, _ = normalize_target(domain)
    if not clean_domain:
        clean_domain = domain.strip()
        
    result = analyze_domain(clean_domain)
    if not result.get("success"):
        return jsonify({"error": result.get("error")}), 400
        
    return jsonify(result)

@app.route("/history", methods=["GET"])
def history():
    history_data = get_history()
    formatted = [
        {
            "id": row[0],
            "target": row[1],
            "timestamp": row[2],
            "risk_level": row[4] if len(row) > 4 and row[4] else "LOW",
            "client_tag": row[5] if len(row) > 5 and row[5] else "General",
            "analyst_notes": row[6] if len(row) > 6 and row[6] else ""
        }
        for row in history_data
    ]
    return jsonify(formatted)

@app.route("/history/<int:scan_id>", methods=["DELETE"])
def delete_history_item(scan_id):
    deleted = delete_scan(scan_id)
    if deleted:
        return jsonify({"success": True, "message": f"Scan #{scan_id} deleted."})
    return jsonify({"error": "Scan not found"}), 404

@app.route("/discover", methods=["POST"])
def discover_hosts():
    data = request.json or {}
    subnet = data.get("subnet")
    if not subnet:
        return jsonify({"error": "Subnet / IP range is required (e.g. 192.168.1.0/24)"}), 400
        
    success, result = run_host_discovery(subnet)
    if success:
        return jsonify({"success": True, "hosts": result})
    else:
        return jsonify({"success": False, "error": result}), 400

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        data = request.json or {}
        webhook_url = data.get("webhook_url", "")
        set_setting("webhook_url", webhook_url)
        return jsonify({"success": True, "message": "Settings saved"})
    
    webhook_url = get_setting("webhook_url", "")
    return jsonify({"webhook_url": webhook_url})

@app.route("/test_webhook", methods=["POST"])
def trigger_test_webhook():
    data = request.json or {}
    webhook_url = data.get("webhook_url") or get_setting("webhook_url")
    if not webhook_url:
        return jsonify({"success": False, "error": "No webhook URL configured."}), 400
        
    success, message = test_webhook_conn(webhook_url)
    if success:
        return jsonify({"success": True, "message": message})
    return jsonify({"success": False, "error": message}), 400

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json or {}
    chat_history = data.get("history", [])
    new_message = data.get("message")
    scan_context = data.get("scan_context", "")
    
    if not new_message:
        return jsonify({"error": "Message is required"}), 400
        
    ai_reply = chat_with_ai(chat_history, new_message, scan_context)
    return jsonify({"reply": ai_reply})

@app.route("/watchlist", methods=["GET", "POST"])
def manage_watchlist():
    if request.method == "POST":
        data = request.json or {}
        target = data.get("target")
        scan_type = data.get("scan_type", "fast")
        interval = data.get("interval", 24)
        
        if not target:
            return jsonify({"error": "Target required"}), 400
            
        success = add_to_watchlist(target, scan_type, interval)
        if success:
            return jsonify({"success": True, "message": f"Added {target} to Watchlist"})
        else:
            return jsonify({"success": False, "error": f"{target} is already in Watchlist"}), 400
            
    # GET method
    watchlist_data = get_watchlist()
    formatted = [
        {
            "id": r[0],
            "target": r[1],
            "scan_type": r[2],
            "interval": r[3],
            "last_scanned": r[4]
        }
        for r in watchlist_data
    ]
    return jsonify(formatted)

@app.route("/watchlist/<int:target_id>", methods=["DELETE"])
def remove_watchlist_item(target_id):
    deleted = delete_from_watchlist(target_id)
    if deleted:
        return jsonify({"success": True, "message": f"Target #{target_id} removed from monitoring."})
    return jsonify({"error": "Watchlist target not found"}), 404

@app.route("/watchlist/scan/<int:target_id>", methods=["POST"])
def trigger_watchlist_scan(target_id):
    item = get_watchlist_target(target_id)
    if not item:
        return jsonify({"error": "Monitored target not found"}), 404
        
    target_ip = item[1]
    scan_type = item[2]
    
    success, new_result = run_nmap_scan(target_ip, scan_type)
    if not success:
        return jsonify({"success": False, "error": new_result}), 500
        
    update_watchlist_time(target_ip)
    old_result = get_latest_scan(target_ip)
    
    diff_detected = False
    ai_diff = ""
    if old_result and old_result.strip() != new_result.strip():
        diff_detected = True
        diff_prompt = (
            f"Previous Scan for {target_ip}:\n{old_result}\n\n"
            f"New Scan for {target_ip}:\n{new_result}\n\n"
            "Compare the two scans. What ports or services changed? Assess if this is a security risk."
        )
        ai_diff = analyze_scan_with_ai(diff_prompt)
        save_diff_log(target_ip, ai_diff, "warning")
        
        webhook_url = get_setting("webhook_url")
        if webhook_url:
            send_webhook_alert(webhook_url, f"Attack surface change detected on {target_ip}!\n\n{ai_diff}", "warning")
            
    # Save the new scan
    ports = parse_nmap_ports(new_result)
    save_scan(target_ip, new_result, nmap_result=new_result, risk_level="MEDIUM" if diff_detected else "LOW")
    
    return jsonify({
        "success": True,
        "target": target_ip,
        "diff_detected": diff_detected,
        "ai_diff": ai_diff,
        "ports": ports,
        "message": "Attack surface change detected!" if diff_detected else "Scan complete: No changes detected."
    })

@app.route("/diff_logs")
def diff_logs():
    logs = get_diff_logs()
    formatted = [
        {"id": r[0], "target": r[1], "diff_text": r[2], "alert_level": r[3], "timestamp": r[4]}
        for r in logs
    ]
    return jsonify(formatted)

@app.route("/check_nmap")
def check_nmap_status():
    is_installed = check_nmap()
    return jsonify({"installed": is_installed})

# --- Background Task: Continuous Monitoring ---
@scheduler.task('interval', id='run_watchlist_scans', hours=1)
def run_watchlist_scans():
    with app.app_context():
        targets = get_watchlist()
        for t in targets:
            target_ip = t[1]
            scan_type = t[2]
            
            success, new_result = run_nmap_scan(target_ip, scan_type)
            if not success:
                continue
                
            update_watchlist_time(target_ip)
            old_result = get_latest_scan(target_ip)
            
            if old_result and old_result.strip() != new_result.strip():
                diff_prompt = (
                    f"Previous Scan for {target_ip}:\n{old_result}\n\n"
                    f"New Scan for {target_ip}:\n{new_result}\n\n"
                    "What changed? Is it dangerous?"
                )
                ai_diff = analyze_scan_with_ai(diff_prompt)
                save_diff_log(target_ip, ai_diff, "warning")
                
                webhook_url = get_setting("webhook_url")
                if webhook_url:
                    send_webhook_alert(webhook_url, f"Change detected on {target_ip}!\n\nAI Analysis:\n{ai_diff}", "warning")
                
            save_scan(target_ip, new_result, nmap_result=new_result)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001, use_reloader=False)
    app.run(debug=True, port=5001, use_reloader=False)
