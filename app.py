from flask import Flask, render_template, request, jsonify
from utils import run_nmap_scan, check_nmap, analyze_scan_with_ai, chat_with_ai, run_osint, send_webhook_alert
from db import init_db, save_scan, get_history, add_to_watchlist, get_watchlist, get_diff_logs, save_diff_log, update_watchlist_time, get_latest_scan, get_setting, set_setting, save_osint, get_latest_osint
from flask_apscheduler import APScheduler
import logging
import threading

app = Flask(__name__)
app.secret_key = "cybersecurity-ai-assistant-secret"

# Configure Scheduler
class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# Initialize database
init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target")
    scan_type = data.get("scan_type", "fast")
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    # Run the Nmap scan
    success, nmap_result = run_nmap_scan(target, scan_type)
    
    # Run OSINT
    osint_result = run_osint(target)
    
    if not success:
        return jsonify({"error": nmap_result}), 500
        
    # Run the AI Analysis
    ai_prompt = f"--- NMAP RAW ---\n{nmap_result}\n\n--- OSINT DATA ---\n{osint_result}"
    ai_analysis = analyze_scan_with_ai(ai_prompt)
    
    # Save to database
    save_osint(target, str(osint_result))
    full_result = f"{ai_prompt}\n\n--- AI ANALYSIS ---\n{ai_analysis}"
    save_scan(target, full_result)
    
    return jsonify({
        "success": True,
        "nmap_result": nmap_result,
        "osint_result": osint_result,
        "ai_analysis": ai_analysis
    })

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        data = request.json
        webhook_url = data.get("webhook_url", "")
        set_setting("webhook_url", webhook_url)
        return jsonify({"success": True, "message": "Settings saved"})
    
    webhook_url = get_setting("webhook_url", "")
    return jsonify({"webhook_url": webhook_url})

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
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
        data = request.json
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
    formatted = [{"id": r[0], "target": r[1], "scan_type": r[2], "interval": r[3], "last_scanned": r[4]} for r in watchlist_data]
    return jsonify(formatted)

@app.route("/diff_logs")
def diff_logs():
    logs = get_diff_logs()
    formatted = [{"id": r[0], "target": r[1], "diff_text": r[2], "alert_level": r[3], "timestamp": r[4]} for r in logs]
    return jsonify(formatted)

@app.route("/history")
def history():
    history_data = get_history()
    # Format for JSON response
    formatted_history = [
        {"id": row[0], "target": row[1], "timestamp": row[2], "result": row[3]} 
        for row in history_data
    ]
    return jsonify(formatted_history)

@app.route("/check_nmap")
def check_nmap_status():
    is_installed = check_nmap()
    return jsonify({"installed": is_installed})

# --- Background Task: Continuous Monitoring ---
@scheduler.task('interval', id='run_watchlist_scans', hours=1)
def run_watchlist_scans():
    # In a real app, you would check interval_hours for each target.
    # For this portfolio piece, we will simply scan every target in the watchlist
    # whenever this runs (we'll set it to run every hour, but users can trigger it manually for testing)
    with app.app_context():
        targets = get_watchlist()
        for t in targets:
            target_ip = t[1]
            scan_type = t[2]
            
            # Run scan
            success, new_result = run_nmap_scan(target_ip, scan_type)
            if not success:
                continue
                
            update_watchlist_time(target_ip)
            
            # Get old scan
            old_result = get_latest_scan(target_ip)
            
            # Very basic diffing logic (If the new raw Nmap text is different from the old)
            # In a true enterprise app, we'd use AI to diff it intelligently.
            if old_result and old_result != new_result:
                # Ask AI to explain the difference
                diff_prompt = f"Previous Scan:\n{old_result}\n\nNew Scan:\n{new_result}\n\nWhat changed? Is it dangerous?"
                ai_diff = analyze_scan_with_ai(diff_prompt)
                save_diff_log(target_ip, ai_diff, "warning")
                
                webhook_url = get_setting("webhook_url")
                if webhook_url:
                    send_webhook_alert(webhook_url, f"Change detected on {target_ip}!\n\nAI Analysis:\n{ai_diff}", "warning")
                
            # Save the new scan
            save_scan(target_ip, new_result)

if __name__ == "__main__":
    app.run(debug=True, port=5001, use_reloader=False) # use_reloader=False prevents scheduler from running twice
