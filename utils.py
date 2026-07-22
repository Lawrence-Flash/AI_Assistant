import subprocess
import shutil
import re
import logging
import os
import json
import requests
import whois
import dns.resolver
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

def is_valid_target(target):
    """
    Validates if the provided string is a valid IP address or domain name
    
    Args:
        target (str): The target IP or domain to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    # IP address pattern
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    # Domain pattern
    domain_pattern = r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$"
    
    is_ip = re.match(ip_pattern, target) is not None
    is_domain = re.match(domain_pattern, target) is not None
    
    if is_ip:
        # Additional validation for IP addresses
        octets = target.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
    
    return is_ip or is_domain

def check_nmap():
    """
    Checks if Nmap is installed and available on the system
    
    Returns:
        bool: True if Nmap is installed, False otherwise
    """
    return shutil.which("nmap") is not None

def run_nmap_scan(target, scan_type="fast"):
    """
    Runs an Nmap scan on the specified target
    
    Args:
        target (str): The target IP or domain to scan
        scan_type (str): Type of scan ("fast" or "advanced")
    
    Returns:
        tuple: (success: bool, result: str) where result is the scan output or error message
    """
    if not check_nmap():
        logging.error("Nmap is not installed or not found in system PATH")
        return False, "Nmap is not installed or not found in your system PATH."
    
    if not is_valid_target(target):
        logging.error(f"Invalid target: {target}")
        return False, "Invalid target. Please provide a valid IP address or domain name."
    
    try:
        logging.debug(f"Starting Nmap scan of {target}")
        
        flags = ["-F"]
        if scan_type == "advanced":
            flags = ["-sV", "-O", "-T4"]
        elif scan_type == "vuln":
            # Running Nmap with vulnerability scripts. Note: This can take a while.
            flags = ["-sV", "-O", "-T4", "--script", "vuln"]
            
        result = subprocess.run(["nmap"] + flags + [target], 
                               capture_output=True, 
                               text=True, 
                               timeout=600)  # 10 minute timeout for vuln scans
        
        if result.returncode == 0:
            logging.info(f"Nmap scan of {target} completed successfully")
            return True, result.stdout
        else:
            logging.error(f"Nmap scan failed with return code {result.returncode}")
            return False, f"Nmap scan failed: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        logging.error(f"Nmap scan of {target} timed out")
        return False, "Scan timed out. The target may be unreachable or blocking scans."
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap error: {str(e)}")
        return False, f"Nmap error: {e.stderr}"
    except Exception as e:
        logging.error(f"Unexpected error during scan: {str(e)}")
        return False, f"An unexpected error occurred: {str(e)}"

def analyze_scan_with_ai(nmap_output):
    """
    Passes Nmap output to the AI model for cybersecurity analysis.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "AI analysis failed: No API key found. Please set the GEMINI_API_KEY environment variable."
        
    try:
        genai.configure(api_key=api_key)
        # Using gemini-2.5-flash for fast and accurate text analysis
        model = genai.GenerativeModel("gemini-2.5-flash")
        prompt = (
            "You are a Senior Cybersecurity Expert. Analyze the following Nmap scan output. "
            "1. Summarize the open ports and their associated services. "
            "2. Identify any potential vulnerabilities or misconfigurations. "
            "3. Provide concrete, actionable remediation steps. "
            "Keep the report professional, concise, and structured."
            f"\n\nNmap Output:\n{nmap_output}"
        )
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"AI analysis error: {str(e)}"

def chat_with_ai(chat_history, new_message, scan_context):
    """
    Handles interactive chat with the AI, maintaining scan context.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "Chat failed: No API key found."
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        
        # Build the system context
        system_context = (
            "You are an expert Cybersecurity Advisor. You are helping a user understand the results of an Nmap network scan. "
            "You should provide clear, actionable, and professional advice. Do not hallucinate vulnerabilities that are not in the scan context. "
            f"\n\n--- CURRENT SCAN CONTEXT ---\n{scan_context}\n----------------------------\n\n"
        )
        
        # Build the conversation history
        conversation = system_context
        for msg in chat_history:
            role = "User: " if msg["role"] == "user" else "Advisor: "
            conversation += f"{role}{msg['content']}\n"
            
        # Add the new message
        conversation += f"User: {new_message}\nAdvisor: "
        
        response = model.generate_content(conversation)
        return response.text
    except Exception as e:
        return f"Chat error: {str(e)}"

def run_osint(target):
    """
    Gathers OSINT data using whois and DNS records.
    """
    results = {}
    try:
        w = whois.whois(target)
        results['whois'] = str(w)
    except Exception as e:
        results['whois'] = f"Whois error: {str(e)}"
    
    try:
        answers = dns.resolver.resolve(target, 'A')
        results['dns_a'] = [rdata.to_text() for rdata in answers]
    except Exception as e:
        results['dns_a'] = str(e)
        
    try:
        answers = dns.resolver.resolve(target, 'MX')
        results['dns_mx'] = [rdata.to_text() for rdata in answers]
    except Exception as e:
        results['dns_mx'] = str(e)
        
    return results

def send_webhook_alert(webhook_url, message, alert_level='info'):
    """
    Sends an alert to a configured webhook (e.g. Discord/Slack).
    """
    if not webhook_url:
        return False
        
    color = 16711680 if alert_level == 'warning' else 3447003 # Red or Blue
    
    payload = {
        "content": f"**Cybersecurity Assistant Alert**\nLevel: {alert_level.upper()}",
        "embeds": [{
            "title": "Scan Status Update",
            "description": message,
            "color": color
        }]
    }
    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        return response.status_code in (200, 204)
    except Exception as e:
        logging.error(f"Failed to send webhook: {e}")
        return False
