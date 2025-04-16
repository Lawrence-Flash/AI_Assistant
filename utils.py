import subprocess
import shutil
import re
import logging

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

def run_nmap_scan(target):
    """
    Runs an Nmap scan on the specified target
    
    Args:
        target (str): The target IP or domain to scan
    
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
        # -F performs a fast scan of 100 most common ports
        result = subprocess.run(["nmap", "-F", target], 
                               capture_output=True, 
                               text=True, 
                               timeout=120)  # 2 minute timeout
        
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
