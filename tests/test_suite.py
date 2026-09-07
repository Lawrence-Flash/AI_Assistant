import sys
import os

# Ensure project root is in sys.path regardless of execution directory or PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
import json
import tempfile
import sqlite3

import utils
import db
from app import app

class TestSecurityAssistant(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # 1. Target & Port Validation Tests
    def test_target_validation(self):
        # Valid targets
        self.assertTrue(utils.is_valid_target("192.168.1.1"))
        self.assertTrue(utils.is_valid_target("10.0.0.1"))
        self.assertTrue(utils.is_valid_target("::1"))
        self.assertTrue(utils.is_valid_target("scanme.nmap.org"))
        self.assertTrue(utils.is_valid_target("google.com"))
        self.assertTrue(utils.is_valid_target("sub.domain.example.co.uk"))
        self.assertTrue(utils.is_valid_target("localhost"))
        
        # Invalid targets
        self.assertFalse(utils.is_valid_target(""))
        self.assertFalse(utils.is_valid_target("   "))
        self.assertFalse(utils.is_valid_target("http://google.com")) # Raw URL should fail target regex
        self.assertFalse(utils.is_valid_target("invalid..domain"))
        self.assertFalse(utils.is_valid_target("999.999.999.999"))

    def test_subnet_validation(self):
        self.assertTrue(utils.is_valid_subnet("192.168.1.0/24"))
        self.assertTrue(utils.is_valid_subnet("10.0.0.0/8"))
        self.assertTrue(utils.is_valid_subnet("172.16.0.0/16"))
        self.assertFalse(utils.is_valid_subnet("not-a-subnet"))
        self.assertFalse(utils.is_valid_subnet(""))

    def test_port_spec_validation(self):
        self.assertTrue(utils.is_valid_port_spec("80"))
        self.assertTrue(utils.is_valid_port_spec("80,443"))
        self.assertTrue(utils.is_valid_port_spec("1-1000"))
        self.assertTrue(utils.is_valid_port_spec("22,80-90,443,8080"))
        
        self.assertFalse(utils.is_valid_port_spec(""))
        self.assertFalse(utils.is_valid_port_spec("abc"))
        self.assertFalse(utils.is_valid_port_spec("0")) # 0 is invalid
        self.assertFalse(utils.is_valid_port_spec("70000")) # > 65535
        self.assertFalse(utils.is_valid_port_spec("100-50")) # inverted range

    # 2. Port & Service Parsing Tests
    def test_parse_nmap_ports(self):
        sample_nmap = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-07 18:00 UTC
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.098s latency).
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 6.6.1p1 Ubuntu
80/tcp    open     http       Apache httpd 2.4.7 ((Ubuntu))
9929/tcp  open     nping-echo Nping echo
31337/tcp filtered Elite
MAC Address: 00:11:22:33:44:55 (Cisco Systems)

Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
"""
        ports = utils.parse_nmap_ports(sample_nmap)
        self.assertEqual(len(ports), 4)
        
        self.assertEqual(ports[0]["port"], "22/tcp")
        self.assertEqual(ports[0]["state"], "open")
        self.assertEqual(ports[0]["service"], "ssh")
        self.assertIn("OpenSSH", ports[0]["version"])
        
        self.assertEqual(ports[1]["port"], "80/tcp")
        self.assertEqual(ports[1]["service"], "http")
        self.assertIn("Apache", ports[1]["version"])
        
        self.assertEqual(ports[3]["port"], "31337/tcp")
        self.assertEqual(ports[3]["state"], "filtered")

    # 3. Risk Score Extraction
    def test_extract_risk_score(self):
        self.assertEqual(utils.extract_risk_score("Risk Level: CRITICAL\nDetails..."), "CRITICAL")
        self.assertEqual(utils.extract_risk_score("Risk Level: HIGH\nDetails..."), "HIGH")
        self.assertEqual(utils.extract_risk_score("Risk Level: MEDIUM\nDetails..."), "MEDIUM")
        self.assertEqual(utils.extract_risk_score("Risk Level: LOW\nDetails..."), "LOW")
        self.assertEqual(utils.extract_risk_score("Risk Level: INFORMATIONAL\nDetails..."), "INFORMATIONAL")
        
        # Fallback keywords
        self.assertEqual(utils.extract_risk_score("Found a CRITICAL VULNERABILITY in Apache"), "CRITICAL")
        self.assertEqual(utils.extract_risk_score("This service is HIGH RISK and vulnerable"), "HIGH")

    # 4. Database Operations
    def test_database_operations(self):
        db.init_db()
        
        # Save scan with client_tag and analyst_notes
        scan_id = db.save_scan(
            target="127.0.0.1",
            result="Test scan result text",
            nmap_result="PORT 80/tcp open http",
            risk_level="HIGH",
            client_tag="Acme Corp Test",
            analyst_notes="Verified open port during sprint audit."
        )
        self.assertIsNotNone(scan_id)
        
        # Retrieve scan
        scan = db.get_scan_by_id(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["target"], "127.0.0.1")
        self.assertEqual(scan["risk_level"], "HIGH")
        self.assertEqual(scan["client_tag"], "Acme Corp Test")
        self.assertEqual(scan["analyst_notes"], "Verified open port during sprint audit.")
        
        # Update analyst notes
        updated = db.update_scan_notes(scan_id, "Updated notes: remediated via firewall rule.", "Acme Corp Q3")
        self.assertTrue(updated)
        
        scan_after = db.get_scan_by_id(scan_id)
        self.assertEqual(scan_after["analyst_notes"], "Updated notes: remediated via firewall rule.")
        self.assertEqual(scan_after["client_tag"], "Acme Corp Q3")
        
        # Clean up
        deleted = db.delete_scan(scan_id)
        self.assertTrue(deleted)
        self.assertIsNone(db.get_scan_by_id(scan_id))

    # 5. Flask API Routes
    def test_api_routes(self):
        # Index page
        resp = self.app.get("/")
        self.assertEqual(resp.status_code, 200)
        
        # Check nmap
        resp = self.app.get("/check_nmap")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("installed", data)
        
        # History
        resp = self.app.get("/history")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(json.loads(resp.data), list)
        
        # Missing target in scan
        resp = self.app.post("/scan", json={})
        self.assertEqual(resp.status_code, 400)
        
        # Missing subnet in discover
        resp = self.app.post("/discover", json={})
        self.assertEqual(resp.status_code, 400)
        
        # Missing domain in subdomains
        resp = self.app.post("/subdomains", json={})
        self.assertEqual(resp.status_code, 400)
        
        # Missing target in remediation
        resp = self.app.post("/remediation", json={})
        self.assertEqual(resp.status_code, 400)
        
        # Watchlist
        resp = self.app.get("/watchlist")
        self.assertEqual(resp.status_code, 200)

    # 6. Advanced Security Utilities Tests
    def test_advanced_security_features(self):
        # Test subdomain enumeration on IP (should return empty list safely)
        subs = utils.enumerate_subdomains("127.0.0.1")
        self.assertEqual(subs, [])
        
        # Test hardening script fallback generation without API key
        script = utils.generate_hardening_script("10.0.0.1", "Port 22 SSH open, Port 80 HTTP open", platform="linux")
        self.assertIsNotNone(script)
        self.assertTrue(len(script) > 10)
        
        # Test HTTP security audit on non-existent web service fails gracefully
        http_audit = utils.analyze_http_security("192.0.2.1") # TEST-NET-1 unrouteable
        self.assertFalse(http_audit.get("available", True))
        self.assertIn("error", http_audit)

    # 7. Domain Scanning & Reconnaissance Tests
    def test_target_normalization(self):
        # URL schemes and paths
        t1, p1 = utils.normalize_target("https://scanme.nmap.org/test?q=1#top")
        self.assertEqual(t1, "scanme.nmap.org")
        self.assertIsNone(p1)

        # Host with custom port
        t2, p2 = utils.normalize_target("example.com:8443")
        self.assertEqual(t2, "example.com")
        self.assertEqual(p2, "8443")

        # IP with port and path
        t3, p3 = utils.normalize_target("http://192.168.1.1:8080/admin")
        self.assertEqual(t3, "192.168.1.1")
        self.assertEqual(p3, "8080")

        # IPv6 with port brackets
        t4, p4 = utils.normalize_target("[::1]:9090")
        self.assertEqual(t4, "::1")
        self.assertEqual(p4, "9090")

        # Trailing slashes and whitespaces
        t5, p5 = utils.normalize_target("  google.com/  ")
        self.assertEqual(t5, "google.com")
        self.assertIsNone(p5)

    def test_domain_target_detection(self):
        self.assertTrue(utils.is_domain_target("google.com"))
        self.assertTrue(utils.is_domain_target("scanme.nmap.org"))
        self.assertTrue(utils.is_domain_target("sub.corp.example.co.uk"))
        
        self.assertFalse(utils.is_domain_target("192.168.1.1"))
        self.assertFalse(utils.is_domain_target("127.0.0.1"))
        self.assertFalse(utils.is_domain_target("::1"))
        self.assertFalse(utils.is_domain_target("localhost"))
        self.assertFalse(utils.is_domain_target("invalid..domain"))

    def test_email_security_analysis(self):
        # Configured SPF Softfail
        sec1 = utils.analyze_email_security("test.com", txt_records=["v=spf1 include:_spf.google.com ~all"])
        self.assertEqual(sec1["spf"]["status"], "PASS")
        self.assertIn("SoftFail", sec1["spf"]["policy"])

        # Strict SPF Hardfail
        sec2 = utils.analyze_email_security("test.com", txt_records=["v=spf1 ip4:192.0.2.1 -all"])
        self.assertEqual(sec2["spf"]["status"], "PASS")
        self.assertIn("HardFail", sec2["spf"]["policy"])

        # Dangerous SPF +all
        sec3 = utils.analyze_email_security("test.com", txt_records=["v=spf1 +all"])
        self.assertEqual(sec3["spf"]["status"], "CRITICAL")

        # Missing SPF
        sec4 = utils.analyze_email_security("test.com", txt_records=[])
        self.assertEqual(sec4["spf"]["status"], "MISSING")
        self.assertEqual(sec4["overall"], "VULNERABLE")

    def test_cdn_proxy_detection(self):
        # Cloudflare header detection
        cf = utils.detect_cdn_proxy("test.com", headers={"cf-ray": "12345", "server": "cloudflare"})
        self.assertTrue(cf["is_proxied"])
        self.assertIn("Cloudflare", cf["provider"])

        # AWS CloudFront CNAME detection
        cf2 = utils.detect_cdn_proxy("test.com", cnames=["d1234.cloudfront.net"])
        self.assertTrue(cf2["is_proxied"])
        self.assertIn("AWS CloudFront", cf2["provider"])

        # Direct connection (no proxy)
        direct = utils.detect_cdn_proxy("test.com", headers={}, cnames=[])
        self.assertFalse(direct["is_proxied"])
        self.assertIn("Direct", direct["provider"])

    def test_domain_audit_endpoint(self):
        # Missing domain parameter
        resp1 = self.app.post("/domain_audit", json={})
        self.assertEqual(resp1.status_code, 400)

        # Invalid domain format
        resp2 = self.app.post("/domain_audit", json={"domain": "invalid..domain"})
        self.assertEqual(resp2.status_code, 400)

if __name__ == "__main__":
    unittest.main()

