"""Scan, exposure, and target tests. No packets are sent."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.exposure import flags_for_report, flags_for_service
from collector.nmapxml import inventory_rows, parse_cpe, parse_nmap_xml, rows_to_csv
from collector.report import build_report, render_html, render_markdown
from collector.targets import TargetRejected, classify_target
import scan

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "site" / "sample-nmap.xml").read_text(encoding="utf-8")


def _service(**kwargs):
    base = {
        "port": 0,
        "protocol": "tcp",
        "state": "open",
        "name": "",
        "product": "",
        "version": "",
        "extrainfo": "",
        "tunnel": "",
    }
    base.update(kwargs)
    return base


class SampleXmlTests(unittest.TestCase):
    def setUp(self):
        self.report = parse_nmap_xml(SAMPLE)
        self.rows = inventory_rows(self.report)
        self.by_port = {(row["host"], row["port"]): row for row in self.rows}

    def test_cpe_names_are_normalised(self):
        windows = self.by_port[("192.168.1.10", "445")]
        self.assertEqual(windows["name"], "Windows 10")
        self.assertEqual(windows["vendor"], "Microsoft")
        self.assertEqual(windows["version"], "")
        self.assertEqual(windows["source"], "cpe")
        self.assertEqual(self.by_port[("192.168.1.30", "443")]["name"], "Exchange Server")
        self.assertEqual(self.by_port[("192.168.1.30", "443")]["version"], "2019")
        self.assertEqual(self.by_port[("192.168.1.35", "80")]["name"], "WordPress")
        self.assertEqual(self.by_port[("192.168.1.35", "80")]["version"], "6.4.2")
        self.assertEqual(self.by_port[("192.168.1.40", "443")]["name"], "FortiOS")
        self.assertEqual(self.by_port[("192.168.1.40", "443")]["vendor"], "Fortinet")
        self.assertEqual(self.by_port[("192.168.1.20", "8291")]["name"], "RouterOS")
        self.assertEqual(self.by_port[("192.168.1.20", "8291")]["vendor"], "MikroTik")
        self.assertEqual(self.by_port[("192.168.1.20", "8291")]["version"], "6.49.10")
        mysql = self.by_port[("192.168.1.50", "3306")]
        self.assertEqual(mysql["name"], "MySQL")
        self.assertEqual(mysql["vendor"], "Oracle")
        self.assertEqual(mysql["version"], "5.7.33")

    def test_banner_vendor_is_guessed_when_there_is_no_cpe(self):
        router = self.by_port[("192.168.1.70", "80")]
        self.assertEqual(router["name"], "TL-WR841N")
        self.assertEqual(router["vendor"], "TP-Link")
        self.assertEqual(router["version"], "3.16.9")
        self.assertEqual(router["source"], "banner")
        self.assertEqual(self.by_port[("192.168.1.60", "9100")]["name"], "HP LaserJet 400")
        self.assertEqual(self.by_port[("192.168.1.60", "9100")]["vendor"], "")

    def test_closed_ports_and_down_hosts_are_omitted(self):
        self.assertNotIn(("192.168.1.10", "135"), self.by_port)
        self.assertNotIn(("192.168.1.10", "3389"), self.by_port)
        self.assertNotIn(("192.168.1.50", "23"), self.by_port)
        self.assertFalse(any(row["host"] == "192.168.1.99" for row in self.rows))

    def test_csv_header_matches_the_checker(self):
        text = rows_to_csv(self.rows)
        self.assertTrue(text.startswith("name,vendor,version,host,port,protocol,service\n"))
        self.assertIn("Exchange Server,Microsoft,2019,192.168.1.30,443,tcp,https", text)

    def test_cpe23_and_escaped_colon(self):
        parsed = parse_cpe(r"cpe:2.3:a:vendor:product\:name:1.2:*:*:*:*:*:*:*")
        self.assertEqual(parsed["product"], "product:name")
        self.assertEqual(parsed["version"], "1.2")


class ExposureTests(unittest.TestCase):
    def setUp(self):
        self.flags = flags_for_report(parse_nmap_xml(SAMPLE))
        self.ids = {(flag["host"], flag["port"], flag["id"]) for flag in self.flags}

    def test_sample_flags(self):
        self.assertIn(("192.168.1.50", 23, "telnet"), self.ids)
        self.assertIn(("192.168.1.50", 21, "ftp-cleartext"), self.ids)
        self.assertIn(("192.168.1.50", 3306, "database"), self.ids)
        self.assertIn(("192.168.1.10", 3389, "rdp"), self.ids)
        self.assertIn(("192.168.1.10", 445, "smb"), self.ids)
        self.assertIn(("192.168.1.20", 22, "ssh-old"), self.ids)
        self.assertIn(("192.168.1.55", 443, "tls-old"), self.ids)
        self.assertFalse(any(flag["host"] == "192.168.1.40" and flag["port"] == 22 for flag in self.flags))
        self.assertFalse(any(flag["host"] == "192.168.1.60" and flag["port"] == 9200 for flag in self.flags))
        self.assertFalse(any(flag["host"] == "192.168.1.99" for flag in self.flags))

    def test_levels_and_advice_are_plain(self):
        telnet = next(flag for flag in self.flags if flag["id"] == "telnet")
        self.assertEqual(telnet["level"], "high")
        self.assertIn("Turn it off", telnet["advice"])
        ssh = next(flag for flag in self.flags if flag["id"] == "ssh-old")
        self.assertEqual(ssh["level"], "check")
        self.assertIn("not from a proof", ssh["advice"])

    def test_current_ssh_ftps_and_http_on_9200_are_quiet(self):
        self.assertEqual(flags_for_service(_service(port=22, name="ssh", product="OpenSSH", version="9.6p1")), [])
        self.assertEqual(flags_for_service(_service(port=22, name="ssh", product="OpenSSH", version="8.9p1")), [])
        self.assertEqual(flags_for_service(_service(port=990, name="ftps", tunnel="ssl")), [])
        self.assertEqual(flags_for_service(_service(port=21, name="ftp", tunnel="ssl")), [])
        self.assertEqual(flags_for_service(_service(port=9200, name="http", product="HP HTTP Server")), [])

    def test_very_old_ssh_and_protocol_1(self):
        old = flags_for_service(_service(port=22, name="ssh", product="OpenSSH", version="6.6p1"))
        self.assertEqual(old[0]["id"], "ssh-old")
        self.assertIn("very old", old[0]["title"])
        proto = flags_for_service(_service(port=22, name="ssh", product="OpenSSH", extrainfo="protocol 1.99"))
        self.assertEqual(proto[0]["id"], "ssh-protocol-1")
        self.assertEqual(proto[0]["level"], "high")

    def test_closed_port_is_not_a_finding(self):
        self.assertEqual(flags_for_service(_service(port=23, name="telnet", state="closed")), [])


class TargetTests(unittest.TestCase):
    def test_private_ranges_are_allowed(self):
        for target in ("192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.1", "169.254.1.1", "192.168.1.10-20"):
            decision = classify_target(target)
            self.assertTrue(decision["local"], target)

    def test_public_and_mixed_ranges_are_refused(self):
        for target in ("8.8.8.8", "172.32.0.1", "192.168.1.1,8.8.8.8"):
            decision = classify_target(target)
            self.assertFalse(decision["local"], target)
        self.assertFalse(classify_target("224.0.0.1")["local"])

    def test_hostname_uses_the_resolver(self):
        private = classify_target("till.office.local", resolver=lambda host, port: [(None, None, None, None, ("192.168.1.10", 0))])
        self.assertTrue(private["local"])
        public = classify_target("example.com", resolver=lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))])
        self.assertFalse(public["local"])

    def test_unresolved_hostname_is_rejected(self):
        def boom(host, port):
            raise OSError("no such host")

        with self.assertRaises(TargetRejected):
            classify_target("does-not-resolve.local", resolver=boom)

    def test_flags_and_empty_targets_are_rejected(self):
        for target in ("-oX", "192.168.1.1 -oX", "", "192.168.1.1\n10.0.0.1"):
            with self.assertRaises(TargetRejected):
                classify_target(target)

    def test_large_private_range_is_still_local(self):
        decision = classify_target("10.0.0.0/8")
        self.assertTrue(decision["local"])
        self.assertTrue(any("long time" in line for line in decision["descriptions"]))


class CommandTests(unittest.TestCase):
    def test_defaults_are_service_detection_only(self):
        command = scan.build_nmap_command("192.168.1.0/24", None, "120s")
        self.assertEqual(command[0], "nmap")
        self.assertIn("-sV", command)
        self.assertIn("-T3", command)
        self.assertNotIn("-A", command)
        self.assertNotIn("-O", command)
        self.assertNotIn("--script", command)
        self.assertEqual(command[-1], "192.168.1.0/24")
        topped = scan.build_nmap_command("10.0.0.5", 100, "120s")
        self.assertEqual(topped[-3:], ["--top-ports", "100", "10.0.0.5"])


class CliTests(unittest.TestCase):
    def test_refuses_to_scan_without_the_ownership_flag(self):
        calls = []

        def runner(command, capture_output, timeout):
            calls.append(command)
            raise AssertionError("nmap should not run")

        code = scan.main(["--target", "192.168.1.0/24"], runner=runner)
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])

    def test_refuses_a_public_target_without_the_override(self):
        calls = []

        def runner(command, capture_output, timeout):
            calls.append(command)
            raise AssertionError("nmap should not run")

        code = scan.main(["--target", "8.8.8.8", "--i-own-this-network"], runner=runner)
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])

    def test_allow_public_still_requires_ownership(self):
        code = scan.main(["--target", "8.8.8.8", "--allow-public"])
        self.assertEqual(code, 2)

    def test_from_xml_does_not_call_nmap(self):
        calls = []

        def runner(command, capture_output, timeout):
            calls.append(command)
            raise AssertionError("nmap should not run")

        with tempfile.TemporaryDirectory() as tmp:
            code = scan.main(
                ["--from-xml", str(ROOT / "site" / "sample-nmap.xml"), "--output-dir", tmp, "--catalog", str(Path(tmp) / "missing.json")],
                runner=runner,
            )
            self.assertEqual(code, 0, calls)
            self.assertEqual(calls, [])
            self.assertTrue((Path(tmp) / "inventory.csv").is_file())
            self.assertTrue((Path(tmp) / "report.html").is_file())
            self.assertIn("Exchange Server", (Path(tmp) / "inventory.csv").read_text(encoding="utf-8"))
            report = (Path(tmp) / "report.md").read_text(encoding="utf-8")
            self.assertIn("Telnet is open", report)
            self.assertIn("Cybercrimes Act 19 of 2020", report)

    def test_owned_private_target_uses_the_mocked_runner(self):
        seen = {}

        class Completed:
            returncode = 0
            stdout = SAMPLE.encode("utf-8")
            stderr = b""

        def runner(command, capture_output, timeout):
            seen["command"] = command
            seen["timeout"] = timeout
            return Completed()

        catalog = {
            "generated_at": "2026-10-14T00:00:00+00:00",
            "mode": "test",
            "items": [
                {
                    "kind": "cve",
                    "cve_id": "CVE-TEST-EXCHANGE",
                    "vendor": "Microsoft",
                    "product": "Exchange Server",
                    "score": 80,
                    "in_kev": True,
                    "what_to_do": "Patch Exchange and do not expose it.",
                    "summary": "Test.",
                    "reasons": ["KEV"],
                    "version_ranges": [],
                    "aliases": [{"vendor": "microsoft", "product": "exchange_server"}],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            catalog_path = Path(tmp) / "catalog.json"
            catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
            out = Path(tmp) / "out"
            code = scan.main(
                ["--target", "192.168.1.0/24", "--i-own-this-network", "--top-ports", "100", "--catalog", str(catalog_path), "--output-dir", str(out)],
                runner=runner,
            )
            self.assertEqual(code, 0)
            self.assertEqual(seen["command"][-3:], ["--top-ports", "100", "192.168.1.0/24"])
            self.assertNotIn("--script", seen["command"])
            html = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn("CVE-TEST-EXCHANGE", html)
            self.assertIn("mail.office.local", html)
            self.assertIn("Remote Desktop is open", html)
            self.assertIn("9.6p1", html)
            self.assertIn("OpenSSH 7.2 is an older release line", html)
            self.assertNotIn("OpenSSH 9.6 is an older", html)
            self.assertNotIn("very old", html)

    def test_missing_nmap_is_explained(self):
        with patch.object(scan.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError) as caught:
                scan.run_nmap(["nmap", "-sV", "192.168.1.1"], 5)
        self.assertIn("sudo apt install nmap", str(caught.exception))


class ReportTests(unittest.TestCase):
    def test_report_caps_repeated_matches_and_notes_untested_tls(self):
        parsed = parse_nmap_xml(SAMPLE)
        rows = inventory_rows(parsed)
        items = []
        for index in range(8):
            items.append({
                "kind": "cve",
                "cve_id": f"CVE-WIN-{index}",
                "vendor": "Microsoft",
                "product": "Windows",
                "score": 40,
                "in_kev": True,
                "kev_date_added": f"2026-01-0{index + 1}" if index < 9 else "2026-01-09",
                "what_to_do": "Update Windows.",
                "summary": "Windows.",
                "reasons": [],
                "version_ranges": [],
                "aliases": [],
            })
        report = build_report(parsed, rows, {"items": items, "generated_at": "t", "mode": "test"}, "sample")
        windows = next(block for block in report["hosts"] if block["host"]["ip"] == "192.168.1.10")
        self.assertEqual(len(windows["matches"]), 5)
        self.assertEqual(sum(windows["hidden"].values()), 3)
        shop = next(block for block in report["hosts"] if block["host"]["ip"] == "192.168.1.35")
        self.assertTrue(any("did not check" in note for note in shop["notes"]))
        firewall = next(block for block in report["hosts"] if block["host"]["ip"] == "192.168.1.40")
        self.assertEqual(firewall["flags"], [])
        text = render_markdown(report)
        html = render_html(report)
        self.assertIn("more catalog matches", text)
        self.assertIn("Cybercrimes Act", html)
        self.assertIn("HP LaserJet 400", html)


if __name__ == "__main__":
    unittest.main()
