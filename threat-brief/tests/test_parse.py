"""Parsing tests. Fixtures only — these tests do not open a socket."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.parse import parse_epss, parse_kev, parse_nvd, parse_rss

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class ParseTests(unittest.TestCase):
    def test_kev_fields(self):
        records = parse_kev(load("kev_sample.json"))
        self.assertEqual([item["cve_id"] for item in records], ["CVE-2024-11111", "CVE-2020-00001"])
        exchange = records[0]
        self.assertEqual(exchange["vendor"], "Microsoft")
        self.assertEqual(exchange["product"], "Exchange Server")
        self.assertTrue(exchange["in_kev"])
        self.assertEqual(exchange["ransomware"], "Known")
        self.assertEqual(exchange["kev_date_added"], "2026-01-10")
        self.assertIsNone(exchange["cvss"])

    def test_nvd_prefers_v31_over_v2_and_primary_score(self):
        records = {item["cve_id"]: item for item in parse_nvd(load("nvd_sample.json"))}
        exchange = records["CVE-2024-11111"]
        self.assertEqual(exchange["cvss"], 9.8)
        self.assertEqual(exchange["cvss_version"], "3.1")
        self.assertEqual(exchange["severity"], "CRITICAL")
        self.assertIn("remote code execution", exchange["description"].lower())
        self.assertNotIn("Texto", exchange["description"])

        wordpress = records["CVE-2024-22222"]
        self.assertEqual(wordpress["cvss"], 4.0)
        self.assertEqual(wordpress["cvss_version"], "2.0")
        self.assertEqual(wordpress["severity"], "MEDIUM")

        forti = records["CVE-2024-33333"]
        self.assertEqual(forti["cvss"], 9.8)
        self.assertEqual(forti["severity"], "CRITICAL")

    def test_nvd_cpe_ranges_skip_negated_and_not_vulnerable(self):
        records = {item["cve_id"]: item for item in parse_nvd(load("nvd_sample.json"))}
        exchange = records["CVE-2024-11111"]
        self.assertEqual(len(exchange["version_ranges"]), 1)
        rng = exchange["version_ranges"][0]
        self.assertEqual(rng["vendor"], "microsoft")
        self.assertEqual(rng["product"], "exchange_server")
        self.assertEqual(rng["start_including"], "15.2.0")
        self.assertEqual(rng["end_excluding"], "15.2.1118.15")
        products = {alias["product"] for alias in exchange["aliases"]}
        self.assertEqual(products, {"exchange_server"})
        self.assertEqual(exchange["references"][0]["url"], "https://example.com/exchange-advisory")

        forti = records["CVE-2024-33333"]["version_ranges"][0]
        self.assertEqual(forti["end_excluding"], "7.2.5")
        wordpress = records["CVE-2024-22222"]["version_ranges"][0]
        self.assertEqual(wordpress["version"], "6.4.2")

    def test_epss_ignores_bad_rows(self):
        scores = parse_epss(load("epss_sample.json"))
        self.assertEqual(set(scores), {"CVE-2024-11111", "CVE-2024-22222"})
        self.assertEqual(scores["CVE-2024-11111"]["epss"], 0.5)
        self.assertEqual(scores["CVE-2024-11111"]["percentile"], 0.97)

    def test_rss_strips_html_and_finds_cves(self):
        items = parse_rss((FIXTURES / "rss_sample.xml").read_bytes(), "Example Security")
        self.assertEqual(len(items), 4)
        self.assertEqual(items[0]["cve_ids"], ["CVE-2024-11111"])
        self.assertNotIn("<", items[0]["description"])
        self.assertIn("CVE-2024-11111", items[0]["description"])
        self.assertTrue(items[0]["published"].startswith("2026-01-11"))

    def test_rss_two_digit_year_used_by_cisa(self):
        xml = b"""<?xml version="1.0"?>
        <rss version="2.0"><channel><item>
          <title>Advisory CVE-2026-00001</title>
          <link>https://example.com/cisa</link>
          <pubDate>Tue, 13 Oct 26 12:00:00 +0000</pubDate>
          <description>Short note.</description>
        </item></channel></rss>"""
        items = parse_rss(xml, "CISA advisories")
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["published"].startswith("2026-10-13"))

    def test_broken_rss_returns_empty(self):
        self.assertEqual(parse_rss(b"<rss>", "Broken"), [])


if __name__ == "__main__":
    unittest.main()
