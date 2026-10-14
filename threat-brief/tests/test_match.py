"""Inventory matching tests. No network."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.match import cmp_version, match_inventory, parse_inventory_csv

CATALOG = [
    {
        "cve_id": "CVE-EXCHANGE",
        "kind": "cve",
        "vendor": "Microsoft",
        "product": "Exchange Server",
        "score": 90,
        "in_kev": True,
        "cvss": 9.8,
        "smb_matches": ["Microsoft 365 / Exchange"],
        "what_to_do": "Patch Exchange.",
        "summary": "Exchange is affected.",
        "reasons": ["KEV"],
        "version_ranges": [],
        "aliases": [{"vendor": "microsoft", "product": "exchange_server"}],
    },
    {
        "cve_id": "CVE-IKE",
        "kind": "cve",
        "vendor": "Microsoft",
        "product": "Internet Key Exchange (IKE) Service Extensions",
        "score": 88,
        "in_kev": True,
        "what_to_do": "Not mail.",
        "summary": "IKE.",
        "reasons": [],
        "version_ranges": [],
        "aliases": [],
    },
    {
        "cve_id": "CVE-FORTI",
        "kind": "cve",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "score": 70,
        "in_kev": False,
        "what_to_do": "Patch FortiOS.",
        "summary": "FortiOS.",
        "reasons": [],
        "version_ranges": [
            {
                "vendor": "fortinet",
                "product": "fortios",
                "version": "*",
                "start_including": "7.2.0",
                "start_excluding": None,
                "end_including": None,
                "end_excluding": "7.2.5",
            }
        ],
        "aliases": [],
    },
    {
        "cve_id": "CVE-WP",
        "kind": "cve",
        "vendor": "WordPress",
        "product": "Core",
        "score": 40,
        "in_kev": False,
        "what_to_do": "Update WordPress.",
        "summary": "WordPress core.",
        "reasons": [],
        "version_ranges": [
            {
                "vendor": "wordpress",
                "product": "wordpress",
                "version": "6.4.2",
                "start_including": None,
                "start_excluding": None,
                "end_including": None,
                "end_excluding": None,
            }
        ],
        "aliases": [{"vendor": "wordpress", "product": "wordpress"}],
    },
    {
        "cve_id": "CVE-WIN",
        "kind": "cve",
        "vendor": "Microsoft",
        "product": "Windows",
        "score": 55,
        "in_kev": True,
        "what_to_do": "Patch Windows.",
        "summary": "Windows.",
        "reasons": [],
        "version_ranges": [],
        "aliases": [],
    },
    {
        "cve_id": "CVE-TPLINK",
        "kind": "cve",
        "vendor": "TP-Link",
        "product": "TL-WR841N",
        "score": 30,
        "in_kev": True,
        "what_to_do": "Replace or patch the router.",
        "summary": "Old router.",
        "reasons": [],
        "version_ranges": [],
        "aliases": [],
    },
]


class MatchTests(unittest.TestCase):
    def test_version_ordering_is_approximate(self):
        self.assertEqual(cmp_version("7.2.4", "7.2.5"), -1)
        self.assertEqual(cmp_version("7.2.10", "7.2.9"), 1)
        self.assertEqual(cmp_version("1.0", "1.0.0"), 0)
        self.assertEqual(cmp_version("22H2", "22h2"), 0)
        self.assertEqual(cmp_version("15.2.1000", "15.2.1118.15"), -1)

    def test_csv_headers_aliases_quotes_and_bom(self):
        text = "\ufeffproduct,manufacturer,ver\n\"Exchange Server\",\"Microsoft\",\"15.2.1000\"\n"
        rows = parse_inventory_csv(text)
        self.assertEqual(rows[0]["name"], "Exchange Server")
        self.assertEqual(rows[0]["vendor"], "Microsoft")
        self.assertEqual(rows[0]["version"], "15.2.1000")

    def test_csv_requires_a_name_column(self):
        with self.assertRaises(ValueError):
            parse_inventory_csv("version,notes\n1.0,hello\n")
        with self.assertRaises(ValueError):
            parse_inventory_csv("")

    def test_prioritised_matches_and_rejections(self):
        rows = parse_inventory_csv(
            "\n".join(
                [
                    "name,vendor,version",
                    "Exchange Server,Microsoft,2019",
                    "FortiOS,Fortinet,7.2.4",
                    "FortiOS,Fortinet,7.2.5",
                    "WordPress,WordPress,6.4.2",
                    "WordPress,WordPress,6.5.0",
                    "Windows 10,Microsoft,",
                    "Office printer,Generic,1.0",
                    "Yoco Neo,Yoco,1.0",
                    "TL-WR841N,TP-Link,",
                ]
            )
        )
        result = match_inventory(rows, CATALOG)
        affected = [(item["inventory"]["name"], item["inventory"]["version"], item["cve_id"], item["confidence"]) for item in result["affected"]]
        self.assertEqual(
            affected,
            [
                ("Exchange Server", "2019", "CVE-EXCHANGE", "name_only"),
                ("FortiOS", "7.2.4", "CVE-FORTI", "version_in_range"),
                ("Windows 10", "", "CVE-WIN", "name_only"),
                ("WordPress", "6.4.2", "CVE-WP", "version_exact"),
                ("TL-WR841N", "", "CVE-TPLINK", "name_only"),
            ],
        )
        self.assertEqual([item["score"] for item in result["affected"]], [90, 70, 55, 40, 30])
        cleared = {(item["inventory"]["version"], item["cve_id"]) for item in result["cleared"]}
        self.assertIn(("7.2.5", "CVE-FORTI"), cleared)
        self.assertIn(("6.5.0", "CVE-WP"), cleared)
        matched_ids = {item["cve_id"] for item in result["affected"]} | {item["cve_id"] for item in result["cleared"]}
        self.assertNotIn("CVE-IKE", matched_ids)
        printer = [item for item in result["affected"] if item["inventory"]["name"] == "Office printer"]
        self.assertEqual(printer, [])
        yoco = [item for item in result["affected"] if item["inventory"]["name"] == "Yoco Neo"]
        self.assertEqual(yoco, [])
        self.assertIn("approximate", result["affected"][0]["confidence_label"])

    def test_equal_scores_put_the_newer_catalog_date_first(self):
        rows = parse_inventory_csv("name,vendor,version\nWindows,Microsoft,\n")
        catalog = [
            {**CATALOG[4], "cve_id": "CVE-OLD", "score": 40, "kev_date_added": "2008-01-01"},
            {**CATALOG[4], "cve_id": "CVE-NEW", "score": 40, "kev_date_added": "2026-10-13"},
        ]
        result = match_inventory(rows, catalog)
        self.assertEqual([item["cve_id"] for item in result["affected"]], ["CVE-NEW", "CVE-OLD"])


if __name__ == "__main__":
    unittest.main()
