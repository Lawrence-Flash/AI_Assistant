"""End-to-end build from fixtures. Does not call the network."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.config import load_profiles, load_settings
from collector.match import match_inventory, parse_inventory_csv
from collector.pipeline import build_documents, collect_fixtures, main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings()
        self.profiles = load_profiles()
        self.brief, self.catalog = collect_fixtures(self.settings, self.profiles)

    def test_fixture_mode_merges_and_dedupes(self):
        self.assertEqual(self.brief["mode"], "fixtures")
        self.assertEqual(self.brief["formula"]["id"], "smb-sa-v1")
        brief_ids = [item["id"] for item in self.brief["items"]]
        self.assertEqual(brief_ids.count("CVE-2024-11111"), 1)
        self.assertNotIn("CVE-2020-00001", brief_ids)
        self.assertEqual(self.brief["counts"]["brief_cves"], 3)
        self.assertEqual(self.brief["counts"]["brief_news"], 1)
        self.assertEqual(self.catalog["counts"]["catalog_cves"], 4)

        by_id = {item["id"]: item for item in self.catalog["items"]}
        exchange = by_id["CVE-2024-11111"]
        self.assertEqual(exchange["score"], 89.2)
        self.assertEqual(exchange["cvss"], 9.8)
        self.assertEqual(exchange["cvss_version"], "3.1")
        self.assertTrue(exchange["in_kev"])
        self.assertEqual(exchange["product"], "Exchange Server")
        self.assertEqual(exchange["summary_engine"], "rules-v1")
        self.assertTrue(exchange["what_to_do"])
        self.assertTrue(any(ref["url"] == "https://example.com/exchange" for ref in exchange["references"]))
        self.assertEqual(len(exchange["version_ranges"]), 1)

        self.assertEqual(by_id["CVE-2024-33333"]["score"], 54.2)
        self.assertEqual(by_id["CVE-2024-33333"]["cvss"], 9.8)
        self.assertEqual(by_id["CVE-2024-22222"]["score"], 31.2)
        self.assertEqual(by_id["CVE-2020-00001"]["score"], 25.0)
        self.assertIsNone(by_id["CVE-2020-00001"]["cvss"])
        self.assertTrue(any("No CVSS" in reason for reason in by_id["CVE-2020-00001"]["reasons"]))

        news = [item for item in self.brief["items"] if item["kind"] == "news"]
        self.assertEqual(len(news), 1)
        self.assertIn("point of sale", news[0]["title"])
        self.assertEqual(news[0]["score"], 20.0)
        self.assertNotIn("astronomy", " ".join(item["title"].lower() for item in self.brief["items"]))

    def test_inventory_against_fixture_catalog(self):
        rows = parse_inventory_csv((FIXTURES / "inventory_sample.csv").read_text(encoding="utf-8"))
        result = match_inventory(rows, self.catalog["items"])
        found = {(item["inventory"]["name"], item["inventory"]["version"], item["cve_id"], item["confidence"]) for item in result["affected"]}
        self.assertIn(("Exchange Server", "15.2.1000", "CVE-2024-11111", "version_in_range"), found)
        self.assertIn(("FortiOS", "7.2.4", "CVE-2024-33333", "version_in_range"), found)
        self.assertIn(("WordPress", "6.4.2", "CVE-2024-22222", "version_exact"), found)
        cleared = {(item["inventory"]["version"], item["cve_id"]) for item in result["cleared"]}
        self.assertIn(("7.2.5", "CVE-2024-33333"), cleared)
        self.assertIn(("6.5.0", "CVE-2024-22222"), cleared)
        names = {item["inventory"]["name"] for item in result["affected"]}
        self.assertNotIn("Office printer", names)
        self.assertNotIn("Yoco Neo", names)
        self.assertNotIn("Windows 10", names)

    def test_fixtures_entrypoint_does_not_use_the_network(self, ):
        def explode(*args, **kwargs):
            raise AssertionError("network used")

        with mock.patch("urllib.request.urlopen", explode):
            with mock.patch("collector.fetch.urllib.request.urlopen", explode):
                brief, catalog = collect_fixtures(self.settings, self.profiles)
        self.assertGreater(len(catalog["items"]), 0)
        self.assertGreater(len(brief["items"]), 0)

    def test_main_fixtures_writes_site_files(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            code = main(["--fixtures", "--output", directory])
            self.assertEqual(code, 0)
            brief = json.loads(Path(directory, "brief.json").read_text(encoding="utf-8"))
            catalog = json.loads(Path(directory, "catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(brief["mode"], "fixtures")
        self.assertEqual(len(catalog["items"]), 4)

    def test_build_documents_accepts_empty_feeds(self):
        brief, catalog = build_documents(None, [], None, [], self.settings, self.profiles, warnings=["empty"])
        self.assertEqual(catalog["items"], [])
        self.assertEqual(brief["items"], [])
        self.assertEqual(brief["warnings"], ["empty"])


if __name__ == "__main__":
    unittest.main()
