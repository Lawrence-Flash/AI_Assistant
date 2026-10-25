"""Scoring tests. The expected numbers are the smb-sa-v1 formula."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.config import load_profiles, load_settings
from collector.score import DEFAULT_WEIGHTS, matching_profiles, score_cve, score_news
from collector.summarise import get_summariser

PROFILES = load_profiles()


def cve(**overrides):
    record = {
        "cve_id": "CVE-2024-99999",
        "kind": "cve",
        "vendor": "Example",
        "product": "Widget",
        "title": "Example Widget bug",
        "description": "A bug in an uncommon product.",
        "cvss": None,
        "cvss_version": None,
        "severity": None,
        "in_kev": False,
        "kev_date_added": "",
        "ransomware": "Unknown",
        "epss": None,
        "epss_percentile": None,
        "aliases": [],
    }
    record.update(overrides)
    return record


class ScoreTests(unittest.TestCase):
    def test_config_weights_match_the_documented_defaults(self):
        settings = load_settings()
        self.assertEqual(settings["weights"], DEFAULT_WEIGHTS)
        self.assertEqual(settings["formula_id"], "smb-sa-v1")
        self.assertEqual(sum(DEFAULT_WEIGHTS.values()), 100)

    def test_full_score_is_100(self):
        result = score_cve(
            cve(
                vendor="Microsoft",
                product="Windows",
                cvss=10,
                cvss_version="3.1",
                severity="CRITICAL",
                in_kev=True,
                kev_date_added="2026-01-10",
                epss=1,
                epss_percentile=1,
            ),
            PROFILES,
        )
        self.assertEqual(result["score"], 100.0)
        self.assertEqual(result["score_components"], {"cvss": 40.0, "kev": 25.0, "epss": 20.0, "smb": 15.0})
        self.assertIn("Windows", result["smb_matches"])
        self.assertTrue(any("Total 100.0 out of 100." == reason for reason in result["reasons"]))

    def test_exchange_example_shows_each_part(self):
        result = score_cve(
            cve(
                vendor="Microsoft",
                product="Exchange Server",
                cvss=9.8,
                cvss_version="3.1",
                severity="CRITICAL",
                in_kev=True,
                kev_date_added="2026-01-10",
                ransomware="Known",
                epss=0.5,
                epss_percentile=0.97,
            ),
            PROFILES,
        )
        self.assertEqual(result["score"], 89.2)
        self.assertEqual(result["score_components"]["cvss"], 39.2)
        self.assertEqual(result["score_components"]["epss"], 10.0)
        joined = " ".join(result["reasons"])
        self.assertIn("39.2 of 40", joined)
        self.assertIn("25.0 of 25", joined)
        self.assertIn("10.0 of 20", joined)
        self.assertIn("15.0 of 15", joined)
        self.assertIn("ransomware", joined)
        self.assertIn("Microsoft 365 / Exchange", result["smb_matches"])

    def test_missing_data_scores_zero_for_that_part(self):
        result = score_cve(cve(), PROFILES)
        self.assertEqual(result["score"], 0.0)
        joined = " ".join(result["reasons"])
        self.assertIn("No CVSS score was published, so that part contributes 0 of 40.", joined)
        self.assertIn("Not listed in the CISA KEV catalog, so that part contributes 0 of 25.", joined)
        self.assertIn("No EPSS score was available", joined)
        self.assertIn("0 of 15", joined)

    def test_ransomware_note_does_not_add_points(self):
        base = cve(cvss=10, cvss_version="3.1", severity="CRITICAL", in_kev=True, kev_date_added="2026-01-01")
        plain = score_cve(base, PROFILES)
        flagged = score_cve({**base, "ransomware": "Known"}, PROFILES)
        self.assertEqual(plain["score"], flagged["score"])
        self.assertEqual(plain["score"], 65.0)

    def test_total_is_capped_at_100(self):
        result = score_cve(
            cve(vendor="Microsoft", product="Windows", cvss=10, in_kev=True, epss=1),
            PROFILES,
            {"cvss": 80, "kev": 25, "epss": 20, "smb": 15},
        )
        self.assertEqual(result["score"], 100.0)

    def test_short_patterns_do_not_match_unrelated_words(self):
        unrelated = cve(
            vendor="Example",
            product="Repository",
            description="A possible issue was found in the repository export.",
        )
        self.assertEqual(matching_profiles(unrelated, PROFILES), [])
        pos = cve(vendor="Yoco", product="POS")
        labels = [profile["label"] for profile in matching_profiles(pos, PROFILES)]
        self.assertEqual(labels, ["Card machines and POS"])

    def test_internet_key_exchange_is_not_microsoft_exchange(self):
        ike = cve(vendor="Microsoft", product="Internet Key Exchange (IKE) Service Extensions")
        self.assertEqual(matching_profiles(ike, PROFILES), [])

    def test_news_score_is_separate_and_capped(self):
        hit = score_news(
            {
                "title": "Small retailers warned about point of sale ransomware",
                "description": "Shops are being hit.",
            },
            PROFILES,
            urgency_terms=load_settings()["urgency_terms"],
        )
        self.assertEqual(hit["formula_id"], "news-relevance-v1")
        self.assertEqual(hit["score"], 20.0)
        self.assertIn("Card machines and POS", hit["smb_matches"])
        miss = score_news(
            {"title": "Astronomy photo contest", "description": "Night sky."},
            PROFILES,
            urgency_terms=load_settings()["urgency_terms"],
        )
        self.assertEqual(miss["score"], 0.0)

    def test_only_the_rule_summariser_is_registered(self):
        summary = get_summariser("rules-v1").summarise(
            {
                "kind": "cve",
                "cve_id": "CVE-2024-11111",
                "vendor": "Microsoft",
                "product": "Exchange Server",
                "severity": "CRITICAL",
                "description": "Microsoft Exchange Server lets a remote attacker run commands.",
                "in_kev": True,
                "ransomware": "Known",
                "epss": 0.5,
                "smb_matches": ["Microsoft 365 / Exchange"],
                "cvss": 9.8,
            }
        )
        self.assertEqual(summary.engine, "rules-v1")
        self.assertIn("CVE-2024-11111", summary.text)
        self.assertIn("install the vendor update", summary.what_to_do)
        self.assertIn("ransomware", summary.text.lower())
        with self.assertRaises(LookupError):
            get_summariser("gemini")
        with self.assertRaises(LookupError):
            get_summariser("openai")


if __name__ == "__main__":
    unittest.main()
