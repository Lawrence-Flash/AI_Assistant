"""Impact score for a small South African business.

The default formula id is smb-sa-v1. Weights live in config/settings.json
and are passed in, so a change to the config is the change to the formula.

  CVSS   (cvss / 10) * weights.cvss     default max 40
  KEV    weights.kev if listed, else 0  default 25
  EPSS   epss * weights.epss            default max 20
  SMB    weights.smb if a profile hits  default 15

Each component is rounded to one decimal place, then added. The total is
capped at 100. A missing CVSS or EPSS value contributes 0 and the reason
says so. News items use a separate, smaller relevance score.
"""

from __future__ import annotations

from collector.textutil import contains_phrase, normalise

FORMULA_ID = "smb-sa-v1"
DEFAULT_WEIGHTS = {"cvss": 40, "kev": 25, "epss": 20, "smb": 15}
DEFAULT_NEWS_WEIGHTS = {"smb": 10, "urgency": 10}


def one_dp(value: float) -> float:
    return float(f"{value:.1f}")


def matching_profiles(record: dict, profiles: list[dict]) -> list[dict]:
    """Return software profiles that match this record.

    A one-word pattern is checked against vendor, product, and CPE aliases
    only, so a word such as "exchange" does not fire on a long description
    about something else. A pattern of two or more words is also checked
    against the title and description.
    """
    identity = _identity_text(record)
    full = " ".join(
        part
        for part in (
            identity,
            record.get("title") or "",
            record.get("description") or "",
        )
        if part
    )
    matched = []
    for profile in profiles:
        if _profile_hits(profile, identity, full):
            matched.append(profile)
    return matched


def score_cve(record: dict, profiles: list[dict], weights: dict | None = None) -> dict:
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    cvss_max = float(weights["cvss"])
    kev_max = float(weights["kev"])
    epss_max = float(weights["epss"])
    smb_max = float(weights["smb"])

    reasons: list[str] = []
    cvss = record.get("cvss")
    if cvss is None:
        cvss_points = 0.0
        reasons.append(f"No CVSS score was published, so that part contributes 0 of {one_dp(cvss_max):.0f}.")
    else:
        cvss_points = one_dp(float(cvss) / 10.0 * cvss_max)
        version = record.get("cvss_version") or "unknown version"
        severity = record.get("severity") or "unspecified severity"
        reasons.append(
            f"CVSS {float(cvss):.1f} ({version}, {severity}) contributes {cvss_points:.1f} of {one_dp(cvss_max):.0f}."
        )

    if record.get("in_kev"):
        kev_points = one_dp(kev_max)
        added = record.get("kev_date_added") or "an unknown date"
        ransomware = ""
        if (record.get("ransomware") or "").lower() == "known":
            ransomware = " CISA also marks known ransomware use. That note does not add extra points."
        reasons.append(
            f"Listed in the CISA Known Exploited Vulnerabilities catalog (added {added}), "
            f"so that part contributes {kev_points:.1f} of {one_dp(kev_max):.0f}.{ransomware}"
        )
    else:
        kev_points = 0.0
        reasons.append(
            f"Not listed in the CISA KEV catalog, so that part contributes 0 of {one_dp(kev_max):.0f}."
        )

    epss = record.get("epss")
    if epss is None:
        epss_points = 0.0
        reasons.append(
            f"No EPSS score was available for this entry, so that part contributes 0 of {one_dp(epss_max):.0f}."
        )
    else:
        epss_points = one_dp(float(epss) * epss_max)
        percent = float(epss) * 100
        percentile = record.get("epss_percentile")
        percentile_text = f", percentile {float(percentile):.2f}" if percentile is not None else ""
        reasons.append(
            f"EPSS {float(epss):.2f} means FIRST estimates about a {percent:.0f}% probability of "
            f"exploitation activity in the next 30 days{percentile_text}. "
            f"That contributes {epss_points:.1f} of {one_dp(epss_max):.0f}. "
            "It is a forecast, not a statement that you will be attacked."
        )

    profiles_hit = matching_profiles(record, profiles)
    labels = [profile["label"] for profile in profiles_hit]
    if labels:
        smb_points = one_dp(smb_max)
        reasons.append(
            "Matches the small-business software list: "
            + ", ".join(labels)
            + f". That contributes {smb_points:.1f} of {one_dp(smb_max):.0f}."
        )
    else:
        smb_points = 0.0
        reasons.append(
            f"Does not match the small-business software list, so that part contributes 0 of {one_dp(smb_max):.0f}."
        )

    total = min(100.0, one_dp(cvss_points + kev_points + epss_points + smb_points))
    reasons.append(f"Total {total:.1f} out of 100.")
    return {
        "formula_id": FORMULA_ID,
        "score": total,
        "score_components": {
            "cvss": cvss_points,
            "kev": kev_points,
            "epss": epss_points,
            "smb": smb_points,
        },
        "smb_matches": labels,
        "reasons": reasons,
    }


def score_news(
    record: dict,
    profiles: list[dict],
    weights: dict | None = None,
    urgency_terms: list[str] | None = None,
) -> dict:
    """News relevance, capped well below a serious CVE. Not the CVE formula."""
    weights = {**DEFAULT_NEWS_WEIGHTS, **(weights or {})}
    terms = urgency_terms or []
    smb_max = float(weights["smb"])
    urgency_max = float(weights["urgency"])
    text = " ".join(part for part in (record.get("title"), record.get("description")) if part)
    reasons = [
        "This is a news headline, so it does not use the CVE impact formula. "
        f"Relevance is capped at {one_dp(smb_max + urgency_max):.0f}."
    ]
    labels = []
    for profile in profiles:
        for pattern in profile.get("patterns") or []:
            if contains_phrase(text, pattern):
                labels.append(profile["label"])
                break
    if labels:
        smb_points = one_dp(smb_max)
        reasons.append(
            "Mentions software on the small-business list ("
            + ", ".join(labels)
            + f"): {smb_points:.1f} of {one_dp(smb_max):.0f}."
        )
    else:
        smb_points = 0.0
        reasons.append(f"Does not mention the small-business software list: 0 of {one_dp(smb_max):.0f}.")

    urgency_hit = next((term for term in terms if contains_phrase(text, term) or _loose_term(text, term)), None)
    if urgency_hit:
        urgency_points = one_dp(urgency_max)
        reasons.append(
            f"Uses the urgency term '{urgency_hit}': {urgency_points:.1f} of {one_dp(urgency_max):.0f}."
        )
    else:
        urgency_points = 0.0
        reasons.append(f"No ransomware, zero-day, or active-exploitation wording: 0 of {one_dp(urgency_max):.0f}.")

    total = one_dp(smb_points + urgency_points)
    reasons.append(f"Total {total:.1f} out of {one_dp(smb_max + urgency_max):.0f} on the news scale.")
    return {
        "formula_id": "news-relevance-v1",
        "score": total,
        "score_components": {"smb": smb_points, "urgency": urgency_points},
        "smb_matches": labels,
        "reasons": reasons,
    }


def _identity_text(record: dict) -> str:
    """Vendor, product, and CPE aliases only. Titles are too easy to false-match."""
    parts = [record.get("vendor") or "", record.get("product") or ""]
    for alias in record.get("aliases") or []:
        parts.append(alias.get("vendor") or "")
        parts.append(alias.get("product") or "")
    return " ".join(part for part in parts if part)


def _profile_hits(profile: dict, identity: str, full: str) -> bool:
    for pattern in profile.get("patterns") or []:
        haystack = full if len(normalise(pattern).split()) >= 2 else identity
        if contains_phrase(haystack, pattern):
            return True
    return False


def _loose_term(text: str, term: str) -> bool:
    """Allow '0-day' to match after punctuation has been normalised to spaces."""
    return contains_phrase(text, term.replace("-", " "))
