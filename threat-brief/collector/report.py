"""Build a local HTML and Markdown report from a scan and the catalog.

The HTML file is self-contained so it opens from disk. It does not call a server.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from collector.exposure import flags_for_report, tls_untested_note
from collector.match import match_inventory
from collector.targets import LEGAL_WARNING

MATCH_LIMIT = 5


def build_report(scan: dict, rows: list[dict], catalog: dict | None, source_label: str) -> dict:
    catalog = catalog or {}
    items = catalog.get("items") or []
    flags = flags_for_report(scan)
    per_host = []
    matched_rows = 0
    for host in scan.get("hosts") or []:
        host_rows = [row for row in rows if row.get("host") == host.get("ip")]
        matches = match_inventory(host_rows, items) if host_rows and items else {"affected": [], "cleared": []}
        kept, hidden = _cap(matches["affected"])
        if kept:
            matched_rows += 1
        notes = []
        for service in host.get("services") or []:
            note = tls_untested_note(service)
            if note and note not in notes:
                notes.append(note)
        per_host.append({
            "host": host,
            "rows": host_rows,
            "flags": [flag for flag in flags if flag["host"] == host.get("ip")],
            "matches": kept,
            "hidden": hidden,
            "notes": notes,
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_label": source_label,
        "nmap_args": scan.get("args") or "",
        "catalog_generated_at": catalog.get("generated_at") or "",
        "catalog_mode": catalog.get("mode") or "",
        "catalog_count": len(items),
        "hosts": per_host,
        "flags": flags,
        "inventory_count": len(rows),
        "hosts_with_matches": matched_rows,
        "legal": LEGAL_WARNING,
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Local network report",
        "",
        report["legal"],
        "",
        "This is a service-version scan compared with the public threat-brief catalog. It is not a penetration test, and a quiet host is invisible.",
        "",
        f"Generated: {report['generated_at']}",
        f"Source: {report['source_label']}",
    ]
    if report["nmap_args"]:
        lines.append(f"Nmap arguments recorded in the XML: `{report['nmap_args']}`")
    if report["catalog_count"]:
        lines.append(
            f"Catalog: {report['catalog_count']} CVEs"
            + (f", generated {report['catalog_generated_at']}" if report["catalog_generated_at"] else "")
            + (f", mode {report['catalog_mode']}" if report["catalog_mode"] else "")
            + "."
        )
    else:
        lines.append("No catalog file was loaded, so this report has risk flags only. Run `python3 threat-brief/collect.py` and scan again to add CVE matches.")
    lines.append("")
    lines.append(f"Inventory rows: {report['inventory_count']}. Hosts with at least one catalog match: {report['hosts_with_matches']}. Risk flags: {len(report['flags'])}.")
    lines.append("")
    if report["flags"]:
        lines.append("## Risk flags")
        lines.append("")
        for flag in report["flags"]:
            lines.append(f"- **{flag['level'].upper()}** {flag['host']}:{flag['port']} {flag['title']}. {flag['advice']}")
        lines.append("")
    for block in report["hosts"]:
        host = block["host"]
        title = host.get("ip") or "unknown host"
        if host.get("hostnames"):
            title += " (" + ", ".join(host["hostnames"]) + ")"
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"Status: {host.get('status') or 'unknown'}.")
        lines.append("")
        open_services = [service for service in host.get("services") or [] if service.get("state") == "open"]
        if not open_services:
            lines.append("No open ports in this file.")
            lines.append("")
            continue
        lines.append("| Port | Service | Product | Version |")
        lines.append("| --- | --- | --- | --- |")
        for service in open_services:
            lines.append(
                f"| {service['port']}/{service['protocol']} | {_md(service.get('name'))} | {_md(service.get('product'))} | {_md(service.get('version'))} |"
            )
        lines.append("")
        if block["flags"]:
            lines.append("### What to do about the exposure")
            lines.append("")
            for flag in block["flags"]:
                lines.append(f"- **{flag['title']}.** {flag['advice']}")
            lines.append("")
        for note in block["notes"]:
            lines.append(f"- Note: {note}")
        if block["notes"]:
            lines.append("")
        if block["matches"]:
            lines.append("### Catalog matches (approximate)")
            lines.append("")
            for match in block["matches"]:
                where = match["inventory"].get("name") or ""
                if match["inventory"].get("version"):
                    where += " " + match["inventory"]["version"]
                kev = " Known exploited." if match.get("in_kev") else ""
                lines.append(
                    f"- {where}: {match['cve_id']} score {match['score']}.{kev} {match.get('what_to_do') or ''} ({match.get('confidence_label') or match.get('confidence')})"
                )
            for key, extra in sorted(block["hidden"].items()):
                lines.append(f"- {key[0]} has {extra} more catalog matches not listed here. Open the Am I affected page for the full list.")
            lines.append("")
        elif report["catalog_count"]:
            lines.append("No catalog row matched the products on this host. That can mean the names differ, not that the host is safe.")
            lines.append("")
    lines.append("Version matching is approximate. Many KEV entries have no version range. A name match still needs a person to confirm it.")
    lines.append("")
    return "\n".join(lines)


def render_html(report: dict) -> str:
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en-ZA"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Local network report</title>",
        "<style>",
        "body{margin:0;background:#f3efe4;color:#1b1914;font:17px/1.5 'Segoe UI',Arial,sans-serif}",
        "main{width:min(920px,calc(100% - 32px));margin:0 auto;padding:32px 0 64px}",
        "h1,h2{font-family:Georgia,Palatino,serif;font-weight:600}",
        "h1{font-size:40px;margin:0 0 8px}",
        ".banner{background:#f8ebe4;border-left:4px solid #8d3416;padding:12px 14px}",
        ".meta{color:#5e584e}",
        "article{background:#fffdf8;border:1px solid #ddd4c4;border-radius:14px;padding:16px;margin:12px 0}",
        "table{width:100%;border-collapse:collapse;font-size:15px}",
        "th,td{text-align:left;vertical-align:top;border-bottom:1px solid #ddd4c4;padding:8px}",
        ".high{color:#8d3416;font-weight:700}",
        ".check{color:#8a5a10;font-weight:700}",
        ".action{background:#e7f3ec;border-radius:10px;padding:8px 10px}",
        "</style></head><body><main>",
        "<p class='meta'>Security Threat Brief · local report</p>",
        "<h1>Local network report</h1>",
        f"<div class='banner'><p>{html.escape(report['legal'])}</p></div>",
        "<p>This compares a service-version scan with the public catalog. It is not a penetration test. Hosts that do not answer are missing.</p>",
        f"<p class='meta'>Generated {_esc(report['generated_at'])}. Source {_esc(report['source_label'])}.</p>",
    ]
    if report["nmap_args"]:
        parts.append(f"<p class='meta'>Nmap arguments in the XML: {_esc(report['nmap_args'])}</p>")
    if report["catalog_count"]:
        parts.append(
            f"<p class='meta'>Catalog: {report['catalog_count']} CVEs"
            + (f", generated {_esc(report['catalog_generated_at'])}" if report["catalog_generated_at"] else "")
            + ".</p>"
        )
    else:
        parts.append("<p class='banner'>No catalog was loaded. This file has exposure notes only. Run the collector, then build the report again, to add CVE matches.</p>")
    parts.append(
        f"<p>{report['inventory_count']} inventory rows, {report['hosts_with_matches']} hosts with a catalog match, {len(report['flags'])} risk flags.</p>"
    )
    for block in report["hosts"]:
        host = block["host"]
        heading = host.get("ip") or "Unknown host"
        if host.get("hostnames"):
            heading += " · " + ", ".join(host["hostnames"])
        parts.append("<article>")
        parts.append(f"<h2>{_esc(heading)}</h2>")
        parts.append(f"<p class='meta'>Status: {_esc(host.get('status') or 'unknown')}</p>")
        open_services = [service for service in host.get("services") or [] if service.get("state") == "open"]
        if open_services:
            parts.append("<table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>")
            for service in open_services:
                parts.append(
                    "<tr>"
                    f"<td>{service['port']}/{_esc(service.get('protocol'))}</td>"
                    f"<td>{_esc(service.get('name'))}</td>"
                    f"<td>{_esc(service.get('product'))}</td>"
                    f"<td>{_esc(service.get('version'))}</td>"
                    "</tr>"
                )
            parts.append("</tbody></table>")
        else:
            parts.append("<p>No open ports in this file.</p>")
        for flag in block["flags"]:
            css = "high" if flag["level"] == "high" else "check"
            parts.append(
                f"<p class='action'><span class='{css}'>{_esc(flag['level'].upper())} · {_esc(flag['title'])}.</span> {_esc(flag['advice'])}</p>"
            )
        for note in block["notes"]:
            parts.append(f"<p class='meta'>{_esc(note)}</p>")
        if block["matches"]:
            parts.append("<h3>Catalog matches, approximate</h3>")
            parts.append("<ul>")
            for match in block["matches"]:
                where = match["inventory"].get("name") or ""
                if match["inventory"].get("version"):
                    where += " " + str(match["inventory"]["version"])
                kev = " Known exploited." if match.get("in_kev") else ""
                parts.append(
                    "<li><strong>"
                    + _esc(where)
                    + "</strong> "
                    + _esc(match.get("cve_id"))
                    + f" score {_esc(match.get('score'))}.{_esc(kev)} "
                    + _esc(match.get("what_to_do"))
                    + " "
                    + _esc(match.get("confidence_label") or "")
                    + "</li>"
                )
            for key, extra in sorted(block["hidden"].items()):
                parts.append(f"<li>{_esc(key[0])} has {extra} more matches. The Am I affected page lists them.</li>")
            parts.append("</ul>")
        elif report["catalog_count"] and open_services:
            parts.append("<p>No catalog name matched this host. That can be a naming gap, not a clean bill of health.</p>")
        parts.append("</article>")
    parts.append("<p class='meta'>Version matching is approximate. Many known-exploited entries have no version range.</p>")
    parts.append("</main></body></html>")
    return "\n".join(parts)


def _cap(matches: list[dict]) -> tuple[list[dict], dict]:
    counts: dict[tuple, int] = {}
    kept = []
    hidden: dict[tuple, int] = {}
    for match in matches:
        inventory = match.get("inventory") or {}
        key = (inventory.get("name") or "", inventory.get("host") or "", str(inventory.get("port") or ""))
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= MATCH_LIMIT:
            kept.append(match)
        else:
            hidden[key] = hidden.get(key, 0) + 1
    return kept, hidden


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _md(value) -> str:
    return ("" if value is None else str(value)).replace("|", "\\|") or "—"
