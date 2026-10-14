#!/usr/bin/env python3
"""Scan a network you own and build an inventory the threat brief can check.

Examples:

    python3 threat-brief/scan.py --from-xml threat-brief/site/sample-nmap.xml
    python3 threat-brief/scan.py --target 192.168.1.0/24 --i-own-this-network
    python3 threat-brief/scan.py --target 192.168.1.0/24 --i-own-this-network --top-ports 100

The live scan runs `nmap -sV` with quiet defaults. It does not run exploit
scripts. Public addresses are refused unless you also pass --allow-public.
Reading an XML file does not send packets.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from collector.exposure import flags_for_report
from collector.nmapxml import inventory_rows, parse_nmap_xml, rows_to_csv
from collector.report import build_report, render_html, render_markdown
from collector.targets import LEGAL_WARNING, TargetRejected, classify_target

DEFAULT_CATALOG = ROOT / "site" / "data" / "catalog.json"
DEFAULT_OUTPUT = ROOT / "scan-out"


def build_nmap_command(target: str, top_ports: int | None, host_timeout: str) -> list[str]:
    """Service detection only. No NSE vuln scripts, no OS probe, no timing above T3."""
    command = ["nmap", "-sV", "-T3", "--open", "--host-timeout", host_timeout, "-oX", "-"]
    if top_ports:
        command.extend(["--top-ports", str(top_ports)])
    command.append(target)
    return command


def run_nmap(command: list[str], scan_timeout: int, runner=None) -> bytes:
    if runner is None and shutil.which("nmap") is None:
        raise RuntimeError("nmap is not installed. On Ubuntu or WSL: sudo apt install nmap")
    execute = runner or subprocess.run
    try:
        completed = execute(command, capture_output=True, timeout=scan_timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"nmap exceeded {scan_timeout} seconds and was stopped.") from error
    stdout = completed.stdout or b""
    if completed.returncode != 0 and b"<nmaprun" not in stdout and b"<host" not in stdout:
        detail = (completed.stderr or stdout or b"").decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"nmap exited with status {completed.returncode}")
    return stdout


def load_catalog(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_outputs(scan: dict, xml_bytes: bytes, output_dir: Path, source_label: str, catalog: dict | None) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = inventory_rows(scan)
    report = build_report(scan, rows, catalog, source_label)
    (output_dir / "nmap.xml").write_bytes(xml_bytes if isinstance(xml_bytes, bytes) else xml_bytes.encode("utf-8"))
    (output_dir / "inventory.csv").write_text(rows_to_csv(rows), encoding="utf-8")
    (output_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (output_dir / "report.html").write_text(render_html(report), encoding="utf-8")
    report["output_dir"] = str(output_dir)
    report["rows"] = rows
    return report


def main(argv: list[str] | None = None, runner=None, resolver=None) -> int:
    parser = argparse.ArgumentParser(description="Turn an nmap service scan of a network you own into an inventory and a local report.")
    parser.add_argument("--target", help="Private IP, range, or CIDR to scan. Example: 192.168.1.0/24")
    parser.add_argument("--from-xml", type=Path, help="Read an existing nmap XML file instead of scanning.")
    parser.add_argument("--i-own-this-network", action="store_true", help="Confirm you own this network or have written permission to scan it.")
    parser.add_argument("--allow-public", action="store_true", help="Also allow a public address. Still requires --i-own-this-network. Use this only when you really have permission.")
    parser.add_argument("--top-ports", type=int, default=None, help="Ask nmap to scan this many common ports instead of its default list.")
    parser.add_argument("--host-timeout", default="120s", help="Per-host nmap timeout. Default 120s.")
    parser.add_argument("--scan-timeout", type=int, default=1800, help="Stop the whole nmap process after this many seconds. Default 1800.")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG, help="Catalog JSON from the collector.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT, help="Where to write inventory.csv, report.html, and report.md.")
    args = parser.parse_args(argv)

    if args.from_xml and args.target:
        print("Pass either --from-xml or --target, not both.", file=sys.stderr)
        return 2
    if not args.from_xml and not args.target:
        print("Pass --target to scan, or --from-xml to read a saved nmap file.", file=sys.stderr)
        return 2
    if args.top_ports is not None and not 1 <= args.top_ports <= 65535:
        print("--top-ports must be between 1 and 65535.", file=sys.stderr)
        return 2
    if args.allow_public and not args.i_own_this_network:
        print("--allow-public still requires --i-own-this-network.", file=sys.stderr)
        return 2

    try:
        if args.from_xml:
            if not args.from_xml.is_file():
                print(f"XML file not found: {args.from_xml}", file=sys.stderr)
                return 1
            xml_bytes = args.from_xml.read_bytes()
            source = f"XML file {args.from_xml}"
            print("No packets were sent. This only reads the XML file.")
            print(LEGAL_WARNING)
        else:
            decision = classify_target(args.target, resolver=resolver)
            if not args.i_own_this_network:
                print(LEGAL_WARNING, file=sys.stderr)
                print(
                    "Refusing to scan. Re-run with --i-own-this-network only if you own this network "
                    "or you have written permission to test it.",
                    file=sys.stderr,
                )
                return 2
            if not decision["local"] and not args.allow_public:
                print(LEGAL_WARNING, file=sys.stderr)
                print(decision["reason"], file=sys.stderr)
                print("Refusing to scan. Pass --allow-public as well only if you have permission for that public address.", file=sys.stderr)
                return 2
            print(LEGAL_WARNING)
            print(f"Scanning {args.target} ({decision['reason']})")
            for extra in decision["descriptions"]:
                if extra != args.target:
                    print(f"Note: {extra}")
            command = build_nmap_command(args.target, args.top_ports, args.host_timeout)
            xml_bytes = run_nmap(command, args.scan_timeout, runner=runner)
            source = "nmap " + " ".join(command[1:])
    except TargetRejected as error:
        print(LEGAL_WARNING, file=sys.stderr)
        print(str(error), file=sys.stderr)
        return 2
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1

    try:
        scan = parse_nmap_xml(xml_bytes)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1

    catalog = None
    try:
        catalog = load_catalog(args.catalog)
    except json.JSONDecodeError:
        print(f"Could not read the catalog at {args.catalog}. The report will not include CVE matches.", file=sys.stderr)
    if catalog is None:
        print(f"No catalog at {args.catalog}. Exposure notes will still be written.")

    report = write_outputs(scan, xml_bytes, args.output_dir, source, catalog)
    flags = flags_for_report(scan)
    print(
        f"Wrote {args.output_dir / 'inventory.csv'}, {args.output_dir / 'report.html'}, and {args.output_dir / 'report.md'} "
        f"({report['inventory_count']} inventory rows, {len(flags)} risk flags, {report['hosts_with_matches']} hosts with a catalog match)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
