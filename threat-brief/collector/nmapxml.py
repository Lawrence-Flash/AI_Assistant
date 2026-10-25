"""Read nmap XML and turn services into inventory rows.

Nmap's own CPE is preferred over the free-text product banner. Names are
normalised (underscores become spaces, a few well-known products keep their
usual spelling) so the existing matcher can compare them with the catalog.
"""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET
from urllib.parse import unquote

PRODUCT_NAMES = {
    "fortios": "FortiOS",
    "fortigate": "FortiGate",
    "fortiproxy": "FortiProxy",
    "routeros": "RouterOS",
    "openssh": "OpenSSH",
    "openssl": "OpenSSL",
    "wordpress": "WordPress",
    "woocommerce": "WooCommerce",
    "exchange_server": "Exchange Server",
    "http_server": "HTTP Server",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "windows": "Windows",
    "windows_10": "Windows 10",
    "windows_11": "Windows 11",
    "windows_server_2012": "Windows Server 2012",
    "windows_server_2016": "Windows Server 2016",
    "windows_server_2019": "Windows Server 2019",
    "windows_server_2022": "Windows Server 2022",
}

VENDOR_NAMES = {
    "microsoft": "Microsoft",
    "fortinet": "Fortinet",
    "mikrotik": "MikroTik",
    "wordpress": "WordPress",
    "openbsd": "OpenBSD",
    "apache": "Apache",
    "oracle": "Oracle",
    "linux": "Linux",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "ietf": "IETF",
}

CSV_FIELDS = ["name", "vendor", "version", "host", "port", "protocol", "service"]


def parse_nmap_xml(xml_text: str | bytes) -> dict:
    """Return hosts, open services, and the nmaprun attributes."""
    if isinstance(xml_text, bytes):
        xml_text = xml_text.decode("utf-8", errors="replace")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise ValueError(f"This is not valid nmap XML: {error}") from error
    if _local(root.tag) not in {"nmaprun", "host"}:
        raise ValueError("This XML does not look like an nmap report.")
    hosts = []
    host_nodes = root.findall("host") if _local(root.tag) == "nmaprun" else [root]
    for node in host_nodes:
        hosts.append(_host(node))
    return {
        "scanner": root.attrib.get("scanner", ""),
        "args": root.attrib.get("args", ""),
        "version": root.attrib.get("version", ""),
        "hosts": hosts,
    }


def inventory_rows(report: dict) -> list[dict]:
    """One CSV row per detected product. Closed ports are left out."""
    rows = []
    seen: set[tuple] = set()
    for host in report.get("hosts") or []:
        if host.get("status") != "up":
            continue
        for service in host.get("services") or []:
            if service.get("state") != "open":
                continue
            for item in _rows_for_service(host, service):
                key = (
                    item["host"],
                    item["port"],
                    item["protocol"],
                    item["name"].lower(),
                    item["vendor"].lower(),
                    item["version"].lower(),
                )
                if key in seen:
                    continue
                seen.add(key)
                rows.append(item)
    return rows


def rows_to_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in CSV_FIELDS})
    return buffer.getvalue()


def parse_cpe(cpe: str) -> dict | None:
    """Return vendor, product, and version from an nmap CPE string."""
    text = unquote((cpe or "").strip())
    if text.startswith("cpe:2.3:"):
        parts = _split_cpe(text)
        if len(parts) < 5:
            return None
        vendor, product, version = parts[3], parts[4], parts[5] if len(parts) > 5 else ""
    elif text.startswith("cpe:/"):
        parts = text.split(":")
        vendor = parts[2] if len(parts) > 2 else ""
        product = parts[3] if len(parts) > 3 else ""
        version = parts[4] if len(parts) > 4 else ""
    else:
        return None
    vendor = _field(vendor)
    product = _field(product)
    version = _field(version)
    if not product:
        return None
    return {
        "vendor": display_vendor(vendor),
        "product": display_product(product),
        "version": version,
    }


def display_product(raw: str) -> str:
    key = (raw or "").strip().lower()
    if key in PRODUCT_NAMES:
        return PRODUCT_NAMES[key]
    return _title_tokens(raw)


def display_vendor(raw: str) -> str:
    key = (raw or "").strip().lower()
    if key in VENDOR_NAMES:
        return VENDOR_NAMES[key]
    return _title_tokens(raw)


def _rows_for_service(host: dict, service: dict) -> list[dict]:
    base = {
        "host": host.get("ip") or "",
        "port": str(service.get("port") or ""),
        "protocol": service.get("protocol") or "",
        "service": service.get("name") or "",
    }
    rows = []
    for cpe in service.get("cpes") or []:
        parsed = parse_cpe(cpe)
        if not parsed:
            continue
        rows.append({**base, "name": parsed["product"], "vendor": parsed["vendor"], "version": parsed["version"], "source": "cpe"})
    if rows:
        return rows
    product = (service.get("product") or "").strip()
    if not product:
        return []
    vendor = _vendor_from_product(product, service.get("ostype") or "")
    name = product
    if vendor and name.lower().startswith(vendor.lower() + " "):
        name = name[len(vendor) + 1 :].strip() or product
    return [{
        **base,
        "name": display_product(name.replace(" ", "_")) if "_" in name else name,
        "vendor": vendor,
        "version": (service.get("version") or "").strip(),
        "source": "banner",
    }]


def _vendor_from_product(product: str, ostype: str) -> str:
    lowered = product.lower()
    if lowered.startswith("microsoft") or ostype.lower() == "windows":
        return "Microsoft"
    if lowered.startswith("fortinet") or "fortios" in lowered or "fortigate" in lowered:
        return "Fortinet"
    if "mikrotik" in lowered or "routeros" in lowered:
        return "MikroTik"
    if lowered.startswith("wordpress"):
        return "WordPress"
    if "tp-link" in lowered or "tplink" in lowered:
        return "TP-Link"
    return ""


def _host(node: ET.Element) -> dict:
    addresses = []
    ip = ""
    for address in node.findall("address"):
        addresses.append({
            "addr": address.attrib.get("addr", ""),
            "type": address.attrib.get("addrtype", ""),
            "vendor": address.attrib.get("vendor", ""),
        })
        if not ip and address.attrib.get("addrtype") == "ipv4":
            ip = address.attrib.get("addr", "")
    if not ip:
        for address in addresses:
            if address["type"] != "mac" and address["addr"]:
                ip = address["addr"]
                break
    names = []
    for hostname in node.findall("./hostnames/hostname"):
        name = hostname.attrib.get("name")
        if name:
            names.append(name)
    status = (node.findtext("status") or "")
    status_node = node.find("status")
    state = status_node.attrib.get("state", "") if status_node is not None else status
    services = []
    for port in node.findall("./ports/port"):
        state_node = port.find("state")
        service_node = port.find("service")
        cpes = [cpe.text.strip() for cpe in (service_node.findall("cpe") if service_node is not None else []) if cpe.text]
        services.append({
            "port": int(port.attrib.get("portid") or 0),
            "protocol": port.attrib.get("protocol") or "",
            "state": state_node.attrib.get("state", "") if state_node is not None else "",
            "name": service_node.attrib.get("name", "") if service_node is not None else "",
            "product": service_node.attrib.get("product", "") if service_node is not None else "",
            "version": service_node.attrib.get("version", "") if service_node is not None else "",
            "extrainfo": service_node.attrib.get("extrainfo", "") if service_node is not None else "",
            "ostype": service_node.attrib.get("ostype", "") if service_node is not None else "",
            "tunnel": service_node.attrib.get("tunnel", "") if service_node is not None else "",
            "cpes": cpes,
        })
    return {"ip": ip, "addresses": addresses, "hostnames": names, "status": state or "unknown", "services": services}


def _field(value: str) -> str:
    text = unquote(value or "").strip()
    if text in {"*", "-", ""}:
        return ""
    return text


def _title_tokens(raw: str) -> str:
    parts = (raw or "").replace("_", " ").split()
    titled = []
    for part in parts:
        if part.isalpha() and part.islower():
            titled.append(part[:1].upper() + part[1:])
        else:
            titled.append(part)
    return " ".join(titled)


def _split_cpe(criteria: str) -> list[str]:
    parts: list[str] = []
    buffer: list[str] = []
    index = 0
    while index < len(criteria):
        char = criteria[index]
        if char == "\\" and index + 1 < len(criteria):
            buffer.append(criteria[index + 1])
            index += 2
            continue
        if char == ":":
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
        index += 1
    parts.append("".join(buffer))
    return parts


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag
