"""Plain-English flags for services that are risky to leave open.

A flag is raised only from the port, the service name, or text nmap actually
printed. This does not probe TLS ciphers and it does not run nmap scripts.
"""

from __future__ import annotations

import re

# Ports and service names that are worth a human looking at.
# "high" means "do something this week if this can be reached beyond the office".
# "check" means "common on a LAN, dangerous if it is exposed further".
RULES = [
    {
        "id": "telnet",
        "level": "high",
        "title": "Telnet is open",
        "ports": {23},
        "services": {"telnet"},
        "advice": "Telnet sends usernames and passwords in the clear. Turn it off. If you need remote administration, use SSH, and do not expose that to the internet.",
    },
    {
        "id": "ftp-cleartext",
        "level": "high",
        "title": "FTP is open",
        "ports": {21},
        "services": {"ftp"},
        "advice": "Ordinary FTP sends logins in the clear. Prefer SFTP. If this is only a printer or scanner on the office LAN, keep it off the internet and turn FTP off if you do not use it.",
    },
    {
        "id": "smb",
        "level": "check",
        "title": "SMB file sharing is open",
        "ports": {445, 139},
        "services": {"microsoft-ds", "netbios-ssn"},
        "advice": "SMB is normal between office PCs. Do not forward port 445 or 139 to the internet. If this PC does not need to share files, turn file sharing off.",
    },
    {
        "id": "rdp",
        "level": "high",
        "title": "Remote Desktop is open",
        "ports": {3389},
        "services": {"ms-wbt-server"},
        "advice": "Remote Desktop is a common way in for ransomware. Do not expose port 3389 to the internet. Reach it through a VPN if people must connect from outside, and keep Windows updated.",
    },
    {
        "id": "vnc",
        "level": "check",
        "title": "VNC is open",
        "ports": {5900, 5901, 5902},
        "services": {"vnc"},
        "advice": "VNC is often protected by a weak password. Do not expose it to the internet. Turn it off if nobody uses it.",
    },
    {
        "id": "snmp",
        "level": "check",
        "title": "SNMP is open",
        "ports": {161, 162},
        "services": {"snmp"},
        "advice": "SNMP can leak how the network is built, especially with the default 'public' community. Limit it to the office LAN and prefer SNMP version 3.",
    },
    {
        "id": "nfs",
        "level": "check",
        "title": "NFS is open",
        "ports": {2049},
        "services": {"nfs"},
        "advice": "Network file shares should not be reachable from the internet. Check which hosts are allowed to mount this share.",
    },
    {
        "id": "docker-api",
        "level": "high",
        "title": "Docker API port is open",
        "ports": {2375},
        "services": {"docker"},
        "advice": "Port 2375 is the unencrypted Docker API. Anyone who can reach it can often control the host. Close it, or allow it only from localhost.",
    },
]

DATABASES = {
    3306: "MySQL or MariaDB",
    5432: "PostgreSQL",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5984: "CouchDB",
    11211: "Memcached",
}

DATABASE_SERVICES = {
    "mysql": "MySQL or MariaDB",
    "mariadb": "MySQL or MariaDB",
    "postgresql": "PostgreSQL",
    "ms-sql-s": "Microsoft SQL Server",
    "mongodb": "MongoDB",
    "mongod": "MongoDB",
    "redis": "Redis",
    "memcached": "Memcached",
}


def flags_for_service(service: dict) -> list[dict]:
    """Flags for one open service. Empty if the port is not open."""
    if service.get("state") != "open":
        return []
    found = []
    port = int(service.get("port") or 0)
    name = (service.get("name") or "").lower()
    blob = " ".join(
        str(service.get(key) or "")
        for key in ("name", "product", "version", "extrainfo", "tunnel")
    )
    for rule in RULES:
        if _rule_matches(rule, port, name, service):
            found.append(_flag(rule["id"], rule["level"], rule["title"], rule["advice"], service))
    database = DATABASES.get(port) or DATABASE_SERVICES.get(name)
    if database and name not in {"http", "https", "ssl"}:
        found.append(_flag(
            "database",
            "high",
            f"{database} looks exposed",
            f"Port {port} is the usual port for {database}. A database should not be reachable from the whole office network, and never from the internet. Allow only the application that needs it.",
            service,
        ))
    ssh = _ssh_flag(service, blob)
    if ssh:
        found.append(ssh)
    tls = _tls_flag(service, blob)
    if tls:
        found.append(tls)
    return found


def flags_for_report(report: dict) -> list[dict]:
    rows = []
    for host in report.get("hosts") or []:
        if host.get("status") != "up":
            continue
        for service in host.get("services") or []:
            for flag in flags_for_service(service):
                rows.append({**flag, "host": host.get("ip") or "", "hostnames": host.get("hostnames") or []})
    rows.sort(key=lambda item: (0 if item["level"] == "high" else 1, item["host"], item["port"]))
    return rows


def tls_untested_note(service: dict) -> str:
    """A note, not a finding, when HTTPS is present but the TLS version was not tested."""
    if service.get("state") != "open":
        return ""
    blob = " ".join(str(service.get(key) or "") for key in ("name", "product", "version", "extrainfo", "tunnel")).lower()
    if _old_tls(blob):
        return ""
    tunnel = (service.get("tunnel") or "").lower()
    name = (service.get("name") or "").lower()
    if tunnel == "ssl" or name in {"https", "ssl"}:
        return "This port is wrapped in TLS. The scan did not check which TLS versions are allowed."
    return ""


def _rule_matches(rule: dict, port: int, name: str, service: dict) -> bool:
    if rule["id"] == "ftp-cleartext":
        if (service.get("tunnel") or "").lower() == "ssl" or name in {"ftps", "sftp"}:
            return False
    return port in rule["ports"] or name in rule["services"]


def _ssh_flag(service: dict, blob: str) -> dict | None:
    name = (service.get("name") or "").lower()
    port = int(service.get("port") or 0)
    if name not in {"ssh", "openssh"} and port != 22 and "openssh" not in blob.lower():
        return None
    lowered = blob.lower()
    if re.search(r"protocol\s*1([^0-9.]|$)", lowered) or "1.99" in lowered or "ssh-1" in lowered:
        return _flag(
            "ssh-protocol-1",
            "high",
            "SSH protocol 1 is obsolete",
            "This banner mentions SSH protocol 1. Turn protocol 1 off and allow only protocol 2. Then update the SSH software.",
            service,
        )
    match = re.search(r"openssh[^\d]{0,3}(\d+)\.(\d+)", lowered)
    if not match:
        return None
    major = int(match.group(1))
    version = f"{match.group(1)}.{match.group(2)}"
    if major < 7:
        return _flag(
            "ssh-old",
            "check",
            f"OpenSSH {version} is a very old release line",
            "Check whether the vendor still publishes security updates for this OpenSSH. If they do not, upgrade it or replace the device. This flag is from the version banner, not from a proof that a particular bug is present.",
            service,
        )
    if major == 7:
        return _flag(
            "ssh-old",
            "check",
            f"OpenSSH {version} is an older release line",
            "Confirm this OpenSSH still receives security updates from the vendor. Upgrade it if the device is no longer supported. This flag is from the version banner, not from a proof that a particular bug is present.",
            service,
        )
    return None


def _tls_flag(service: dict, blob: str) -> dict | None:
    if not _old_tls(blob.lower()):
        return None
    return _flag(
        "tls-old",
        "check",
        "An old TLS or SSL version was named in the banner",
        "Nmap printed an old protocol such as SSLv3 or TLS 1.0. Prefer TLS 1.2 or 1.3. This scan did not try every cipher, so treat the banner as a lead and check the device's settings.",
        service,
    )


def _old_tls(lowered: str) -> bool:
    markers = ("sslv2", "ssl v2", "sslv3", "ssl v3", "tlsv1.0", "tls 1.0", "tlsv1.1", "tls 1.1")
    return any(marker in lowered for marker in markers)


def _flag(flag_id: str, level: str, title: str, advice: str, service: dict) -> dict:
    return {
        "id": flag_id,
        "level": level,
        "title": title,
        "advice": advice,
        "port": int(service.get("port") or 0),
        "protocol": service.get("protocol") or "",
        "service": service.get("name") or "",
    }
