"""Decide whether a scan target is a private network.

The scanner refuses public addresses unless the caller passes an explicit
override. It never sends packets by itself.
"""

from __future__ import annotations

import ipaddress
import socket

LEGAL_WARNING = (
    "Only scan a network you own, or one you have written permission to test. "
    "In South Africa, the Cybercrimes Act 19 of 2020 includes offences for unlawful "
    "access to data and for interfering with data or a computer system. Scanning a "
    "network you do not have permission to test can be unlawful. This note is not legal advice."
)


class TargetRejected(ValueError):
    """The target must not be scanned with the flags that were given."""


def classify_target(target: str, resolver=None) -> dict:
    """Return whether every address in `target` is local.

    `resolver` is optional and is only used for hostnames. Tests pass a fake.
    A hostname that does not resolve is rejected, so the tool does not scan a
    name it could not check.
    """
    text = (target or "").strip()
    if not text or any(char in text for char in "\n\r\x00"):
        raise TargetRejected("The target is empty or contains a newline.")
    if text.startswith("-"):
        raise TargetRejected("The target looks like an nmap flag. Pass the network range only.")

    tokens = [part for part in _split_tokens(text) if part]
    if not tokens:
        raise TargetRejected("The target is empty.")

    addresses: list[str] = []
    descriptions: list[str] = []
    count = 0
    for token in tokens:
        if token.startswith("-"):
            raise TargetRejected("The target looks like an nmap flag. Pass the network range only.")
        parsed = _parse_token(token, resolver)
        descriptions.append(parsed["label"])
        addresses.extend(parsed["addresses"])
        count += parsed["count"]
        for address in parsed["addresses"]:
            if not _is_local(address):
                return {
                    "local": False,
                    "reason": f"{address} is a public address. This tool will not probe it without --allow-public.",
                    "addresses": addresses,
                    "descriptions": descriptions,
                    "count": count,
                }
    if count > 1024:
        descriptions.append(
            f"This covers about {count} addresses. A version scan of a range that size can take a long time."
        )
    return {
        "local": True,
        "reason": "Every address in the target is private, loopback, or link-local.",
        "addresses": addresses,
        "descriptions": descriptions,
        "count": count,
    }


def _split_tokens(target: str) -> list[str]:
    pieces: list[str] = []
    for chunk in target.replace(",", " ").split():
        pieces.append(chunk.strip())
    return pieces


def _parse_token(token: str, resolver) -> dict:
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        network = None
    if network is not None and "/" in token:
        sample = [str(network.network_address)]
        if network.num_addresses > 1:
            sample.append(str(network.broadcast_address))
        return {"label": token, "addresses": sample, "count": network.num_addresses}

    span = _ipv4_range(token)
    if span is not None:
        start, end = span
        return {"label": token, "addresses": [str(start), str(end)], "count": int(end) - int(start) + 1}

    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        address = None
    if address is not None:
        return {"label": token, "addresses": [str(address)], "count": 1}

    return _resolve_name(token, resolver)


def _ipv4_range(token: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address] | None:
    if "-" not in token:
        return None
    left, right = token.split("-", 1)
    try:
        start = ipaddress.ip_address(left)
    except ValueError:
        return None
    if not isinstance(start, ipaddress.IPv4Address):
        return None
    if right.isdigit():
        octets = str(start).split(".")
        octets[-1] = right
        try:
            end = ipaddress.ip_address(".".join(octets))
        except ValueError:
            return None
    else:
        try:
            end = ipaddress.ip_address(right)
        except ValueError:
            return None
    if not isinstance(end, ipaddress.IPv4Address) or int(end) < int(start):
        return None
    return start, end


def _resolve_name(token: str, resolver) -> dict:
    if any(char in token for char in "/\\"):
        raise TargetRejected(f"Cannot understand target {token!r}.")
    lookup = resolver or socket.getaddrinfo
    try:
        infos = lookup(token, None)
    except Exception as error:
        raise TargetRejected(f"Could not resolve {token!r}, so it was not scanned. ({error})") from error
    found: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            address = str(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
        if address not in found:
            found.append(address)
    if not found:
        raise TargetRejected(f"Could not resolve {token!r} to an IP address, so it was not scanned.")
    return {"label": token, "addresses": found, "count": len(found)}


def _is_local(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if address.is_multicast or address.is_unspecified:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local)
