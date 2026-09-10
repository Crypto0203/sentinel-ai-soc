"""
url_safety.py
--------------
SSRF-safe outbound URL fetching for redirect-chain resolution.

Why this exists (per senior-review feedback):
  The moment your scanner fetches attacker-controlled URLs (to follow
  redirects, or to feed a headless browser for detonation), the scanner
  itself becomes an SSRF vector. An attacker can mail a link to
  http://169.254.169.254/latest/meta-data/ (cloud metadata) or an internal
  10.x/192.168.x service and have YOUR infrastructure fetch it on their
  behalf. This module resolves DNS and validates every IP — including every
  hop of a redirect chain, since an attacker can point a public-looking
  hostname at a DNS record that resolves to a private IP ("DNS rebinding").

Dependencies: requests (usually already present)
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local + cloud metadata (169.254.169.254)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
]

MAX_REDIRECTS = 8
FETCH_TIMEOUT_SECONDS = 6


class SSRFBlockedError(Exception):
    pass


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable -> treat as blocked, fail closed
    return any(ip in net for net in BLOCKED_NETWORKS)


def _resolve_all_ips(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def validate_url_safe(url: str) -> tuple[bool, str]:
    """Fail-closed validation: only return True if EVERY resolved IP for the
    hostname is public. Call this again on every redirect hop, not just the
    first URL — DNS can resolve differently between requests (rebinding)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"Blocked non-HTTP(S) scheme: {parsed.scheme}"
    if not parsed.hostname:
        return False, "No hostname in URL"

    ips = _resolve_all_ips(parsed.hostname)
    if not ips:
        return False, f"DNS resolution failed for {parsed.hostname}"
    for ip in ips:
        if _is_blocked_ip(ip):
            return False, f"{parsed.hostname} resolves to private/internal IP {ip} — blocked (possible SSRF/DNS rebinding)"
    return True, "OK"


@dataclass
class RedirectHop:
    url: str
    status_code: Optional[int]
    blocked_reason: Optional[str] = None


@dataclass
class RedirectChainResult:
    hops: list[RedirectHop] = field(default_factory=list)
    final_url: Optional[str] = None
    final_domain: Optional[str] = None
    blocked: bool = False
    displayed_domain: Optional[str] = None
    signal: Optional[str] = None  # "url_final_domain_mismatch" if final != displayed


def resolve_redirect_chain(start_url: str) -> RedirectChainResult:
    """Manually walks redirects (rather than requests' auto-follow) so every
    hop gets SSRF-validated before being fetched — auto-follow would fetch
    the malicious redirect target before you ever get a chance to check it."""
    result = RedirectChainResult()
    displayed_domain = urlparse(start_url).hostname
    result.displayed_domain = displayed_domain

    current_url = start_url
    session = requests.Session()

    for _ in range(MAX_REDIRECTS):
        ok, reason = validate_url_safe(current_url)
        if not ok:
            result.hops.append(RedirectHop(current_url, None, blocked_reason=reason))
            result.blocked = True
            return result

        try:
            resp = session.head(current_url, allow_redirects=False, timeout=FETCH_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            result.hops.append(RedirectHop(current_url, None, blocked_reason=str(exc)))
            result.blocked = True
            return result

        result.hops.append(RedirectHop(current_url, resp.status_code))

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            next_url = resp.headers.get("Location")
            if not next_url:
                break
            current_url = requests.compat.urljoin(current_url, next_url)
            continue
        break

    result.final_url = current_url
    result.final_domain = urlparse(current_url).hostname

    if result.final_domain and displayed_domain and result.final_domain != displayed_domain:
        result.signal = "url_final_domain_mismatch"

    return result
