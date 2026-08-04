"""Shared SSRF guard for any endpoint that accepts a user-supplied URL to fetch.

Used by StartRunBody.target_url and DiscoverBody.url in server.py.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

ALLOW_PRIVATE_ENV = "PROMPTSIEGE_ALLOW_PRIVATE_TARGETS"


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_link_local  # covers 169.254.0.0/16, incl. cloud metadata 169.254.169.254
        or ip.is_private  # covers 10/8, 172.16/12, 192.168/16
        or ip.is_unspecified  # 0.0.0.0
    )


def validate_public_url(url: str) -> str:
    """Reject URLs that aren't safe to fetch server-side (SSRF guard).

    Always enforces: scheme must be http or https.

    Also resolves the hostname at validation time (via getaddrinfo) and
    rejects loopback/link-local/private/unspecified addresses and the
    literal host "localhost" — UNLESS the env var
    PROMPTSIEGE_ALLOW_PRIVATE_TARGETS is set truthy, for operators who
    legitimately scan internal/localhost chatbot deployments. The scheme
    check always applies regardless of that flag.

    # ponytail: validation-time resolution only; DNS-rebinding not covered
    # (httpx re-resolves the hostname at fetch time, which may return a
    # different, private IP) — pin the resolved IP into the httpx fetch if
    # this ever runs off-localhost.
    # ponytail: getaddrinfo runs sync in request validation with no timeout;
    # fine for a single-operator localhost tool, move off-loop
    # (run_in_executor) or add a resolver timeout if this ever serves
    # multiple concurrent clients.

    Returns the url unchanged on success; raises ValueError on rejection.
    """
    if "://" not in url:
        # Bare domain / host:port (e.g. "example.com", "example.com:8080") —
        # default to https. Checking "://" rather than parsed.scheme also avoids
        # urlparse misreading "example.com:8080" as scheme="example.com".
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a hostname")

    if os.environ.get(ALLOW_PRIVATE_ENV, "").lower() in ("1", "true", "yes", "on"):
        return url

    if hostname.lower() == "localhost":
        raise ValueError("localhost targets are blocked (set PROMPTSIEGE_ALLOW_PRIVATE_TARGETS=1 to allow)")

    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"could not resolve hostname {hostname!r}: {e}") from e

    for _family, _, _, _, sockaddr in addrinfo:
        raw_ip = sockaddr[0]
        ip = ipaddress.ip_address(raw_ip)
        if _is_blocked_ip(ip):
            # Don't echo the resolved IP back to the caller — this endpoint
            # is unauthenticated and doing so would turn it into a DNS/IP
            # oracle for internal network probing.
            raise ValueError(
                "host resolves to a disallowed/private address; "
                "set PROMPTSIEGE_ALLOW_PRIVATE_TARGETS=1 to allow internal targets"
            )

    return url
