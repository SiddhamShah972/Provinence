"""
SafeFetch: Unified Deterministic Async Network Choke Point
Enforces strict SSRF protection, DNS-rebinding mitigation, scheme whitelisting,
and payload streaming byte caps.
"""

import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List
import httpx
from loguru import logger

from config.settings import settings


class SSRFSecurityError(Exception):
    """Raised when a URL targets a private, loopback, or blocked destination."""
    pass


class PayloadTooLargeError(Exception):
    """Raised when a response exceeds the maximum allowed byte threshold."""
    pass


class DisallowedSchemeError(Exception):
    """Raised when a URL scheme is not strictly http or https."""
    pass


class NetworkFetchError(Exception):
    """Raised on network I/O or protocol failure."""
    pass


class SafeFetch:
    def __init__(self, custom_settings: Optional[Any] = None):
        self.settings = custom_settings or settings
        self.rules = self.settings.load_blocked_rules()
        self.blocked_hostnames = set(self.rules.get("blocked_hostnames", []))
        self.blocked_cidrs = [
            ipaddress.ip_network(cidr) for cidr in self.rules.get("blocked_cidr_ranges", [])
        ]
        self.disallowed_schemes = set(self.rules.get("disallowed_schemes", []))

    def validate_url(self, url: str) -> str:
        """Validates scheme and parses host."""
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()

        if scheme not in self.settings.allowed_schemes or scheme in self.disallowed_schemes:
            raise DisallowedSchemeError(f"Scheme '{scheme}' is forbidden. Allowed schemes: {self.settings.allowed_schemes}")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFSecurityError(f"Missing or invalid hostname in URL: {url}")

        if hostname.lower() in self.blocked_hostnames:
            raise SSRFSecurityError(f"Hostname '{hostname}' is explicitly blocked by SSRF policy.")

        # Check for dangerous TLDs
        for tld in self.rules.get("malicious_tlds", []):
            if hostname.lower().endswith(tld):
                raise SSRFSecurityError(f"Hostname '{hostname}' matches dangerous TLD pattern '{tld}'.")

        return hostname

    def resolve_and_verify_ip(self, hostname: str) -> List[str]:
        """Resolves DNS and verifies all candidate IPs against SSRF CIDRs."""
        try:
            addr_info = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            raise SSRFSecurityError(f"DNS resolution failure for '{hostname}': {e}")

        resolved_ips: List[str] = []
        for info in addr_info:
            ip_str = info[4][0]
            if ip_str in resolved_ips:
                continue
            resolved_ips.append(ip_str)

            ip = ipaddress.ip_address(ip_str)

            # Native checks
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise SSRFSecurityError(
                    f"Resolved IP {ip_str} for host '{hostname}' violates private/internal address policy."
                )

            # Configured CIDR blocks
            for cidr in self.blocked_cidrs:
                if ip in cidr:
                    raise SSRFSecurityError(
                        f"Resolved IP {ip_str} falls within blocked security CIDR: {cidr}"
                    )

        if not resolved_ips:
            raise SSRFSecurityError(f"No IP addresses could be resolved for host '{hostname}'.")

        return resolved_ips

    async def fetch(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Deterministically verifies target and streams response with strict byte capping."""
        hostname = self.validate_url(url)
        self.resolve_and_verify_ip(hostname)

        req_timeout = httpx.Timeout(
            timeout or self.settings.read_timeout_seconds,
            connect=self.settings.connect_timeout_seconds,
        )

        custom_headers = {
            "User-Agent": "ProvenanceEngine/1.0 (+https://github.com/provenance/engine; security research)",
            "Accept": "text/html,application/xhtml+xml,application/xml,application/pdf,*/*",
        }
        if headers:
            custom_headers.update(headers)

        try:
            async with httpx.AsyncClient(timeout=req_timeout, follow_redirects=False) as client:
                async with client.stream("GET", url, headers=custom_headers) as response:
                    # Check for redirect to internal/disallowed address
                    if response.is_redirect:
                        redirect_target = response.headers.get("Location")
                        if redirect_target:
                            # Re-verify destination before redirecting
                            return await self.fetch(redirect_target, headers=headers, timeout=timeout)

                    content_length = response.headers.get("Content-Length")
                    if content_length and int(content_length) > self.settings.max_fetch_bytes:
                        raise PayloadTooLargeError(
                            f"Content-Length ({content_length} bytes) exceeds maximum allowable limit "
                            f"({self.settings.max_fetch_bytes} bytes)."
                        )

                    chunks = []
                    bytes_read = 0
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        bytes_read += len(chunk)
                        if bytes_read > self.settings.max_fetch_bytes:
                            raise PayloadTooLargeError(
                                f"Streaming response exceeded maximum byte cap of {self.settings.max_fetch_bytes} bytes."
                            )
                        chunks.append(chunk)

                    return b"".join(chunks)

        except (SSRFSecurityError, PayloadTooLargeError, DisallowedSchemeError):
            raise
        except Exception as e:
            raise NetworkFetchError(f"Failed to safely fetch URL '{url}': {str(e)}") from e


# Global default SafeFetch client
safe_fetch = SafeFetch()
