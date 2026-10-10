"""
Playwright Guard: Sandboxed Headless Browser Isolation
Restricts browser automation to prevent local file leaks, unauthorized protocols,
and resource-exhaustion vectors.
"""

from typing import List, Dict, Any, Optional
from loguru import logger


class PlaywrightGuard:
    """Security wrapper defining locked-down browser startup and request routing policies."""

    LOCKED_BROWSER_ARGS = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-extensions",
        "--disable-component-update",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-default-apps",
        "--mute-audio",
        "--no-first-run",
    ]

    BLOCKED_RESOURCE_TYPES = [
        "image",
        "media",
        "font",
        "websocket",
    ]

    BLOCKED_SCHEMES = [
        "file:",
        "chrome:",
        "chrome-extension:",
        "data:text/html",
        "javascript:",
        "about:",
    ]

    @classmethod
    def get_browser_launch_options(cls, headless: bool = True) -> Dict[str, Any]:
        """Returns hardened launch arguments for Playwright chromium."""
        return {
            "headless": headless,
            "args": list(cls.LOCKED_BROWSER_ARGS),
        }

    @classmethod
    def get_context_options(cls, inert_js: bool = True) -> Dict[str, Any]:
        """Returns sandboxed browser context options."""
        return {
            "java_script_enabled": not inert_js,
            "bypass_csp": False,
            "ignore_https_errors": False,
            "accept_downloads": False,
        }

    @classmethod
    def should_abort_request(cls, request_url: str, resource_type: str) -> bool:
        """Determines if an outbound browser sub-resource request violates security boundaries."""
        url_lower = request_url.lower()

        for scheme in cls.BLOCKED_SCHEMES:
            if url_lower.startswith(scheme):
                logger.warning(f"Aborting browser request to prohibited scheme: {request_url}")
                return True

        if resource_type.lower() in cls.BLOCKED_RESOURCE_TYPES:
            return True

        return False
