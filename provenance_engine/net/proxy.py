"""
Proxy Pool and Connection Masking Manager
Provides proxy rotation, health checking, and user-agent randomization.
"""

from typing import List, Optional, Dict
import itertools
import random
from pydantic import BaseModel, Field


class ProxyNode(BaseModel):
    url: str
    is_active: bool = True
    fail_count: int = 0
    max_fails: int = 3


class ProxyManager:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ]

    def __init__(self, proxies: Optional[List[str]] = None):
        self._proxies: List[ProxyNode] = [ProxyNode(url=p) for p in (proxies or [])]
        self._cycle = itertools.cycle(self._proxies) if self._proxies else None

    def add_proxy(self, url: str) -> None:
        self._proxies.append(ProxyNode(url=url))
        self._cycle = itertools.cycle(self._proxies)

    def get_next_proxy(self) -> Optional[str]:
        if not self._proxies:
            return None

        # Iterate to find an active proxy
        for _ in range(len(self._proxies)):
            node = next(self._cycle)
            if node.is_active:
                return node.url
        return None

    def mark_failure(self, url: str) -> None:
        for node in self._proxies:
            if node.url == url:
                node.fail_count += 1
                if node.fail_count >= node.max_fails:
                    node.is_active = False
                break

    def get_random_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS)

    def get_safe_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.get_random_user_agent(),
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
            "Sec-GPC": "1",
        }
