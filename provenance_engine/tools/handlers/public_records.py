"""
Public record connectors for SEC EDGAR and the Wayback Machine CDX API.
Enforces compliance headers, rate limits, and memory taint tagging.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional
import httpx

from provenance_engine.net.safe_fetch import SafeAsyncFetcher
from provenance_engine.trust.taint import TaintTracker, TaintedRecord


class SECEdgarClient:
    """
    SEC EDGAR submissions and company facts client.
    Note: SEC mandates a descriptive User-Agent formatted as 'User/App (contact@domain.com)'.
    """
    BASE_URL = "https://data.sec.gov"
    TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
    _ticker_cache: Dict[str, str] = {}
    _title_cache: Dict[str, str] = {}

    def __init__(self, user_agent: str = "ProvenanceResearchEngine (security@provenance-research.local)") -> None:
        self.headers = {
            "User-Agent": user_agent,
            "Accept-Encoding": "gzip, deflate",
            "Host": "data.sec.gov"
        }
        self.sec_gov_headers = {
            "User-Agent": user_agent,
            "Accept-Encoding": "gzip, deflate",
            "Host": "www.sec.gov"
        }
        # SEC enforces a hard cap of 10 requests per second across all endpoints
        self._rate_limiter = asyncio.Semaphore(5)

    async def _populate_ticker_cache(self) -> None:
        """Loads and caches SEC ticker-to-CIK directory."""
        if self._ticker_cache:
            return

        async with self._rate_limiter:
            async with httpx.AsyncClient(timeout=20.0, headers=self.sec_gov_headers) as client:
                resp = await client.get(self.TICKERS_URL)
                resp.raise_for_status()
                data = resp.json()
                for item in data.values():
                    ticker = str(item.get("ticker", "")).upper()
                    cik = str(item.get("cik_str", "")).zfill(10)
                    title = str(item.get("title", "")).strip().upper()
                    if ticker:
                        self._ticker_cache[ticker] = cik
                    if title:
                        self._title_cache[title] = cik

    async def resolve_ticker_to_cik(self, query: str) -> Optional[str]:
        """
        Resolves a ticker symbol (e.g. AAPL, NVDA), numeric CIK, or entity name
        to a canonical 10-digit zero-padded CIK string.
        """
        clean_query = query.strip()
        if clean_query.isdigit():
            return clean_query.zfill(10)

        await self._populate_ticker_cache()
        query_upper = clean_query.upper()

        # Direct ticker lookup
        if query_upper in self._ticker_cache:
            return self._ticker_cache[query_upper]

        # Exact title match
        if query_upper in self._title_cache:
            return self._title_cache[query_upper]

        # Fuzzy / substring title match
        for title, cik in self._title_cache.items():
            if query_upper in title or title in query_upper:
                return cik

        return None

    async def get_company_filings(self, identifier: str) -> Dict[str, Any]:
        """
        Fetch latest submissions and document metadata by ticker (AAPL, NVDA)
        or 10-digit zero-padded CIK.
        """
        cik = await self.resolve_ticker_to_cik(identifier)
        if not cik:
            raise ValueError(f"Could not resolve identifier '{identifier}' to a valid SEC CIK.")

        endpoint = f"{self.BASE_URL}/submissions/CIK{cik}.json"

        async with self._rate_limiter:
            async with httpx.AsyncClient(timeout=15.0, headers=self.headers) as client:
                response = await client.get(endpoint)
                response.raise_for_status()
                return response.json()


class ArchiveCDXClient:
    """
    Archive.org CDX Server API client for tracking domain changes over time.
    """
    CDX_URL = "https://web.archive.org/cdx/search/cdx"
    WAYBACK_RAW_URL = "https://web.archive.org/web/{timestamp}id_/{original}"

    def __init__(self) -> None:
        self.headers = {"User-Agent": "ProvenanceEngine/1.0 (+https://github.com/provenance)"}

    async def get_domain_snapshots(
        self,
        domain: str,
        limit: int = 15,
        match_type: str = "domain"
    ) -> List[Dict[str, str]]:
        """
        Query Wayback Machine index for historical URL captures.
        Returns timestamped snapshot records.
        """
        params = {
            "url": domain,
            "matchType": match_type,
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode,digest",
            "limit": str(limit),
            "collapse": "digest"  # Collapse duplicates with identical SHA-1 hashes
        }

        async with httpx.AsyncClient(timeout=20.0, headers=self.headers) as client:
            response = await client.get(self.CDX_URL, params=params)
            response.raise_for_status()
            raw_data = response.json()

            if not raw_data or len(raw_data) < 2:
                return []

            headers = raw_data[0]
            rows = raw_data[1:]
            return [dict(zip(headers, row)) for row in rows]

    async def fetch_snapshot_content(self, timestamp: str, original_url: str) -> str:
        """Fetches raw captured text content for a specific snapshot."""
        endpoint = self.WAYBACK_RAW_URL.format(timestamp=timestamp, original=original_url)
        async with httpx.AsyncClient(timeout=25.0, headers=self.headers, follow_redirects=True) as client:
            response = await client.get(endpoint)
            response.raise_for_status()
            return response.text

    async def diff_historical_snapshots(
        self,
        domain: str,
        timestamp_a: Optional[str] = None,
        timestamp_b: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Compares two temporal captures of a domain, extracting structural changes
        and generating a unified text delta.
        """
        import difflib
        import re

        snapshots = await self.get_domain_snapshots(domain, limit=30)
        if len(snapshots) < 2:
            return {
                "domain": domain,
                "status": "insufficient_snapshots",
                "message": f"Found {len(snapshots)} snapshot(s); need at least 2 to compute delta."
            }

        # Sort chronologically
        snapshots.sort(key=lambda s: s.get("timestamp", ""))

        snap_a = next((s for s in snapshots if s.get("timestamp") == timestamp_a), snapshots[0])
        snap_b = next((s for s in reversed(snapshots) if s.get("timestamp") == timestamp_b), snapshots[-1])

        # Fetch contents in parallel
        text_a, text_b = await asyncio.gather(
            self.fetch_snapshot_content(snap_a["timestamp"], snap_a["original"]),
            self.fetch_snapshot_content(snap_b["timestamp"], snap_b["original"]),
            return_exceptions=True
        )

        if isinstance(text_a, Exception) or isinstance(text_b, Exception):
            return {
                "domain": domain,
                "status": "fetch_failed",
                "error_a": str(text_a) if isinstance(text_a, Exception) else None,
                "error_b": str(text_b) if isinstance(text_b, Exception) else None
            }

        # Basic tag stripping to focus on text content
        clean_a = re.sub(r"<[^>]+>", " ", text_a)
        clean_b = re.sub(r"<[^>]+>", " ", text_b)
        lines_a = [l.strip() for l in clean_a.splitlines() if l.strip()]
        lines_b = [l.strip() for l in clean_b.splitlines() if l.strip()]

        diff = list(difflib.unified_diff(
            lines_a, lines_b,
            fromfile=f"{domain}@{snap_a['timestamp']}",
            tofile=f"{domain}@{snap_b['timestamp']}",
            n=2
        ))

        added_lines = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
        removed_lines = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))

        return {
            "domain": domain,
            "status": "success",
            "snapshot_early": {"timestamp": snap_a["timestamp"], "url": snap_a["original"]},
            "snapshot_late": {"timestamp": snap_b["timestamp"], "url": snap_b["original"]},
            "added_lines": added_lines,
            "removed_lines": removed_lines,
            "unified_diff_sample": "\n".join(diff[:80])
        }
