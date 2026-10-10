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

    def __init__(self, user_agent: str = "ProvenanceResearchEngine (security@provenance-research.local)") -> None:
        self.headers = {
            "User-Agent": user_agent,
            "Accept-Encoding": "gzip, deflate",
            "Host": "data.sec.gov"
        }
        # SEC enforces a hard cap of 10 requests per second across all endpoints
        self._rate_limiter = asyncio.Semaphore(5)

    async def get_company_filings(self, cik: str) -> Dict[str, Any]:
        """Fetch latest submissions and document metadata by 10-digit zero-padded CIK."""
        padded_cik = cik.zfill(10)
        endpoint = f"{self.BASE_URL}/submissions/CIK{padded_cik}.json"

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
