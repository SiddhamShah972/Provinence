"""
MultiSiloHarvester: Live OSINT & Web Harvesting Engine
Discovers primary sources, technical preprints, and post-mortems dynamically
across DuckDuckGo, Hacker News, and public archives with zero API keys required.
"""
from __future__ import annotations

import urllib.parse
from typing import List, Dict, Any, Optional
import httpx
from bs4 import BeautifulSoup
from loguru import logger


class MultiSiloHarvester:
    """Discovers real source candidates dynamically across multiple public silos."""

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    @classmethod
    async def search_duckduckgo(cls, query: str, limit: int = 8) -> List[Dict[str, str]]:
        """Scrapes clean DuckDuckGo HTML results with zero JavaScript execution."""
        results: List[Dict[str, str]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=cls.DEFAULT_HEADERS, follow_redirects=True) as client:
                resp = await client.post("https://html.duckduckgo.com/html/", data={"q": query})
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for a in soup.select(".result__a"):
                        raw_href = a.get("href", "")
                        title = a.get_text(strip=True)
                        if not raw_href or not title:
                            continue

                        # Extract clean URL from DuckDuckGo redirect wrapper
                        if "uddg=" in raw_href:
                            parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(raw_href).query)
                            clean_url = parsed_qs.get("uddg", [raw_href])[0]
                        else:
                            clean_url = raw_href

                        if clean_url.startswith("http") and not any(r["url"] == clean_url for r in results):
                            results.append({"title": title, "url": clean_url, "source": "duckduckgo"})
                            if len(results) >= limit:
                                break
        except Exception as e:
            logger.warning(f"DuckDuckGo search error for '{query}': {e}")
        return results

    @classmethod
    async def search_hacker_news(cls, query: str, limit: int = 5) -> List[Dict[str, str]]:
        """Queries Hacker News Algolia index for post-mortems, incidents, and engineering threads."""
        results: List[Dict[str, str]] = []
        try:
            encoded_query = urllib.parse.quote(query)
            endpoint = f"https://hn.algolia.com/api/v1/search?query={encoded_query}&hitsPerPage={limit}"
            async with httpx.AsyncClient(timeout=8.0, headers=cls.DEFAULT_HEADERS) as client:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    for hit in data.get("hits", []):
                        title = hit.get("title") or hit.get("story_title")
                        object_id = hit.get("objectID")
                        url = hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}"
                        if title and url and url.startswith("http"):
                            results.append({"title": f"[HN] {title}", "url": url, "source": "hacker_news"})
        except Exception as e:
            logger.warning(f"Hacker News search error for '{query}': {e}")
        return results

    @classmethod
    async def search_wikipedia(cls, query: str, limit: int = 5) -> List[Dict[str, str]]:
        """Queries the official Wikipedia OpenSearch API for authoritative encyclopedia articles."""
        results: List[Dict[str, str]] = []
        try:
            encoded_query = urllib.parse.quote(query)
            endpoint = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={encoded_query}&limit={limit}&format=json"
            wiki_headers = {"User-Agent": "ProvenanceEngine/1.0 (security@provenance-research.local)"}
            async with httpx.AsyncClient(timeout=8.0, headers=wiki_headers) as client:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    titles = data[1] if len(data) > 1 else []
                    urls = data[3] if len(data) > 3 else []
                    for t, u in zip(titles, urls):
                        if t and u:
                            results.append({"title": f"[Wikipedia] {t}", "url": u, "source": "wikipedia"})
        except Exception as e:
            logger.warning(f"Wikipedia search error for '{query}': {e}")
        return results

    @classmethod
    async def harvest_all(cls, query: str, limit: int = 12) -> List[Dict[str, str]]:
        """Executes concurrent multi-silo discovery across DuckDuckGo, HN, and Wikipedia."""
        import asyncio
        ddg_task = cls.search_duckduckgo(query, limit=limit)
        hn_task = cls.search_hacker_news(query, limit=5)
        wiki_task = cls.search_wikipedia(query, limit=4)

        ddg_res, hn_res, wiki_res = await asyncio.gather(ddg_task, hn_task, wiki_task, return_exceptions=True)

        combined: List[Dict[str, str]] = []
        seen_urls = set()

        for item_list in (ddg_res, hn_res, wiki_res):
            if isinstance(item_list, list):
                for item in item_list:
                    u = item["url"]
                    if u not in seen_urls:
                        seen_urls.add(u)
                        combined.append(item)

        return combined[:limit]
