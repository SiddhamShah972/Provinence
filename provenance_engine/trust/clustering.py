"""
SimHash & Disjoint-Set (Union-Find) Sybil Clustering Engine
Detects syndicated, plagiarized, and echo-chamber sources using 64-bit SimHash.
"""

import hashlib
import re
from typing import List, Dict, Set, Tuple, Any, Optional
from pydantic import BaseModel, Field

from config.settings import settings


class DisjointSet:
    """Disjoint-Set (Union-Find) with path compression and union-by-rank."""

    def __init__(self, elements: List[str]):
        self.parent: Dict[str, str] = {e: e for e in elements}
        self.rank: Dict[str, int] = {e: 0 for e in elements}

    def find(self, item: str) -> str:
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])  # Path compression
        return self.parent[item]

    def union(self, item1: str, item2: str) -> None:
        root1 = self.find(item1)
        root2 = self.find(item2)

        if root1 != root2:
            if self.rank[root1] < self.rank[root2]:
                self.parent[root1] = root2
            elif self.rank[root1] > self.rank[root2]:
                self.parent[root2] = root1
            else:
                self.parent[root2] = root1
                self.rank[root1] += 1

    def get_clusters(self) -> Dict[str, List[str]]:
        clusters: Dict[str, List[str]] = {}
        for elem in self.parent:
            root = self.find(elem)
            clusters.setdefault(root, []).append(elem)
        return clusters


class SourceDocument(BaseModel):
    doc_id: str
    uri: str
    content: str
    simhash: Optional[int] = None

    model_config = {"extra": "forbid"}


class SimHashClusterEngine:
    """Computes 64-bit SimHash fingerprints and clusters documents via Hamming distance."""

    @classmethod
    def compute_simhash_64(cls, text: str) -> int:
        """Computes a 64-bit SimHash fingerprint over word 3-grams."""
        words = re.findall(r"\w+", text.lower())
        if not words:
            return 0

        # Create word 3-grams (or unigrams if short)
        if len(words) >= 3:
            shingles = [" ".join(words[i : i + 3]) for i in range(len(words) - 2)]
        else:
            shingles = words

        v = [0] * 64

        for shingle in shingles:
            # 64-bit integer hash via MD5 slice
            h = int(hashlib.md5(shingle.encode("utf-8")).hexdigest()[:16], 16)
            for i in range(64):
                bit = (h >> i) & 1
                if bit:
                    v[i] += 1
                else:
                    v[i] -= 1

        fingerprint = 0
        for i in range(64):
            if v[i] > 0:
                fingerprint |= 1 << i

        return fingerprint

    @classmethod
    def hamming_distance(cls, hash1: int, hash2: int) -> int:
        """Calculates bitwise Hamming distance between two 64-bit integers."""
        xor = hash1 ^ hash2
        # Count set bits
        return bin(xor).count("1")

    @classmethod
    def cluster_sources(
        cls,
        documents: List[SourceDocument],
        threshold: Optional[int] = None,
    ) -> Dict[str, List[SourceDocument]]:
        """Groups sources into clusters where Hamming distance <= threshold (default: 3)."""
        dist_threshold = threshold if threshold is not None else settings.simhash_distance_threshold
        if not documents:
            return {}

        doc_map = {d.doc_id: d for d in documents}
        for doc in documents:
            if doc.simhash is None:
                doc.simhash = cls.compute_simhash_64(doc.content)

        doc_ids = [d.doc_id for d in documents]
        ds = DisjointSet(doc_ids)

        # Pairwise comparison
        n = len(documents)
        for i in range(n):
            for j in range(i + 1, n):
                h1 = documents[i].simhash
                h2 = documents[j].simhash
                if h1 is not None and h2 is not None:
                    dist = cls.hamming_distance(h1, h2)
                    if dist <= dist_threshold:
                        ds.union(documents[i].doc_id, documents[j].doc_id)

        clusters = ds.get_clusters()
        return {
            root: [doc_map[elem] for elem in members]
            for root, members in clusters.items()
        }
