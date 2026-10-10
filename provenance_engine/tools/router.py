"""
Hybrid BM25 + Dense Similarity Tool Selection Router
Enforces strict k <= 15 candidate window and escalates borderline selections
to Pro High Reasoning.
"""

import math
from typing import List, Dict, Tuple, Optional
from loguru import logger

from config.settings import settings
from provenance_engine.tools.registry import ToolDefinition, ToolRegistry, tool_registry
from provenance_engine.llm_router import default_router, TaskType, ModelTier


class BM25Scorer:
    """Lightweight deterministic BM25 scorer."""

    def __init__(self, corpus: List[List[str]], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.corpus_size = len(corpus)
        self.avg_doc_len = sum(len(d) for d in corpus) / max(1, self.corpus_size)
        self.doc_freqs: Dict[str, int] = {}
        self.doc_lens = [len(d) for d in corpus]

        for doc in corpus:
            unique_terms = set(doc)
            for term in unique_terms:
                self.doc_freqs[term] = self.doc_freqs.get(term, 0) + 1

    def score(self, query_tokens: List[str], doc_idx: int, doc_tokens: List[str]) -> float:
        score = 0.0
        doc_len = self.doc_lens[doc_idx]

        for term in query_tokens:
            if term not in self.doc_freqs:
                continue

            df = self.doc_freqs[term]
            idf = math.log(1.0 + (self.corpus_size - df + 0.5) / (df + 0.5))

            tf = doc_tokens.count(term)
            numerator = tf * (self.k1 + 1.0)
            denominator = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / max(1.0, self.avg_doc_len)))

            score += idf * (numerator / max(1e-6, denominator))

        return score


class HybridToolRouter:
    def __init__(self, registry: Optional[ToolRegistry] = None, router=None):
        self.registry = registry or tool_registry
        self.llm = router or default_router
        self.max_k = min(15, settings.max_tool_candidates)

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower().strip(".,!?:;\"'()[]{}") for w in text.split() if w.strip()]

    def route_tools(
        self,
        query: str,
        k: Optional[int] = None,
    ) -> List[Tuple[ToolDefinition, float]]:
        """Returns top-k tools (where k <= 15) ranked by hybrid score."""
        target_k = min(k or self.max_k, 15)
        tools = self.registry.list_all()

        if not tools:
            return []

        query_tokens = self._tokenize(query)

        # Build corpus tokens: name + description + keywords
        corpus_tokens = []
        for t in tools:
            doc_str = f"{t.name} {t.description} {' '.join(t.keywords)}"
            corpus_tokens.append(self._tokenize(doc_str))

        bm25 = BM25Scorer(corpus_tokens)

        scored_tools: List[Tuple[ToolDefinition, float]] = []
        for idx, tool in enumerate(tools):
            b_score = bm25.score(query_tokens, idx, corpus_tokens[idx])

            # Jaccard / lexical overlap for dense component
            set_q = set(query_tokens)
            set_d = set(corpus_tokens[idx])
            overlap = len(set_q & set_d) / max(1, len(set_q | set_d))

            hybrid = (0.7 * b_score) + (0.3 * (overlap * 10.0))
            scored_tools.append((tool, hybrid))

        # Rank descending
        scored_tools.sort(key=lambda x: x[1], reverse=True)
        return scored_tools[:target_k]

    async def select_best_tool(
        self,
        query: str,
    ) -> ToolDefinition:
        """Selects the optimal tool, automatically escalating borderline scores to Pro High Reasoning."""
        candidates = self.route_tools(query, k=5)
        if not candidates:
            raise ValueError("No tools registered in registry.")

        if len(candidates) == 1:
            return candidates[0][0]

        top_tool, top_score = candidates[0]
        runner_up_tool, runner_up_score = candidates[1]

        # Check for borderline confidence delta
        score_delta = abs(top_score - runner_up_score)
        if score_delta < settings.borderline_confidence_delta and top_score > 0:
            logger.info(
                f"Borderline tool score delta ({score_delta:.3f} < {settings.borderline_confidence_delta}). "
                f"Escalating to ModelTier.PRO_HIGH_REASONING for disambiguation."
            )

            tool_names = [t.name for t, _ in candidates[:3]]
            disambig_resp = await self.llm.generate(
                task=TaskType.TOOL_DISAMBIGUATION,
                prompt=f"Disambiguate tool selection for query: '{query}'. Options: {tool_names}",
                context_data={
                    "query": query,
                    "candidate_tools": tool_names,
                },
            )

            selected_name = ""
            if disambig_resp.parsed_json and "selected_tool" in disambig_resp.parsed_json:
                selected_name = disambig_resp.parsed_json["selected_tool"]

            resolved = self.registry.get(selected_name)
            if resolved:
                return resolved

        return top_tool
