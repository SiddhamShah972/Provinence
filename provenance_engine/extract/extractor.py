"""
Offset-Grounded Verbatim Claim Extractor and Grounding Verifier
Deterministically proves whether cited quotes exist verbatim at exact character offsets.
"""

import hashlib
import uuid
from typing import Tuple, Optional, List, Dict, Any
from loguru import logger

from provenance_engine.extract.schemas import EvidenceSnippet, Claim
from provenance_engine.llm_router import default_router, TaskType, ModelTier


class GroundingVerificationError(Exception):
    """Raised when a citation fails offset or verbatim integrity checks."""
    pass


class ClaimExtractor:
    """Verifies and extracts offset-grounded claims from source documents."""

    @classmethod
    def compute_sha256(cls, content: str | bytes) -> str:
        if isinstance(content, str):
            content = content.encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    @classmethod
    def verify_exact_offset(
        cls,
        source_text: str,
        quote: str,
        char_start: int,
        char_end: int,
    ) -> Tuple[bool, Optional[str]]:
        """Strict deterministic check: source_text[char_start:char_end] == quote."""
        if not quote:
            return False, "Quote cannot be empty."

        if char_start < 0 or char_end > len(source_text) or char_start >= char_end:
            return False, f"Offsets [{char_start}:{char_end}] out of source bounds (len={len(source_text)})."

        actual_slice = source_text[char_start:char_end]
        if actual_slice == quote:
            return True, None

        # Check for offset drift
        drift_idx = source_text.find(quote)
        if drift_idx != -1:
            return False, f"Offset drift detected: quote exists at [{drift_idx}:{drift_idx + len(quote)}], not [{char_start}:{char_end}]."

        return False, "Verbatim quote does not exist in the source document."

    @classmethod
    def create_evidence_snippet(
        cls,
        source_uri: str,
        source_text: str,
        exact_text: str,
        char_start: int,
        char_end: int,
        page_or_line: Optional[int] = None,
    ) -> EvidenceSnippet:
        """Constructs an EvidenceSnippet and deterministically verifies its offsets."""
        source_hash = cls.compute_sha256(source_text)
        is_exact, err_msg = cls.verify_exact_offset(source_text, exact_text, char_start, char_end)

        snippet_id = f"ev_{hashlib.sha256(f'{source_uri}:{char_start}:{char_end}'.encode()).hexdigest()[:12]}"

        return EvidenceSnippet(
            snippet_id=snippet_id,
            source_uri=source_uri,
            exact_text=exact_text,
            char_start=char_start,
            char_end=char_end,
            page_or_line=page_or_line,
            source_hash=source_hash,
            verified=is_exact,
        )

    @classmethod
    async def extract_claims_from_text(
        cls,
        source_uri: str,
        source_text: str,
        router=None,
    ) -> List[Claim]:
        """Extracts candidate claims using Fast Flash, then deterministically validates each offset."""
        llm = router or default_router
        source_hash = cls.compute_sha256(source_text)

        # High-throughput Fast Flash call
        prompt = (
            f"Extract verifiable factual assertions and verbatim backing quotes from the following document.\n"
            f"SOURCE URI: {source_uri}\n"
            f"CONTENT:\n{source_text[:4000]}\n\n"
            f"Return JSON format:\n"
            f"{{\n"
            f'  "claims": [\n'
            f'    {{"statement": "...", "exact_quote": "..."}}\n'
            f"  ]\n"
            f"}}"
        )

        response = await llm.generate(
            task=TaskType.SCRAPING_EXTRACTION,
            prompt=prompt,
            context_data={"source_text": source_text},
        )

        claims_data = []
        if response.parsed_json and "claims" in response.parsed_json:
            claims_data = response.parsed_json["claims"]

        extracted_claims: List[Claim] = []
        for item in claims_data:
            stmt = item.get("statement", "").strip()
            quote = item.get("exact_quote", "").strip()
            if not stmt:
                continue

            # Find exact offset
            idx = source_text.find(quote) if quote else -1
            if idx != -1:
                start = idx
                end = idx + len(quote)
                is_grounded = True
            else:
                start = 0
                end = 0
                is_grounded = False

            snippet = cls.create_evidence_snippet(
                source_uri=source_uri,
                source_text=source_text,
                exact_text=quote if is_grounded else "",
                char_start=start,
                char_end=end,
            )

            claim_id = f"claim_{uuid.uuid4().hex[:8]}"
            claim = Claim(
                claim_id=claim_id,
                statement=stmt,
                primary_quote=quote,
                citation_id=snippet.snippet_id,
                char_start=start,
                char_end=end,
                source_uri=source_uri,
                confidence=0.9 if is_grounded else 0.2,
                offset_grounded=is_grounded,
            )
            extracted_claims.append(claim)

        return extracted_claims

    @classmethod
    async def repair_citation(
        cls,
        source_text: str,
        unanchored_claim: Claim,
        router=None,
    ) -> Claim:
        """Escalates to Pro High Reasoning to auto-correct and repair broken or drifted offsets."""
        llm = router or default_router

        repair_prompt = (
            f"You are a forensic citation repair engine. Locate the verbatim source text for this assertion.\n"
            f"CLAIM: {unanchored_claim.statement}\n"
            f"PURPORTED QUOTE: {unanchored_claim.primary_quote}\n"
            f"SOURCE TEXT:\n{source_text[:6000]}"
        )

        repair_resp = await llm.generate(
            task=TaskType.CITATION_REPAIR,
            prompt=repair_prompt,
            context_data={
                "source_text": source_text,
                "claim_quote": unanchored_claim.primary_quote,
            },
        )

        if repair_resp.parsed_json and repair_resp.parsed_json.get("repaired"):
            start = repair_resp.parsed_json["char_start"]
            end = repair_resp.parsed_json["char_end"]
            fixed_quote = repair_resp.parsed_json["corrected_snippet"]

            # Deterministic verification of repaired coordinates
            is_valid, _ = cls.verify_exact_offset(source_text, fixed_quote, start, end)
            if is_valid:
                return Claim(
                    claim_id=unanchored_claim.claim_id,
                    statement=unanchored_claim.statement,
                    primary_quote=fixed_quote,
                    citation_id=unanchored_claim.citation_id,
                    char_start=start,
                    char_end=end,
                    source_uri=unanchored_claim.source_uri,
                    confidence=0.95,
                    offset_grounded=True,
                    entailment_reasoning="Repaired and verified via Pro High Reasoning citation repair.",
                )

        return unanchored_claim
