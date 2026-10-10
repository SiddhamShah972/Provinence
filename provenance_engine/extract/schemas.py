"""
Strict Pydantic v2 Schemas for Extraction, Grounding, and Verification
All models strictly enforce extra='forbid' to reject untrusted/unexpected fields.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class EvidenceSnippet(BaseModel):
    snippet_id: str = Field(..., description="Unique deterministic identifier of the snippet.")
    source_uri: str = Field(..., description="Source URL or document identifier.")
    exact_text: str = Field(..., description="Verbatim extracted string from the raw document.")
    char_start: int = Field(..., ge=0, description="Exact 0-based character start offset.")
    char_end: int = Field(..., ge=0, description="Exact 0-based character end offset.")
    page_or_line: Optional[int] = Field(default=None, description="Document page or line number if applicable.")
    source_hash: str = Field(..., description="SHA-256 hash of the complete parent source document.")
    verified: bool = Field(default=False, description="Whether offset exact match has been proven.")

    model_config = {
        "extra": "forbid",
        "frozen": True,
    }

    @field_validator("char_end")
    @classmethod
    def validate_offsets(cls, v: int, info) -> int:
        start = info.data.get("char_start")
        if start is not None and v < start:
            raise ValueError(f"char_end ({v}) must be greater than or equal to char_start ({start})")
        return v


class Claim(BaseModel):
    claim_id: str = Field(..., description="Deterministic claim identifier.")
    statement: str = Field(..., description="Atomic factual assertion.")
    primary_quote: str = Field(..., description="Verbatim cited evidence backing the claim.")
    citation_id: str = Field(..., description="Reference to the backing EvidenceSnippet id.")
    char_start: int = Field(..., ge=0)
    char_end: int = Field(..., ge=0)
    source_uri: str = Field(..., description="Source URI.")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    entailment_verified: bool = Field(default=False)
    offset_grounded: bool = Field(default=False)
    entailment_reasoning: Optional[str] = Field(default=None)

    model_config = {
        "extra": "forbid",
        "frozen": True,
    }


class VerificationEntry(BaseModel):
    claim_id: str
    status: str = Field(..., description="VERIFIED, UNANCHORED, CONTRADICTED, or REPAIRED")
    offset_match: bool
    entailment_score: float = Field(..., ge=0.0, le=1.0)
    cluster_id: Optional[str] = None
    audit_note: str

    model_config = {
        "extra": "forbid",
        "frozen": True,
    }


class VerificationLedger(BaseModel):
    ledger_id: str
    entries: List[VerificationEntry] = Field(default_factory=list)
    total_claims: int = 0
    verified_claims: int = 0
    unanchored_claims: int = 0
    audit_timestamp: str

    model_config = {
        "extra": "forbid",
        "frozen": True,
    }


class Dossier(BaseModel):
    dossier_id: str
    target_query: str
    executive_summary: str
    verified_claims: List[Claim] = Field(default_factory=list)
    ledger: VerificationLedger
    source_clusters: List[Dict[str, Any]] = Field(default_factory=list)
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: str

    model_config = {
        "extra": "forbid",
        "frozen": True,
    }
