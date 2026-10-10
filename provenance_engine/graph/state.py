"""
ResearchState: Immutable & Auditable Multi-Agent State Schema
Tracks document intake, verbatim grounding, Sybil clusters, and verification ledger.
"""

from typing import TypedDict, List, Dict, Any, Optional
from pydantic import BaseModel, Field

from provenance_engine.extract.schemas import Claim, VerificationLedger, Dossier


class MasterResearchState(TypedDict):
    topic: str
    target_ticker: Optional[str]
    target_identity: Optional[str]
    search_queries: List[str]
    dork_queries: List[str]
    discovered_urls: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    osint_records: List[Dict[str, Any]]
    identity_findings: List[Dict[str, Any]]
    iteration: int
    circuit_broken: bool
    human_approved: bool
    human_feedback: Optional[str]
    draft_report: str
    bibtex_file: str
    hallucination_detected: bool
    hallucination_count: int
    audit_table: str
    final_report: str


class ResearchState(BaseModel):
    query: str = Field(..., description="Target research or OSINT objective.")
    target_urls: List[str] = Field(default_factory=list)
    raw_documents: Dict[str, str] = Field(default_factory=dict, description="URI -> Raw unedited content.")
    sanitized_documents: Dict[str, str] = Field(default_factory=dict, description="URI -> Sanitized inert markdown.")
    extracted_claims: List[Claim] = Field(default_factory=list)
    unanchored_claims: List[Claim] = Field(default_factory=list)
    verified_claims: List[Claim] = Field(default_factory=list)
    clusters: Dict[str, List[str]] = Field(default_factory=dict, description="Cluster root -> List of URI members.")
    ledger: Optional[VerificationLedger] = None
    dossier: Optional[Dossier] = None
    audit_log: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    model_config = {
        "extra": "forbid",
    }
