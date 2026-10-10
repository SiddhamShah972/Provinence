"""
Extraction & Grounding Pipeline
"""

from provenance_engine.extract.schemas import (
    EvidenceSnippet,
    Claim,
    VerificationEntry,
    VerificationLedger,
    Dossier,
)
from provenance_engine.extract.extractor import ClaimExtractor

__all__ = [
    "EvidenceSnippet",
    "Claim",
    "VerificationEntry",
    "VerificationLedger",
    "Dossier",
    "ClaimExtractor",
]
