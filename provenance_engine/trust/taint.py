"""
Memory Taint Tracker & Tool Execution Gate
Maintains strict information flow security, tagging unverified external data
and preventing tainted values from reaching privileged tool parameters.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from provenance_engine.tools.registry import ToolDefinition, RiskTier


class TaintLevel(str, Enum):
    SAFE_INTERNAL = "safe_internal"
    UNTRUSTED_INGESTION = "untrusted_ingestion"
    INJECTION_QUARANTINE = "injection_quarantine"
    SANITIZED_PROCESSED = "sanitized_processed"


class TaintViolationError(Exception):
    """Raised when tainted, untrusted data attempts to flow into privileged execution tools."""
    pass


# Alias for integration testing and tool gating
TaintExecutionException = TaintViolationError


class TaintRecord(BaseModel):
    data_id: str
    taint_level: TaintLevel
    origin_uri: Optional[str] = None
    sanitization_history: List[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class MemoryTaintTracker:
    def __init__(self):
        self._records: Dict[str, TaintRecord] = {}

    def register(self, data_id: str, level: TaintLevel, origin_uri: Optional[str] = None) -> TaintRecord:
        record = TaintRecord(data_id=data_id, taint_level=level, origin_uri=origin_uri)
        self._records[data_id] = record
        return record

    def tag_untrusted(self, data_id: str, origin_uri: str) -> TaintRecord:
        return self.register(data_id, TaintLevel.UNTRUSTED_INGESTION, origin_uri)

    def quarantine(self, data_id: str, reason: str) -> TaintRecord:
        rec = self._records.get(data_id)
        if rec:
            rec.sanitization_history.append(f"QUARANTINED: {reason}")
            # Pydantic model is frozen=False if not specified, let's update
            updated = TaintRecord(
                data_id=rec.data_id,
                taint_level=TaintLevel.INJECTION_QUARANTINE,
                origin_uri=rec.origin_uri,
                sanitization_history=rec.sanitization_history,
            )
            self._records[data_id] = updated
            return updated
        return self.register(data_id, TaintLevel.INJECTION_QUARANTINE)

    def mark_sanitized(self, data_id: str, action_desc: str) -> TaintRecord:
        rec = self._records.get(data_id)
        history = list(rec.sanitization_history) if rec else []
        history.append(f"SANITIZED: {action_desc}")
        updated = TaintRecord(
            data_id=data_id,
            taint_level=TaintLevel.SANITIZED_PROCESSED,
            origin_uri=rec.origin_uri if rec else None,
            sanitization_history=history,
        )
        self._records[data_id] = updated
        return updated

    def get_level(self, data_id: str) -> TaintLevel:
        rec = self._records.get(data_id)
        return rec.taint_level if rec else TaintLevel.SAFE_INTERNAL


class TaintGate:
    """Enforces execution barriers for privileged tools."""

    @classmethod
    def verify_execution(
        cls,
        tool: ToolDefinition,
        arguments: Dict[str, Any],
        taint_tracker: MemoryTaintTracker,
    ) -> None:
        """Deterministically halts execution if untrusted/quarantined data enters privileged tools."""
        if tool.risk_tier not in (RiskTier.EXTERNAL_IO, RiskTier.SENSITIVE_SYSTEM):
            # Compute / Read-only internal tools are permitted
            return

        for param_name, param_val in arguments.items():
            # Check string arguments for tagged IDs or untrusted marker tags
            val_str = str(param_val)

            # Check direct data_id lookup
            taint_level = taint_tracker.get_level(val_str)
            if taint_level in (TaintLevel.UNTRUSTED_INGESTION, TaintLevel.INJECTION_QUARANTINE):
                raise TaintViolationError(
                    f"Taint violation: Parameter '{param_name}' contains data with level '{taint_level.value}' "
                    f"blocked from privileged tool '{tool.name}' (Tier: {tool.risk_tier.value})."
                )

            # Check explicit marker in string
            if "[UNTRUSTED_RAW]" in val_str or "<|untrusted|>" in val_str:
                raise TaintViolationError(
                    f"Taint violation: Raw untrusted marker detected in parameter '{param_name}' "
                    f"for tool '{tool.name}'."
                )


class TaintedArtifact(BaseModel):
    content: str
    source: str
    is_tainted: bool = True


class TaintTracker:
    """Artifact-centric taint tracker for OSINT ingestion."""
    def __init__(self):
        self.artifacts: List[TaintedArtifact] = []

    def record_artifact(self, content: str, source: str, trusted: bool = False) -> TaintedArtifact:
        artifact = TaintedArtifact(content=content, source=source, is_tainted=not trusted)
        self.artifacts.append(artifact)
        return artifact

    def verify_tool_execution(self, tool_name: str, args: List[Any]) -> bool:
        privileged_prefixes = ("credential_broker", "system", "file_write", "exec", "shell")
        if any(tool_name.startswith(p) for p in privileged_prefixes):
            for arg in args:
                if getattr(arg, "is_tainted", False):
                    raise TaintExecutionException(
                        f"Taint violation: Tainted artifact from '{arg.source}' cannot be passed to privileged tool '{tool_name}'"
                    )
        return True

