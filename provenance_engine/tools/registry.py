"""
ToolRegistry: Declarative Tool Registry with Deterministic Risk Tiers
"""

from enum import Enum
from typing import Dict, Any, Callable, Optional, List
from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    READ_ONLY = "read_only"
    COMPUTE = "compute"
    EXTERNAL_IO = "external_io"
    SENSITIVE_SYSTEM = "sensitive_system"


import jsonschema


class ToolDefinition(BaseModel):
    name: str
    description: str
    namespace: Optional[str] = "default"
    keywords: List[str] = Field(default_factory=list)
    examples: List[str] = Field(default_factory=list)
    risk_tier: RiskTier = RiskTier.READ_ONLY
    parameters_schema: Dict[str, Any] = Field(default_factory=dict)
    handler: Optional[Any] = Field(default=None, exclude=True)

    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True,
    }


class ToolInvocation(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def validate(self, invocation: ToolInvocation) -> bool:
        tool = self.get(invocation.tool_name)
        if not tool:
            raise ValueError(f"Tool '{invocation.tool_name}' not registered.")
        if tool.parameters_schema:
            try:
                jsonschema.validate(instance=invocation.arguments, schema=tool.parameters_schema)
            except jsonschema.ValidationError as e:
                raise ValueError(f"Tool invocation argument validation failed: {e.message}") from e
        return True

    def list_all(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def filter_by_risk(self, max_risk: RiskTier) -> List[ToolDefinition]:
        order = [
            RiskTier.READ_ONLY,
            RiskTier.COMPUTE,
            RiskTier.EXTERNAL_IO,
            RiskTier.SENSITIVE_SYSTEM,
        ]
        max_idx = order.index(max_risk)
        allowed_tiers = set(order[: max_idx + 1])
        return [t for t in self._tools.values() if t.risk_tier in allowed_tiers]


# Instantiate global registry with baseline OSINT tools
tool_registry = ToolRegistry()

tool_registry.register(
    ToolDefinition(
        name="safe_web_search",
        description="Searches OSINT indexes and news archives safely with parameter sanitization.",
        keywords=["search", "osint", "query", "web", "google", "bing", "archive"],
        risk_tier=RiskTier.EXTERNAL_IO,
        parameters_schema={"query": {"type": "string"}},
    )
)

tool_registry.register(
    ToolDefinition(
        name="fetch_verified_source",
        description="Downloads remote web document through SafeFetch SSRF-choke point.",
        keywords=["fetch", "download", "http", "url", "scrape", "crawl", "webpage"],
        risk_tier=RiskTier.EXTERNAL_IO,
        parameters_schema={"url": {"type": "string"}},
    )
)

tool_registry.register(
    ToolDefinition(
        name="extract_claims",
        description="Parses document text and extracts verbatim offset-grounded claims.",
        keywords=["extract", "claims", "evidence", "offset", "quotes", "text"],
        risk_tier=RiskTier.COMPUTE,
        parameters_schema={"source_text": {"type": "string"}},
    )
)

tool_registry.register(
    ToolDefinition(
        name="nli_validate_claim",
        description="Invokes Pro High Reasoning adversarial NLI to check claim entailment against evidence.",
        keywords=["validate", "nli", "entailment", "verify", "reasoning", "pro", "adversarial"],
        risk_tier=RiskTier.COMPUTE,
        parameters_schema={"premise": {"type": "string"}, "hypothesis": {"type": "string"}},
    )
)

tool_registry.register(
    ToolDefinition(
        name="cluster_sources",
        description="Runs 64-bit SimHash and Disjoint-Set clustering to identify Sybil/echo-chamber sources.",
        keywords=["cluster", "simhash", "sybil", "disjoint_set", "duplicate", "echo_chamber"],
        risk_tier=RiskTier.COMPUTE,
        parameters_schema={"documents": {"type": "array"}},
    )
)

tool_registry.register(
    ToolDefinition(
        name="calibrate_confidence",
        description="Computes Platt/Isotonic calibrated confidence scores across all verified claims.",
        keywords=["calibrate", "platt", "isotonic", "confidence", "probability", "score"],
        risk_tier=RiskTier.COMPUTE,
        parameters_schema={"raw_scores": {"type": "array"}},
    )
)

tool_registry.register(
    ToolDefinition(
        name="safe_git_clone",
        description="Clones public git repositories inside parameterized SafeExec sandbox.",
        keywords=["git", "clone", "repository", "code", "vcs"],
        risk_tier=RiskTier.SENSITIVE_SYSTEM,
        parameters_schema={"repo_url": {"type": "string"}, "dest_dir": {"type": "string"}},
    )
)
