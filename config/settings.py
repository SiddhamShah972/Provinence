"""
Provenance Engine Configuration & Settings
Defines deterministic system thresholds, model tier parameters, SSRF security lists,
and execution boundaries.
"""

from pathlib import Path
from typing import Set, Tuple, Optional
import json
import os
from pydantic import BaseModel, Field

CONFIG_DIR = Path(__file__).resolve().parent
ROOT_DIR = CONFIG_DIR.parent
BLOCKED_DOMAINS_PATH = CONFIG_DIR / "blocked_domains.json"

def _load_env_file(dotenv_path: Path) -> None:
    if dotenv_path.is_file():
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                k, sep, v = line.partition("=")
                if sep:
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v

_load_env_file(ROOT_DIR / ".env")


class Settings(BaseModel):
    # LLM Dual-Tier Router
    fast_flash_model: str = Field(
        default="gemini-3.8-flash",
        description="High-throughput tier for ingestion, scraping extraction, and routine search."
    )
    pro_high_reasoning_model: str = Field(
        default="gemini-3.1-pro-preview",
        description="Deep reasoning tier for NLI validation, injection triage, and citation repair."
    )
    pro_thinking_level: str = Field(
        default="high",
        description="Thinking level configuration for the Pro reasoning tier."
    )
    pro_temperature: float = Field(
        default=0.0,
        description="Deterministic zero temperature for reasoning validation."
    )
    gemini_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    )
    mock_llm_mode: bool = Field(
        default_factory=lambda: os.getenv("PROVENANCE_MOCK_LLM", "false").lower() in ("1", "true", "yes"),
        description="Deterministic offline mode for tests and zero-cost simulation."
    )

    # Network & SSRF Security Boundaries
    max_fetch_bytes: int = Field(default=10 * 1024 * 1024)  # 10 MB strict cap
    connect_timeout_seconds: float = Field(default=5.0)
    read_timeout_seconds: float = Field(default=15.0)
    allowed_schemes: Tuple[str, ...] = ("http", "https")
    blocked_domains_file: Path = Field(default=BLOCKED_DOMAINS_PATH)

    # Tool & Retrieval Routing
    max_tool_candidates: int = Field(default=15, description="Strict k <= 15 limit for tool context exposure.")
    borderline_confidence_delta: float = Field(default=0.15, description="Confidence margin triggering Pro reasoning escalation.")

    # Trust, Sybil & Calibration
    simhash_distance_threshold: int = Field(default=3, description="Hamming distance threshold for Sybil / duplicate clustering.")
    confidence_prior: float = Field(default=0.5, description="Prior belief for factual claim confidence.")

    # Execution Sandbox
    exec_timeout_seconds: float = Field(default=30.0)
    allowed_exec_binaries: Tuple[str, ...] = ("git", "python", "echo", "pytest", "pandoc")

    model_config = {
        "frozen": True,
        "extra": "forbid"
    }

    def load_blocked_rules(self) -> dict:
        if self.blocked_domains_file.is_file():
            with open(self.blocked_domains_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {
            "blocked_hostnames": ["localhost", "127.0.0.1", "::1", "169.254.169.254"],
            "blocked_cidr_ranges": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"],
            "disallowed_schemes": ["file", "gopher", "data", "javascript"],
            "malicious_tlds": [".zip", ".mov"]
        }


# Singleton settings instance
settings = Settings()
