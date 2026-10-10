"""
OSINT Integration and Isolation Test Suite for Provenance Engine.
Verifies safe execution, regex parameter bounds, and taint propagation
for infrastructure recon, identity tracking, and structured public silos.
"""
from __future__ import annotations

import pytest
from provenance_engine.exec.safe_exec import (
    HardenedSubprocessRunner,
    SubprocessSecurityException,
)
from provenance_engine.tools.registry import ToolDefinition, ToolInvocation, ToolRegistry
from provenance_engine.trust.taint import TaintTracker, TaintExecutionException


# =====================================================================
# 1. PARAMETER SANITIZATION FOR OSINT TARGETS
# =====================================================================

def test_osint_handle_validation():
    """Validates platform handles against strict allowlists."""
    # Valid OSINT targets
    assert HardenedSubprocessRunner.validate_arg("torvalds", "handle") == "torvalds"
    assert HardenedSubprocessRunner.validate_arg("security_lead.01", "handle") == "security_lead.01"

    # Attack vectors targeting CLI wrappers
    malicious_handles = [
        "-v",                     # Flag injection
        "--all",                  # Long flag injection
        "admin; whoami",          # Command chaining
        "user | cat /etc/passwd", # Pipe injection
        "dev`id`",                # Backtick evaluation
        "user\0name",             # Null-byte injection
    ]
    for bad_handle in malicious_handles:
        with pytest.raises(SubprocessSecurityException):
            HardenedSubprocessRunner.validate_arg(bad_handle, "handle")


def test_osint_domain_validation():
    """Validates domain targets for crt.sh and DNS tools."""
    assert HardenedSubprocessRunner.validate_arg("kernel.org", "domain") == "kernel.org"

    malicious_domains = [
        "-rf",
        "kernel.org && ls",
        "example.com/../../etc",
        "*.malicious.com",        # Wildcard expansion risk in shell
    ]
    for bad_domain in malicious_domains:
        with pytest.raises(SubprocessSecurityException):
            HardenedSubprocessRunner.validate_arg(bad_domain, "domain")


# =====================================================================
# 2. OSINT TOOL REGISTRATION & ROUTING
# =====================================================================

def test_osint_parameterized_dispatch():
    """Verifies parameterized OSINT tool registry schema validation."""
    registry = ToolRegistry()

    # Register parameterized OSINT tool
    osint_tool = ToolDefinition(
        name="osint.query",
        namespace="osint",
        description="Queries public threat, certificate, and post-mortem silos (crt.sh, SEC, HN).",
        parameters_schema={
            "type": "object",
            "properties": {
                "source": {"type": "string", "enum": ["crt_sh", "hacker_news", "wikidata"]},
                "target": {"type": "string", "maxLength": 120}
            },
            "required": ["source", "target"],
            "additionalProperties": False
        },
        examples=["lookup subdomains for domain", "find developer mentions on hacker news"]
    )
    registry.register(osint_tool)

    # Valid invocation
    valid_call = ToolInvocation(
        tool_name="osint.query",
        arguments={"source": "crt_sh", "target": "openblas.net"}
    )
    assert registry.validate(valid_call) is True

    # Invalid source enum
    invalid_source_call = ToolInvocation(
        tool_name="osint.query",
        arguments={"source": "unvetted_crawler", "target": "openblas.net"}
    )
    with pytest.raises(ValueError):
        registry.validate(invalid_source_call)

    # Injected extra properties
    extra_prop_call = ToolInvocation(
        tool_name="osint.query",
        arguments={"source": "crt_sh", "target": "openblas.net", "bypass_flags": "--all"}
    )
    with pytest.raises(ValueError):
        registry.validate(extra_prop_call)


# =====================================================================
# 3. TAINT TRACKING ON HARVESTED OSINT DATA
# =====================================================================

def test_osint_data_taint_propagation():
    """Ensures raw records retrieved from OSINT tools cannot enter privileged tools."""
    tracker = TaintTracker()

    # Simulated raw record from crt.sh or social handle enumeration
    osint_payload = "Target handle linked to Git repo: https://github.com/anon-dev/leaked-keys"
    tainted_record = tracker.record_artifact(
        content=osint_payload,
        source="osint:identity_recon",
        trusted=False
    )

    assert tainted_record.is_tainted is True

    # Privileged write tool call must be blocked
    with pytest.raises(TaintExecutionException):
        tracker.verify_tool_execution("credential_broker.get_secret", [tainted_record])
