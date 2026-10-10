# PROVENANCE Engine

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Architecture: Async-First](https://img.shields.io/badge/architecture-async--first-green.svg)]()
[![Security: Deterministic Boundaries](https://img.shields.io/badge/security-deterministic_boundaries-red.svg)]()

> **PROVENANCE** is an autonomous, zero-cost, multi-agent deep research and OSINT system that produces auditable dossiers with verified citations, a claim-verification ledger, and evidence-based calibrated confidence.

---

## Key Features

1. **Dual-Tier Model Router (`llm_router.py`)**:
   - `ModelTier.FAST_FLASH` (`gemini-3.8-flash`): High-throughput ingestion, scraping extraction, and routine keyword search.
   - `ModelTier.PRO_HIGH_REASONING` (`gemini-3.1-pro-preview` with `thinking_level="high"`, temperature `0.0`): Adversarial NLI entailment validation, indirect prompt injection triage, auto-correction / citation repair, and borderline tool disambiguation.
   - Offline zero-cost deterministic emulation mode for continuous integration testing without API expenses.

2. **Deterministic Security Boundaries**:
   - **SSRF & DNS Rebinding**: Socket pre-resolution blocking RFC 1918, Link-Local, carrier-grade NAT, and cloud metadata (`169.254.169.254`).
   - **File Intake Hardening**: Magic-byte content sniffing, `defusedxml` against XXE and billion-laugh bombs, and CSV/Excel formula injection (DDE) sanitization.
   - **Command Isolation**: Parameterized `SafeExec` prohibiting `shell=True`, enforcing binary allowlists, and stripping ambient credentials.
   - **Memory Taint Gating**: Information flow tracking tagging scraped data as untrusted and gating privileged tool execution.

3. **Verbatim Offset Grounding**:
   - Claims must satisfy exact character slice matching: `source_text[char_start:char_end] == quote`.
   - Broken or hallucinated quotes fail immediately at the extraction boundary.

4. **Sybil Resistance & Confidence Calibration**:
   - 64-bit SimHash and Disjoint-Set clustering collapses syndicated echo-chamber sources into single independent evidence weights.
   - Platt Scaling and Isotonic regression map raw scores to calibrated posterior probabilities in $[0.0, 1.0]$.

---

## Repository Structure

```text
provenance/
├── config/
│   ├── settings.py              # Pydantic BaseSettings, tier configs, limits
│   └── blocked_domains.json     # SSRF CIDR ranges, banned hosts, malware TLDs
├── provenance_engine/
│   ├── __init__.py
│   ├── llm_router.py            # Dual-tier router (Flash vs Pro 3.1 High Thinking)
│   ├── net/
│   │   ├── safe_fetch.py        # Async SSRF-proof network client with DNS pinning
│   │   ├── proxy.py             # Proxy rotation and pooling
│   │   └── playwright_guard.py  # Sandboxed headless browser manager
│   ├── intake/
│   │   ├── content_router.py    # Magic-byte file router
│   │   ├── sanitizer.py         # Unicode NFKC, delimiter, Bidi cleaner
│   │   ├── render.py            # Inert Markdown renderer
│   │   └── handlers/
│   │       ├── html.py          # Trafilatura / BS4 handler
│   │       ├── pdf.py           # pdfplumber table extractor
│   │       ├── csv_xlsx.py      # openpyxl data_only & DDE injection sanitizer
│   │       ├── docx_pptx.py     # Safe zip decompression & XML extractor
│   │       └── xml.py           # defusedxml XXE-safe parser
│   ├── extract/
│   │   ├── schemas.py           # Pydantic v2 schemas (extra="forbid")
│   │   └── extractor.py         # Verbatim offset-grounded claim extractor
│   ├── exec/
│   │   └── safe_exec.py         # Shell-free parameterized command executor
│   ├── tools/
│   │   ├── registry.py          # Typed tool registry with capability levels
│   │   └── router.py            # Hybrid BM25 + dense similarity router (k <= 15)
│   ├── trust/
│   │   ├── clustering.py        # SimHash & Disjoint-Set engine
│   │   ├── calibrator.py        # Platt/Isotonic confidence calibrator
│   │   └── taint.py             # Memory taint tracker & tool gate
│   └── graph/
│       ├── state.py             # LangGraph state definitions
│       └── graph.py             # Multi-agent LangGraph workflow
├── tests/
│   ├── __init__.py
│   └── test_acceptance.py       # Full acceptance suite testing all security & verification gates
├── docs/
│   ├── PLAN.md                  # Comprehensive architectural specification
│   ├── SECURITY.md              # Threat model and deterministic boundaries
│   └── KNOWN_GAPS.md            # Documented limitations, edge cases, and future roadmap
├── requirements.txt
└── README.md
```

---

## Getting Started

### Installation
```bash
git clone https://github.com/provenance/engine.git
cd engine
pip install -r requirements.txt
```

### Running the Acceptance Suite
```bash
python -m pytest tests/test_acceptance.py -v
```

### Running an OSINT Research Workflow
```python
import asyncio
from provenance_engine.graph.state import ResearchState
from provenance_engine.graph.graph import ResearchGraph

async def main():
    graph = ResearchGraph()
    state = ResearchState(
        query="Investigate Project Provenance architecture",
        target_urls=["https://example-osint.org/report1.html"],
    )
    result = await graph.run(state)
    print(result.dossier.executive_summary)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Documentation
- [Architectural Plan](docs/PLAN.md)
- [Security Model](docs/SECURITY.md)
- [Known Gaps & Roadmap](docs/KNOWN_GAPS.md)
