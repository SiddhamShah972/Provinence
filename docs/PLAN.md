# PROVENANCE Engine: Complete Architectural Plan & Technical Design

## 1. Executive Overview
`provenance_engine` is an autonomous, zero-cost, multi-agent deep research and Open Source Intelligence (OSINT) system designed to produce auditable dossiers with verified citations, a claim-verification ledger, and evidence-based calibrated confidence.

Every security boundary is enforced in deterministic code, network configuration, or system calls—never relying solely on LLM prompt instructions.

---

## 2. Dynamic Dual-Tier Model Router Specification
The core LLM dispatch layer is governed by `provenance_engine/llm_router.py`. Workloads are deterministically segregated into two tiers:

1. **`ModelTier.FAST_FLASH` (`gemini-3.8-flash`)**:
   - High-throughput, low-latency ingestion, scraping extraction, and routine search queries.
   - Low token overhead, fast async iteration.

2. **`ModelTier.PRO_HIGH_REASONING` (`gemini-3.1-pro-preview`)**:
   - Invoked with `thinking_level="high"` and temperature `0.0`.
   - Reserved for:
     1. Adversarial NLI claim entailment validation (`validator.py` / `graph.validation_node`).
     2. Indirect prompt injection triage and payload deconstruction.
     3. Auto-correction and citation repair (`auto_corrector.py` / `extractor.repair_citation`).
     4. Tool routing disambiguation when retrieval confidence is borderline ($\Delta < 0.15$).

---

## 3. Subsystem Breakdown

### 3.1 Network Choke Point (`provenance_engine/net/safe_fetch.py`)
- Pre-resolves DNS before establishing TCP connections.
- Deterministically blocks:
  - Loopback (`127.0.0.0/8`, `::1`)
  - RFC 1918 Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Link-Local and Cloud Metadata (`169.254.0.0/16`, `fe80::/10`, `169.254.169.254`)
  - Carrier-Grade NAT (`100.64.0.0/10`)
  - Disallowed schemes (`file://`, `gopher://`, `data://`, etc.)
- Enforces strict streaming byte cap (10 MB) to defeat compression bombs.

### 3.2 Hardened Intake & Parser Pipeline (`provenance_engine/intake/`)
- **Magic-Byte Sniffing (`content_router.py`)**: Identifies true file types by byte headers (`%PDF-`, `PK\x03\x04`, `<?xml`, `\x89PNG`).
- **Script-Aware Sanitizer (`sanitizer.py`)**: Normalizes Unicode homoglyphs (NFKC), removes bidirectional override controls (`\u202E`), strips zero-width invisibles (`\u200B`), and neutralizes LLM delimiters (`[INST]`, `<|im_start|>`).
- **Inert Markdown Renderer (`render.py`)**: Renders untrusted text/tables safely while neutralizing active HTML `<script>`, `<iframe>`, `on*` handlers.
- **Format Handlers (`intake/handlers/`)**:
  - `html.py`: Clean DOM extraction stripping executable elements.
  - `pdf.py`: PDF table and text extraction with page offsets.
  - `csv_xlsx.py`: OpenPyXL `data_only=True` and formula injection DDE mitigation (neutralizing leading `=`, `+`, `-`, `@`, `\t`, `\r`).
  - `docx_pptx.py`: Zip bomb mitigation (compression ratio & uncompressed caps) and `defusedxml` text extraction.
  - `xml.py`: Hardened `defusedxml` parser blocking XXE and entity expansion bombs.

### 3.3 Verbatim Offset Grounding (`provenance_engine/extract/`)
- Strict Pydantic v2 models (`extra="forbid"`, `frozen=True`).
- Verbatim citation invariant: `source_text[char_start:char_end] == quote`.
- Broken, drifted, or hallucinated quotes fail verification immediately.

### 3.4 Parameterized Command Isolation (`provenance_engine/exec/safe_exec.py`)
- Prohibits `shell=True`.
- Strict allowlist of binaries (`python`, `git`, `echo`, `pytest`).
- Rejects shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `\n`, `\r`, `>`, `<`).
- Strips ambient API keys and credentials from environment variables.

### 3.5 Hybrid Tool Router (`provenance_engine/tools/router.py`)
- BM25 lexical search + dense token overlap similarity.
- Strictly bounds candidates to $k \le 15$.
- Escalates borderline decisions ($\Delta < 0.15$) to `ModelTier.PRO_HIGH_REASONING`.

### 3.6 Trust, Sybil Clustering & Memory Taint (`provenance_engine/trust/`)
- **Sybil SimHash Engine (`clustering.py`)**: Computes 64-bit SimHash fingerprints and clusters near-duplicate syndicated sources via Disjoint-Set (Union-Find).
- **Calibrator (`calibrator.py`)**: Platt Scaling / Isotonic regression mapping raw entailment to calibrated probabilities, penalizing single-cluster echo chambers.
- **Taint Tracker & Gate (`taint.py`)**: Information flow security gating privileged tool execution against untrusted external inputs.

### 3.7 LangGraph Multi-Agent Workflow (`provenance_engine/graph/`)
- Sequential 7-node pipeline:
  `Ingest` $\rightarrow$ `Extract (Flash)` $\rightarrow$ `Sybil Cluster` $\rightarrow$ `Auto-Correct (Pro)` $\rightarrow$ `Validate (Pro NLI)` $\rightarrow$ `Calibrate` $\rightarrow$ `Dossier Synthesizer`.
