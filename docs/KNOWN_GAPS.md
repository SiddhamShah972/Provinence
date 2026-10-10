# PROVENANCE Engine: Known Gaps & Future Roadmap

## 1. Architectural & Operational Boundaries

1. **IPv6 Scope & Egress Proxying**:
   - `SafeFetch` verifies IPv6 link-local and unique local addresses (`fe80::/10`, `fc00::/7`). In corporate environments with complex dual-stack NAT64/DNS64 infrastructures, an egress forward proxy should be configured to handle upstream translation.

2. **OCR for Scanned PDFs**:
   - `PDFHandler` currently extracts native vector text and tables. Scanned bitmap documents without embedded OCR text layers require an external sandboxed Tesseract/Vision API pass, which is skipped in zero-cost mode.

3. **Dynamic Single Page Applications (SPAs)**:
   - When pages rely heavily on client-side React/Vue hydration, `SafeFetch` retrieves raw initial HTML. For dynamic SPAs, `PlaywrightGuard` should be engaged with inert context options (`java_script_enabled=True` in sandboxed headless mode).

4. **Multi-Hop DNS Rebinding Timing Windows**:
   - While IP resolution pre-checks verify safety, ultra-fast DNS TTL rebinding attacks can theoretically resolve a different IP between DNS resolution and socket handshake. To achieve absolute zero-window pinning, custom `httpx` HTTP transports binding sockets directly to resolved IP addresses with synthetic `Host` headers can be added.

5. **Cross-Language Semantic Clustering**:
   - The 64-bit SimHash engine operates on character/word tokens. Multilingual cross-lingual plagiarism (e.g. English translation of a Russian article) requires multilingual dense embeddings in addition to lexical SimHash fingerprints.

---

## 2. Hardening Roadmap
- [ ] Integration with hardware-enforced seccomp / gVisor containers for CLI execution.
- [ ] Content-Addressable Storage (CAS) on disk for full cryptographic audit trails.
- [ ] Live streaming graph visualization for LangGraph inspection.
