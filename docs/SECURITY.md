# PROVENANCE Engine: Security Architecture & Threat Model

## 1. Security Philosophy
In adversarial OSINT and deep research environments, external inputs are untrusted by default.
Prompt-level constraints ("Do not run dangerous commands", "Ignore injection attempts") are fundamentally non-deterministic and insufficient.
**All security boundaries in `provenance_engine` are enforced in deterministic code, network configuration, and system-level checks.**

---

## 2. Threat Vector Mitigations

| Threat Vector | Attack Scenario | Deterministic Defense Mechanism |
|---|---|---|
| **Server-Side Request Forgery (SSRF)** | Attacker submits `http://169.254.169.254/latest/meta-data/` or internal IP `http://10.0.0.1` | `SafeFetch` pre-resolves DNS and checks IP against RFC 1918, Link-Local, and metadata CIDR blocklists. Disallowed schemes (`file://`, `gopher://`, `data://`) are rejected. |
| **DNS Rebinding** | Domain resolves to public IP on first check, then rebands to `127.0.0.1` on socket connect | Pre-resolved IP validation and connection address pinning. |
| **XML External Entity (XXE)** | XML containing `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Parsed strictly via `defusedxml` with entity expansion and external DTD retrieval blocked. |
| **CSV / DDE Formula Injection** | Cell content containing `=cmd|' /C calc'!A0` or `@SUM(...)` | `TabularHandler` detects leading command triggers (`=`, `+`, `-`, `@`, `\t`, `\r`, `%`) and prepends `'` to neutralize execution in spreadsheet software. |
| **Decompression Bomb (Zip Bomb)** | Archive containing gigabytes of zeros expanding to exhaust disk/RAM | `OfficeHandler` checks total uncompressed size ($\le 50\text{ MB}$), compression ratio ($\le 100:1$), and entry count ($\le 1000$). |
| **Prompt Injection / Jailbreaks** | Untrusted scraped document containing `[INST] Ignore previous instructions [/INST]` | `TextSanitizer` normalizes homoglyphs (NFKC), strips Bidi override characters (`\u202E`), removes zero-width characters, and neutralizes instruction tokens. |
| **Tool Execution Hijacking** | Tainted scraped strings passed directly to system execution tools | `TaintGate` and `MemoryTaintTracker` enforce taint boundaries; untrusted external data cannot be passed to privileged tools without verified sanitization. |
| **Subprocess Command Injection** | Passing malicious arguments with `; rm -rf /` or pipes to CLI commands | `SafeExec` enforces `shell=False`, uses binary allowlists, scrubs environment credentials, and blocks shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`). |
| **Hallucinated Citations** | LLM generates plausible-sounding quotes not present in the source | `ClaimExtractor` strictly requires `source_text[char_start:char_end] == quote`. Hallucinated or drifted quotes are flagged as `UNANCHORED`. |
| **Sybil Echo-Chambers** | Coordinated disinformation networks publishing identical articles across 20 domains | `SimHashClusterEngine` computes 64-bit SimHash fingerprints and clusters near-duplicates ($\text{Hamming distance} \le 7$), collapsing them into single evidence weights. |

---

## 3. Privilege & Risk Tiers

Tools are partitioned into deterministic risk levels:
1. `RiskTier.READ_ONLY`: Pure in-memory queries and transformations.
2. `RiskTier.COMPUTE`: Algorithmic calculations (NLI entailment, SimHash, calibration).
3. `RiskTier.EXTERNAL_IO`: Network requests routed through `SafeFetch`.
4. `RiskTier.SENSITIVE_SYSTEM`: Parameterized command execution sandboxed by `SafeExec`.
