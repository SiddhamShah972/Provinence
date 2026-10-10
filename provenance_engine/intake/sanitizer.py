"""
TextSanitizer: Script-Aware Unicode & Delimiter Cleaner
Enforces NFKC normalization, strips bidirectional & invisible control codes,
and neutralizes LLM delimiter injection sequences.
"""

import re
import unicodedata
from typing import Tuple, List
from pydantic import BaseModel, Field


class SanitizationReport(BaseModel):
    bidi_chars_removed: int = 0
    zero_width_chars_removed: int = 0
    delimiters_neutralized: int = 0
    homoglyphs_normalized: bool = False
    original_length: int = 0
    sanitized_length: int = 0


class TextSanitizer:
    # Bidirectional override characters: LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI, LRM, RLM
    BIDI_PATTERN = re.compile(r"[\u200E\u200F\u202A-\u202E\u2066-\u2069]")

    # Zero-width / invisible format characters: ZWSP, ZWNJ, ZWJ, BOM, soft hyphen
    ZERO_WIDTH_PATTERN = re.compile(r"[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]")

    # Suspicious control characters (preserve standard whitespace \t, \n, \r)
    DANGEROUS_CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

    # LLM instruction delimiters that could alter prompt parsing
    DELIMITER_REPLACEMENTS = [
        (re.compile(r"\[/?INST\]", re.IGNORECASE), "[ESCAPED_INST]"),
        (re.compile(r"<\|im_(start|end)\|>", re.IGNORECASE), "<|escaped_im_token|>"),
        (re.compile(r"<\s*/?\s*(system|prompt|instruction)\s*>", re.IGNORECASE), "<escaped_tag>"),
        (re.compile(r"^(\s*)(Human|Assistant|System)(\s*:)", re.MULTILINE | re.IGNORECASE), r"\1[Role:\2]\3"),
    ]

    @classmethod
    def sanitize(cls, text: str) -> Tuple[str, SanitizationReport]:
        if not text:
            return "", SanitizationReport()

        report = SanitizationReport(original_length=len(text))

        # 1. Unicode NFKC Normalization (resolves confusables and homoglyphs)
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            report.homoglyphs_normalized = True

        # 2. Count and strip Bidirectional characters
        bidi_matches = cls.BIDI_PATTERN.findall(normalized)
        report.bidi_chars_removed = len(bidi_matches)
        cleaned = cls.BIDI_PATTERN.sub("", normalized)

        # 3. Count and strip Zero-Width / invisible characters
        zw_matches = cls.ZERO_WIDTH_PATTERN.findall(cleaned)
        report.zero_width_chars_removed = len(zw_matches)
        cleaned = cls.ZERO_WIDTH_PATTERN.sub("", cleaned)

        # 4. Strip dangerous ASCII control chars
        cleaned = cls.DANGEROUS_CONTROL_PATTERN.sub("", cleaned)

        # 5. Neutralize LLM Prompt Injection Delimiters
        for pattern, replacement in cls.DELIMITER_REPLACEMENTS:
            matches = pattern.findall(cleaned)
            if matches:
                report.delimiters_neutralized += len(matches)
                cleaned = pattern.sub(replacement, cleaned)

        report.sanitized_length = len(cleaned)
        return cleaned, report
