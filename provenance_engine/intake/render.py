"""
InertMarkdownRenderer: Renders Untrusted Text and Tables into Safe Markdown
Neutralizes active HTML elements and renders strictly inert Markdown for safe LLM grounding.
"""

import html
import re
from typing import List, Dict, Any, Optional


class InertMarkdownRenderer:
    DANGEROUS_TAGS_PATTERN = re.compile(
        r"<\s*/?\s*(script|iframe|object|embed|form|meta|style|svg|math|link|applet)[^>]*>",
        re.IGNORECASE,
    )
    EVENT_HANDLER_PATTERN = re.compile(r"(\son\w+\s*=\s*['\"][^'\"]*['\"])", re.IGNORECASE)

    @classmethod
    def render_text(cls, text: str, source_label: Optional[str] = None) -> str:
        """Sanitizes HTML/markdown tags to create an inert plain-text markdown block."""
        if not text:
            return ""

        # Neutralize dangerous tags and JavaScript event handlers
        safe = cls.DANGEROUS_TAGS_PATTERN.sub("[FILTERED_TAG]", text)
        safe = cls.EVENT_HANDLER_PATTERN.sub(" [FILTERED_ATTR]", safe)

        lines = safe.splitlines()
        rendered_lines = []
        if source_label:
            rendered_lines.append(f"<!-- Source: {source_label} -->")

        for line in lines:
            rendered_lines.append(line)

        return "\n".join(rendered_lines)

    @classmethod
    def render_table(cls, headers: List[str], rows: List[List[str]]) -> str:
        """Renders 2D data into safe standard Markdown tables."""
        if not headers and not rows:
            return ""

        clean_headers = [cls._escape_cell(h) for h in headers]
        header_line = "| " + " | ".join(clean_headers) + " |"
        sep_line = "| " + " | ".join(["---"] * len(clean_headers)) + " |"

        rendered = [header_line, sep_line]
        for row in rows:
            # Pad row if shorter than headers
            padded = row + [""] * (len(clean_headers) - len(row))
            clean_cells = [cls._escape_cell(cell) for cell in padded[:len(clean_headers)]]
            rendered.append("| " + " | ".join(clean_cells) + " |")

        return "\n".join(rendered)

    @staticmethod
    def _escape_cell(content: Any) -> str:
        if content is None:
            return ""
        text = str(content).replace("\n", " ").replace("\r", " ").replace("|", "\\|")
        return html.escape(text.strip())


def render_safe_markdown(text: str) -> str:
    """Renders text safely into inert Markdown."""
    return InertMarkdownRenderer.render_text(text)

