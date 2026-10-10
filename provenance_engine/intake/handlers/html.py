"""
HTML Document Handler
Extracts clean, readable DOM text while stripping executable or tracking elements.
"""

from typing import Dict, Any, Tuple
from bs4 import BeautifulSoup
from loguru import logger


class HTMLHandler:
    STRIP_TAGS = {"script", "style", "noscript", "iframe", "svg", "header", "footer", "nav", "aside"}

    @classmethod
    def extract_text_and_meta(cls, raw_html: bytes | str) -> Tuple[str, Dict[str, Any]]:
        if isinstance(raw_html, bytes):
            html_text = raw_html.decode("utf-8", errors="replace")
        else:
            html_text = raw_html

        soup = BeautifulSoup(html_text, "html.parser")

        # Extract title before stripping
        title = soup.title.string.strip() if soup.title and soup.title.string else ""

        # Remove prohibited tags
        for element in soup.find_all(cls.STRIP_TAGS):
            element.decompose()

        # Extract textual content with preserved paragraph boundaries
        paragraphs = []
        for p in soup.find_all(["p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote", "td", "th"]):
            text = p.get_text(strip=True)
            if text:
                paragraphs.append(text)

        full_text = "\n\n".join(paragraphs)
        if not full_text:
            # Fallback to general text extraction
            full_text = soup.get_text(separator="\n", strip=True)

        metadata = {
            "title": title,
            "paragraph_count": len(paragraphs),
            "char_count": len(full_text),
        }

        return full_text, metadata
