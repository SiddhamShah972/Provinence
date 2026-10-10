"""
PDF Document Handler
Extracts text and table structures with page-level offset mapping.
"""

import io
import re
from typing import Dict, Any, List, Tuple
from loguru import logger


class PDFHandler:
    @classmethod
    def extract_text_and_tables(cls, data: bytes) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
        """Extracts text and tables with page tracking."""
        pages_text: List[str] = []
        tables: List[Dict[str, Any]] = []

        try:
            import pdfplumber

            with pdfplumber.open(io.BytesIO(data)) as pdf:
                for idx, page in enumerate(pdf.pages):
                    text = page.extract_text() or ""
                    pages_text.append(f"--- Page {idx + 1} ---\n{text}")

                    # Extract tables if present
                    extracted_tables = page.extract_tables()
                    for t_idx, tbl in enumerate(extracted_tables):
                        if tbl:
                            tables.append({
                                "page": idx + 1,
                                "table_id": t_idx + 1,
                                "rows": tbl,
                            })
        except ImportError:
            # Fallback using pypdf or lightweight PDF stream scanner
            try:
                import pypdf
                reader = pypdf.PdfReader(io.BytesIO(data))
                for idx, page in enumerate(reader.pages):
                    text = page.extract_text() or ""
                    pages_text.append(f"--- Page {idx + 1} ---\n{text}")
            except Exception:
                # Basic stream text regex fallback for minimal PDFs
                stream_pattern = re.compile(rb"BT\s+(.*?)\s+ET", re.DOTALL)
                text_chunks = []
                for match in stream_pattern.finditer(data):
                    chunk = match.group(1).decode("latin-1", errors="ignore")
                    text_chunks.append(chunk)
                pages_text.append("\n".join(text_chunks))

        combined_text = "\n\n".join(pages_text)
        metadata = {
            "page_count": len(pages_text),
            "table_count": len(tables),
            "char_count": len(combined_text),
        }

        return combined_text, tables, metadata
