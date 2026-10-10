"""
ContentRouter: Deterministic Magic-Byte Sniffer and File Type Dispatcher
Identifies true payload types regardless of deceptive extensions or headers.
"""

from enum import Enum
import io
import zipfile
from typing import Tuple


class FileType(str, Enum):
    PDF = "pdf"
    DOCX = "docx"
    PPTX = "pptx"
    XLSX = "xlsx"
    ZIP = "zip"
    XML = "xml"
    HTML = "html"
    CSV = "csv"
    JSON = "json"
    TEXT = "text"
    IMAGE = "image"
    UNKNOWN = "unknown"


class ContentRouter:
    """Sniffs raw binary bytes to deterministically classify file types."""

    @classmethod
    def sniff(cls, data: bytes) -> FileType:
        if not data:
            return FileType.UNKNOWN

        header = data[:2048]

        # 1. PDF Signature (%PDF-)
        if header.startswith(b"%PDF-"):
            return FileType.PDF

        # 2. Image Signatures
        if header.startswith(b"\x89PNG\r\n\x1a\n") or header.startswith(b"\xff\xd8\xff") or header.startswith(b"GIF8"):
            return FileType.IMAGE

        # 3. ZIP / Office OpenXML Signatures (PK\x03\x04)
        if header.startswith(b"PK\x03\x04"):
            return cls._inspect_zip_type(data)

        # 4. XML / HTML inspection
        stripped_sample = header.strip()
        lower_sample = stripped_sample.lower()

        if lower_sample.startswith(b"<!doctype html") or b"<html" in lower_sample or b"<head" in lower_sample or b"<body" in lower_sample:
            return FileType.HTML

        if lower_sample.startswith(b"<?xml") or (lower_sample.startswith(b"<") and b"</" in lower_sample and not b"<html" in lower_sample):
            return FileType.XML

        # 5. JSON inspection
        if (stripped_sample.startswith(b"{") and stripped_sample.endswith(b"}")) or (
            stripped_sample.startswith(b"[") and stripped_sample.endswith(b"]")
        ):
            return FileType.JSON

        # 6. CSV or Plain Text check
        try:
            sample_text = header.decode("utf-8", errors="ignore")
            lines = [l for l in sample_text.splitlines() if l.strip()]
            if len(lines) >= 2 and all("," in l or "\t" in l for l in lines[:5]):
                return FileType.CSV
            return FileType.TEXT
        except Exception:
            return FileType.UNKNOWN

    @classmethod
    def _inspect_zip_type(cls, data: bytes) -> FileType:
        """Inspects internal zip manifest safely without full extraction."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                namelist = set(zf.namelist())
                if any("word/document.xml" in name for name in namelist):
                    return FileType.DOCX
                if any("ppt/presentation.xml" in name for name in namelist):
                    return FileType.PPTX
                if any("xl/workbook.xml" in name for name in namelist):
                    return FileType.XLSX
                return FileType.ZIP
        except Exception:
            return FileType.ZIP
