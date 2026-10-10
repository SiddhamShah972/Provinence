"""
OfficeHandler: Safe DOCX and PPTX Text Extractor
Guards against zip bombs and parses OpenXML via defusedxml.
"""

import io
import zipfile
from typing import List, Dict, Any, Tuple
import defusedxml.ElementTree as ET
from loguru import logger


class ZipBombSecurityError(Exception):
    """Raised when an archive exceeds safe compression limits."""
    pass


class OfficeHandler:
    MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
    MAX_COMPRESSION_RATIO = 100.0  # 100:1
    MAX_ARCHIVE_ENTRIES = 1000

    @classmethod
    def _verify_archive_safety(cls, zf: zipfile.ZipFile) -> None:
        total_uncompressed = 0
        total_compressed = 0
        entries = zf.infolist()

        if len(entries) > cls.MAX_ARCHIVE_ENTRIES:
            raise ZipBombSecurityError(f"Archive entry count ({len(entries)}) exceeds safety limit.")

        for info in entries:
            total_uncompressed += info.file_size
            total_compressed += info.compress_size

            if total_uncompressed > cls.MAX_UNCOMPRESSED_BYTES:
                raise ZipBombSecurityError(
                    f"Archive uncompressed size ({total_uncompressed} bytes) exceeds {cls.MAX_UNCOMPRESSED_BYTES} bytes."
                )

        if total_compressed > 0:
            ratio = total_uncompressed / total_compressed
            if ratio > cls.MAX_COMPRESSION_RATIO and total_uncompressed > 1024 * 1024:
                raise ZipBombSecurityError(f"Archive compression ratio ({ratio:.1f}:1) exceeds safety ceiling.")

    @classmethod
    def extract_docx(cls, data: bytes) -> Tuple[str, Dict[str, Any]]:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            cls._verify_archive_safety(zf)

            if "word/document.xml" not in zf.namelist():
                return "", {"error": "Missing word/document.xml"}

            xml_bytes = zf.read("word/document.xml")
            root = ET.fromstring(xml_bytes)

            paragraphs = []
            # DOCX namespace: w:t contains text chunks, w:p represents paragraphs
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}

            for p in root.findall(".//w:p", ns):
                texts = [node.text for node in p.findall(".//w:t", ns) if node.text]
                if texts:
                    paragraphs.append("".join(texts))

            full_text = "\n\n".join(paragraphs)
            return full_text, {"paragraphs": len(paragraphs), "char_count": len(full_text)}

    @classmethod
    def extract_pptx(cls, data: bytes) -> Tuple[str, Dict[str, Any]]:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            cls._verify_archive_safety(zf)

            slide_names = sorted(
                [name for name in zf.namelist() if name.startswith("ppt/slides/slide") and name.endswith(".xml")]
            )

            all_slides_text = []
            ns = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main"}

            for idx, slide_name in enumerate(slide_names):
                xml_bytes = zf.read(slide_name)
                root = ET.fromstring(xml_bytes)
                texts = [node.text for node in root.findall(".//a:t", ns) if node.text]
                slide_text = " ".join(texts)
                all_slides_text.append(f"--- Slide {idx + 1} ---\n{slide_text}")

            full_text = "\n\n".join(all_slides_text)
            return full_text, {"slides_count": len(slide_names), "char_count": len(full_text)}
