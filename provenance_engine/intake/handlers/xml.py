"""
XMLHandler: Safe XML Extraction Powered by defusedxml
Defends against XML External Entity (XXE) and recursive entity expansion attacks.
"""

from typing import Dict, Any, Tuple
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException
from loguru import logger


class XMLSecurityError(Exception):
    """Raised when malicious XML patterns (XXE or expansion bombs) are detected."""
    pass


class XMLHandler:
    @classmethod
    def parse_safely(cls, data: bytes | str) -> Tuple[str, Dict[str, Any]]:
        if isinstance(data, str):
            xml_bytes = data.encode("utf-8")
        else:
            xml_bytes = data

        try:
            root = ET.fromstring(xml_bytes)
        except DefusedXmlException as e:
            raise XMLSecurityError(f"XML Security Violation (XXE / Entity Bomb blocked): {e}")
        except Exception as e:
            raise XMLSecurityError(f"Failed to parse XML safely: {e}")

        # Collect text from all nodes
        text_nodes = []
        for elem in root.iter():
            if elem.text and elem.text.strip():
                text_nodes.append(f"{elem.tag}: {elem.text.strip()}")

        full_text = "\n".join(text_nodes)
        metadata = {
            "root_tag": root.tag,
            "node_count": len(list(root.iter())),
            "char_count": len(full_text),
        }

        return full_text, metadata
