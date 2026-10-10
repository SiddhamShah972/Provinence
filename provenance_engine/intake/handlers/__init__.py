"""
Format-Specific Document Handlers
"""

from provenance_engine.intake.handlers.html import HTMLHandler
from provenance_engine.intake.handlers.pdf import PDFHandler
from provenance_engine.intake.handlers.csv_xlsx import TabularHandler
from provenance_engine.intake.handlers.docx_pptx import OfficeHandler
from provenance_engine.intake.handlers.xml import XMLHandler

__all__ = [
    "HTMLHandler",
    "PDFHandler",
    "TabularHandler",
    "OfficeHandler",
    "XMLHandler",
]
