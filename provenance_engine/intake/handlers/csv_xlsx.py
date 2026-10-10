"""
TabularHandler: CSV and Excel Parser with DDE Formula Injection Mitigation
Uses openpyxl with data_only=True and detaches/neutralizes leading formula command triggers.
"""

import io
import csv
from typing import List, Dict, Any, Tuple
from loguru import logger
import openpyxl


class TabularHandler:
    DANGEROUS_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "%")

    @classmethod
    def sanitize_cell_value(cls, val: Any) -> Tuple[str, bool]:
        """Neutralizes DDE / Formula injection in spreadsheet cells."""
        if val is None:
            return "", False

        s = str(val).strip()
        if not s:
            return "", False

        if s.startswith(cls.DANGEROUS_FORMULA_PREFIXES):
            # Neutralize formula trigger by prefixing with single-quote and removing executable trigger
            safe_val = "'" + s.lstrip("=+-\t\r%@")
            return safe_val, True

        return s, False

    @classmethod
    def parse_csv(cls, data: bytes | str) -> Tuple[List[str], List[List[str]], int]:
        """Parses CSV with formula sanitization. Returns (headers, rows, neutralized_count)."""
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = data

        reader = csv.reader(io.StringIO(text))
        all_rows = list(reader)

        if not all_rows:
            return [], [], 0

        neutralized = 0
        cleaned_rows: List[List[str]] = []

        for row in all_rows:
            cleaned_row = []
            for cell in row:
                sanitized_val, was_threat = cls.sanitize_cell_value(cell)
                if was_threat:
                    neutralized += 1
                cleaned_row.append(sanitized_val)
            cleaned_rows.append(cleaned_row)

        headers = cleaned_rows[0] if cleaned_rows else []
        rows = cleaned_rows[1:] if len(cleaned_rows) > 1 else []
        return headers, rows, neutralized

    @classmethod
    def parse_xlsx(cls, data: bytes) -> Tuple[List[str], List[List[str]], int]:
        """Parses XLSX using data_only=True to prevent evaluating formulas."""
        wb = openpyxl.load_workbook(io.BytesIO(data), data_only=True, read_only=True)
        sheet = wb.active

        if sheet is None:
            return [], [], 0

        all_rows = []
        neutralized = 0

        for row in sheet.iter_rows(values_only=True):
            cleaned_row = []
            for cell in row:
                sanitized_val, was_threat = cls.sanitize_cell_value(cell)
                if was_threat:
                    neutralized += 1
                cleaned_row.append(sanitized_val)
            all_rows.append(cleaned_row)

        wb.close()

        if not all_rows:
            return [], [], 0

        headers = all_rows[0]
        rows = all_rows[1:]
        return headers, rows, neutralized
