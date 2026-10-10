"""
PDF Compilation Exporter
Uses SafeExec to invoke Pandoc with XeLaTeX to compile Markdown and BibTeX into publication-ready PDF dossiers.
"""
import os
import asyncio
from pathlib import Path
from loguru import logger

from provenance_engine.exec.safe_exec import SafeExec, CommandExecutionError


class PDFExporter:
    @classmethod
    async def compile_to_pdf(
        cls,
        report_md_path: str | Path,
        bibtex_path: str | Path,
        output_pdf_path: str | Path,
    ) -> bool:
        """
        Compiles the Markdown report and BibTeX catalog into a PDF.
        Returns True if successful.
        """
        report_path = Path(report_md_path).resolve()
        bib_path = Path(bibtex_path).resolve()
        out_path = Path(output_pdf_path).resolve()

        if not report_path.exists():
            logger.error(f"Cannot compile PDF: Report missing at {report_path}")
            return False
        
        args = [
            str(report_path),
            "--pdf-engine=xelatex",
            "--sandbox",
            "-V", "geometry:margin=1in",
            "-V", "colorlinks=true",
        ]

        if bib_path.exists():
            args.extend(["--citeproc", f"--bibliography={str(bib_path)}"])
        else:
            logger.warning(f"BibTeX catalog missing at {bib_path}; compiling without bibliography.")

        args.extend(["-o", str(out_path)])

        try:
            logger.info(f"Compiling PDF via Pandoc: {out_path.name}...")
            # We must be careful because pandoc will write to output_pdf_path.
            # safe_exec.py run allows overriding timeout.
            return_code, stdout, stderr = await SafeExec.run(
                binary="pandoc",
                args=args,
                timeout=120.0,  # LaTeX compilation can take a while on first run
                cwd=str(report_path.parent)
            )

            if return_code == 0 and out_path.exists():
                logger.success(f"PDF successfully compiled: {out_path}")
                return True
            else:
                logger.error(f"Pandoc failed with code {return_code}. Stderr: {stderr}")
                return False

        except CommandExecutionError as e:
            logger.error(f"Pandoc compilation execution error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error compiling PDF: {e}")
            return False
