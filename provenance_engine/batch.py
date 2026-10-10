"""
Batch Orchestration Mode
Processes multiple research targets concurrently or sequentially, managing API
rate limits, backoffs, and isolated dossier generation.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
import csv
from loguru import logger
from dotenv import load_dotenv

# Ensure local package import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from provenance_engine.graph.graph import compiled_graph
from provenance_engine.graph.state import MasterResearchState
from provenance_engine.intake.render import render_safe_markdown

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception,
)
from google.genai.errors import APIError

load_dotenv()

def is_rate_limit_error(exception: Exception) -> bool:
    """Checks if the exception is a 429 Too Many Requests error."""
    if isinstance(exception, APIError):
        # APIError in google-genai usually has a code property or string representation
        return "429" in str(exception)
    return False

import time
import json
from datetime import datetime

@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=10, max=120),
    retry=retry_if_exception(is_rate_limit_error),
    before_sleep=lambda retry_state: logger.warning(
        f"Rate limit hit. Retrying in {retry_state.next_action.sleep}s (Attempt {retry_state.attempt_number}/5)"
    ),
)
async def run_single_investigation(query: str, batch_output_dir: Path) -> dict:
    """Executes the pipeline for a single target with rate-limit backoff."""
    start_time = time.time()
    logger.info(f"Starting batch investigation: '{query}'")
    
    # Strict Path Sanitization: Strip slashes, null bytes, colons, traversal, then enforce alnum/underscore.
    safe_name = "".join([c if c.isalnum() else "_" for c in query.replace("/", "_").replace("\\", "_").replace(":", "_").replace("\0", "_")])[:60]
    safe_name = safe_name.strip("_") or "unknown_query"
    target_dir = batch_output_dir / safe_name
    target_dir.mkdir(parents=True, exist_ok=True)
    
    thread_id = f"batch-session-{abs(hash(query))}"
    thread_config = {"configurable": {"thread_id": thread_id}}
    
    initial_state: MasterResearchState = {
        "topic": query,
        "target_ticker": None,
        "target_identity": None,
        "search_queries": [],
        "dork_queries": [],
        "discovered_urls": [],
        "findings": [],
        "osint_records": [],
        "identity_findings": [],
        "iteration": 0,
        "circuit_broken": False,
        "human_approved": True,  # Batch mode assumes auto-approve
        "human_feedback": None,
        "draft_report": "",
        "bibtex_file": "",
        "hallucination_detected": False,
        "hallucination_count": 0,
        "audit_table": "",
        "final_report": ""
    }

    try:
        # Execute the full graph synchronously from the batch runner perspective
        async for _ in compiled_graph.astream(initial_state, config=thread_config):
            pass  # Streaming events consumed silently in batch mode
            
        final_state = compiled_graph.get_state(thread_config).values
        elapsed = round(time.time() - start_time, 2)
        
        if final_state.get("final_report"):
            safe_report = render_safe_markdown(final_state["final_report"])
            (target_dir / "report.md").write_text(safe_report, encoding="utf-8")
            (target_dir / "references.bib").write_text(final_state.get("bibtex_file", ""), encoding="utf-8")
            (target_dir / "audit_ledger.md").write_text(final_state.get("audit_table", ""), encoding="utf-8")
            
            # Compile to PDF if pandoc is available
            import shutil
            from provenance_engine.exec.export import PDFExporter
            pdf_ok = False
            if shutil.which("pandoc"):
                logger.info(f"Compiling PDF for {query}...")
                pdf_ok = await PDFExporter.compile_to_pdf(
                    target_dir / "report.md",
                    target_dir / "references.bib",
                    target_dir / "report.pdf"
                )
            
            status = "CIRCUIT_BROKEN" if final_state.get("circuit_broken") else "COMPLETED"
            logger.success(f"Successfully completed: '{query}' in {elapsed}s. Saved to {target_dir}")
            return {
                "query": query,
                "status": status,
                "runtime_seconds": elapsed,
                "directory": str(target_dir.name),
                "claims_count": len(final_state.get("findings", [])),
                "hallucinations_detected": final_state.get("hallucination_detected", False),
                "pdf_generated": pdf_ok,
                "error": None
            }
        else:
            status = "CIRCUIT_BROKEN" if final_state.get("circuit_broken") else "FAILED"
            logger.error(f"Investigation completed without generating a final report for: '{query}'")
            return {
                "query": query,
                "status": status,
                "runtime_seconds": elapsed,
                "directory": str(target_dir.name),
                "error": "No final report generated"
            }

    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        logger.error(f"Critical pipeline failure on '{query}': {e}")
        return {
            "query": query,
            "status": "RETRY_EXHAUSTED" if "429" in str(e) else "FAILED",
            "runtime_seconds": elapsed,
            "directory": str(target_dir.name),
            "error": str(e)
        }


async def run_batch(queries: list[str], output_dir: str, concurrency: int = 2):
    """Processes a batch of queries using a semaphore for concurrency control."""
    start_batch = time.time()
    base_out = Path(output_dir)
    base_out.mkdir(parents=True, exist_ok=True)
    
    sem = asyncio.Semaphore(concurrency)
    
    async def bounded_run(q: str):
        async with sem:
            return await run_single_investigation(q, base_out)
            
    tasks = [asyncio.create_task(bounded_run(q)) for q in queries]
    results = await asyncio.gather(*tasks)
    
    total_elapsed = round(time.time() - start_batch, 2)
    completed_count = sum(1 for r in results if r.get("status") == "COMPLETED")
    
    manifest = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_queries": len(queries),
        "completed": completed_count,
        "failed": len(queries) - completed_count,
        "concurrency": concurrency,
        "total_batch_runtime_seconds": total_elapsed,
        "results": results
    }
    
    manifest_path = base_out / "batch_summary.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info(f"Batch execution finished. {completed_count}/{len(queries)} completed. Manifest written to {manifest_path}")


import signal

shutdown_event = asyncio.Event()


def register_signal_handlers():
    """Binds SIGINT and SIGTERM handlers to coordinate graceful batch shutdowns."""
    def _handle_signal(signum, frame):
        try:
            sig_name = signal.Signals(signum).name
        except Exception:
            sig_name = str(signum)
        logger.warning(
            f"Received {sig_name}. Gracefully finishing current in-flight investigations and flushing manifests before exit..."
        )
        shutdown_event.set()

    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                signal.signal(sig, _handle_signal)
            except (ValueError, AttributeError, RuntimeError):
                pass


def prune_stale_artifacts(base_dir: str | Path, max_days: int = 30) -> None:
    """
    Cleans up telemetry files, temporary compiler files, and old artifacts older than max_days
    to enforce deterministic volume retention quotas.
    """
    try:
        cutoff_sec = time.time() - (max_days * 86400)
        target_path = Path(base_dir)
        if not target_path.exists():
            return

        pruned_count = 0
        for item in target_path.rglob("*"):
            if item.is_file():
                # Prune log/tmp files or older snapshots based on modification time
                if item.suffix in (".log", ".tmp", ".jsonl") or "cdx_cache" in str(item):
                    if item.stat().st_mtime < cutoff_sec:
                        try:
                            item.unlink()
                            pruned_count += 1
                        except OSError:
                            pass

        if pruned_count > 0:
            logger.info(f"Retention policy executed: Pruned {pruned_count} files older than {max_days} days.")
    except Exception as e:
        logger.warning(f"Retention cleaner encountered error: {e}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run batch deep research investigations.")
    parser.add_argument("-i", "--input-csv", "--file", type=str, help="CSV or text file containing queries in the first column/line.")
    parser.add_argument("-q", "--queries", type=str, nargs="+", help="Space-separated list of target queries.")
    parser.add_argument("-o", "--output-dir", type=str, default="output/batch", help="Output directory for batch results.")
    parser.add_argument("-c", "--concurrency", type=int, default=2, help="Max concurrent investigations.")
    parser.add_argument("--watch", action="store_true", help="Run batch recurringly on an interval schedule.")
    parser.add_argument("--interval-seconds", type=int, default=3600, help="Interval in seconds between reconnaissance cycles in watch mode.")
    parser.add_argument("--retention-days", type=int, default=30, help="Days to retain historical telemetry and cache before automated pruning.")
    return parser.parse_args()


async def main_async(args, queries):
    register_signal_handlers()

    if args.watch:
        logger.info(f"Starting recurring surveillance mode. Interval: {args.interval_seconds}s (Graceful SIGTERM/SIGINT enabled)")
        iteration = 1
        while not shutdown_event.is_set():
            logger.info(f"--- Watch Reconnaissance Cycle #{iteration} ---")
            await run_batch(queries, args.output_dir, args.concurrency)

            # Apply retention cleaner after every cycle
            if args.retention_days > 0:
                prune_stale_artifacts(args.output_dir, max_days=args.retention_days)

            iteration += 1
            if shutdown_event.is_set():
                break

            logger.info(f"Surveillance cycle sleeping for {args.interval_seconds}s. Send SIGTERM / Ctrl+C to terminate cleanly.")
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=args.interval_seconds)
                break
            except asyncio.TimeoutError:
                pass

        logger.info("Graceful shutdown confirmed. All in-flight manifests flushed.")
    else:
        await run_batch(queries, args.output_dir, args.concurrency)
        if args.retention_days > 0:
            prune_stale_artifacts(args.output_dir, max_days=args.retention_days)


def main():
    args = parse_arguments()
    queries = []
    
    from provenance_engine.audit.log import setup_audit_telemetry
    setup_audit_telemetry(args.output_dir)
    
    if args.queries:
        queries.extend(args.queries)
        
    if args.input_csv:
        csv_path = Path(args.input_csv)
        if csv_path.is_file():
            with open(csv_path, mode="r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and row[0].strip():
                        queries.append(row[0].strip())
        else:
            logger.error(f"CSV file not found: {args.input_csv}")
            sys.exit(1)
            
    if not queries:
        logger.error("No queries provided. Use --input-csv or --queries.")
        sys.exit(1)
        
    if not os.getenv("GOOGLE_API_KEY") and not os.getenv("GEMINI_API_KEY"):
        logger.error("GOOGLE_API_KEY must be set in environment.")
        sys.exit(1)
        
    logger.info(f"Loaded {len(queries)} queries for batch processing. Concurrency limit: {args.concurrency}")
    
    asyncio.run(main_async(args, queries))


if __name__ == "__main__":
    main()
