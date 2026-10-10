"""
CLI entry point for executing live investigations using the Provenance Engine.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure local package import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from provenance_engine.graph.graph import compiled_graph
from provenance_engine.graph.state import MasterResearchState
from provenance_engine.intake.render import render_safe_markdown


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an autonomous, end-to-end deep research investigation."
    )
    parser.add_argument(
        "-q", "--query",
        type=str,
        required=True,
        help="Target topic, entity, or domain to investigate."
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="output",
        help="Directory to save generated dossiers and bibliographies."
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Bypass human review checkpoint and approve all discovered links."
    )
    return parser.parse_args()


async def run_investigation(query: str, output_dir: str, auto_approve: bool) -> None:
    load_dotenv()

    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GOOGLE_API_KEY is not set. Export it in your shell or .env file.")
        sys.exit(1)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

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
        "human_approved": auto_approve,
        "human_feedback": None,
        "draft_report": "",
        "bibtex_file": "",
        "hallucination_detected": False,
        "hallucination_count": 0,
        "audit_table": "",
        "final_report": ""
    }

    thread_config = {"configurable": {"thread_id": f"investigation-{abs(hash(query))}"}}

    print(f"\n[Provenance] Initiating investigation on: '{query}'")
    print(f"[Provenance] Output directory set to: '{out_path.resolve()}'\n")

    # Stream graph execution
    async for event in compiled_graph.astream(initial_state, config=thread_config):
        for node_name, node_output in event.items():
            print(f"--> [Node Completed: {node_name}]")

            # Checkpoint: Handle Human Review
            if node_name == "human_review" and not auto_approve:
                discovered = node_output.get("discovered_urls", [])
                print("\n" + "=" * 60)
                print(f"HUMAN REVIEW CHECKPOINT: Discovered {len(discovered)} Source Candidates")
                print("=" * 60)
                for idx, item in enumerate(discovered, 1):
                    print(f"  [{idx}] {item.get('title', 'Unknown Title')}")
                    print(f"      URL: {item.get('url', '')}")

                choice = input("\nApprove sources and continue to synthesis? (Y/n): ").strip().lower()
                approval = choice in ("y", "yes", "")

                # Resume graph with operator decision
                compiled_graph.update_state(
                    thread_config,
                    {"human_approved": approval},
                    as_node="human_review"
                )
                if approval:
                    async for cont_event in compiled_graph.astream(None, config=thread_config):
                        for c_node, _ in cont_event.items():
                            if c_node != "__interrupt__":
                                print(f"--> [Node Completed: {c_node}]")

    # Fetch final state from checkpoint
    final_state = compiled_graph.get_state(thread_config).values
    final_report = final_state.get("final_report", "")
    bibtex_data = final_state.get("bibtex_file", "")
    audit_ledger = final_state.get("audit_table", "")

    # Save artifacts to disk
    report_file = out_path / "report.md"
    bib_file = out_path / "references.bib"
    ledger_file = out_path / "audit_ledger.md"

    # Render report safely to prevent any injection/exfiltration
    safe_rendered_report = render_safe_markdown(final_report)
    report_file.write_text(safe_rendered_report, encoding="utf-8")
    bib_file.write_text(bibtex_data, encoding="utf-8")
    ledger_file.write_text(audit_ledger, encoding="utf-8")

    # Compile publication-grade PDF if pandoc is available
    import shutil
    from provenance_engine.exec.export import PDFExporter
    pdf_compiled = False
    if shutil.which("pandoc"):
        pdf_file = out_path / "report.pdf"
        print("  [PDF Exporter] Compiling publication-grade PDF via Pandoc/XeLaTeX...")
        pdf_compiled = await PDFExporter.compile_to_pdf(report_file, bib_file, pdf_file)

    print("\n" + "=" * 60)
    print("INVESTIGATION COMPLETED SUCCESSFULLY")
    print("=" * 60)
    print(f"  • Dossier written to:       {report_file.resolve()}")
    print(f"  • BibTeX references saved: {bib_file.resolve()}")
    print(f"  • Audit Ledger saved:      {ledger_file.resolve()}")
    if pdf_compiled:
        print(f"  • PDF Dossier compiled:    {(out_path / 'report.pdf').resolve()}")
    print()


def main() -> None:
    args = parse_arguments()
    try:
        asyncio.run(run_investigation(args.query, args.output_dir, args.auto_approve))
    except KeyboardInterrupt:
        print("\n[Provenance] Investigation interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
