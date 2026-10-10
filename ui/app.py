"""
Streamlit Intelligence Dashboard for Provenance Engine.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv

# Ensure root package import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load local environment
load_dotenv()

from provenance_engine.graph.graph import compiled_graph
from provenance_engine.graph.state import MasterResearchState
from provenance_engine.intake.render import render_safe_markdown
from provenance_engine.exec.export import PDFExporter

st.set_page_config(
    page_title="Provenance Intelligence Engine",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Provenance: Deep Research & OSINT Engine")
st.caption("Autonomous, evidence-grounded research pipeline with calibrated confidence and zero hallucinated citations.")

# --- SIDEBAR CONFIGURATION ---
with st.sidebar:
    st.header("⚙️ Investigation Parameters")
    query = st.text_input("Investigation Target / Topic", placeholder="e.g. Gallium Nitride power semiconductors")
    auto_approve = st.checkbox("Auto-Approve Discovered Sources", value=False, help="Bypasses the human source review checkpoint.")
    
    st.markdown("---")
    st.markdown("### 🔒 Security Status")
    st.success("SSRF Fortress: Active")
    st.success("Taint Tracking: Enabled")
    st.success("Dual-Tier LLM: Flash / Pro 3.1 High")
    
    run_btn = st.button("🚀 Start Investigation", type="primary", use_container_width=True)

# --- SESSION STATE INITIALIZATION ---
if "state" not in st.session_state:
    st.session_state.state = None
if "thread_config" not in st.session_state:
    st.session_state.thread_config = None
if "checkpoint_reached" not in st.session_state:
    st.session_state.checkpoint_reached = False


async def execute_graph_step(initial_state, thread_config):
    """Streams graph execution until completion or checkpoint."""
    events = []
    async for event in compiled_graph.astream(initial_state, config=thread_config):
        events.append(event)
    return events


# --- MAIN WORKFLOW TRIGGER ---
if run_btn and query:
    st.session_state.checkpoint_reached = False
    thread_id = f"ui-session-{abs(hash(query))}"
    st.session_state.thread_config = {"configurable": {"thread_id": thread_id}}
    
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

    with st.status("Executing investigation pipeline...", expanded=True) as status:
        st.write("🔍 Generating dorks & searching multi-silos...")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        events = loop.run_until_complete(execute_graph_step(initial_state, st.session_state.thread_config))
        status.update(label="Pipeline reached checkpoint or finished!", state="complete")

    st.session_state.state = compiled_graph.get_state(st.session_state.thread_config).values


# --- HUMAN REVIEW CHECKPOINT (INTERRUPT) ---
if st.session_state.state and not auto_approve and not st.session_state.checkpoint_reached:
    current_state = st.session_state.state
    if not current_state.get("final_report"):
        st.warning("⚠️ **Human Review Checkpoint**: Review discovered candidates before proceeding to synthesis.")
        discovered = current_state.get("discovered_urls", [])
        
        if discovered:
            for idx, item in enumerate(discovered, 1):
                st.markdown(f"**[{idx}] {item.get('title', 'Unknown')}**  \n🔗 `{item.get('url', '')}`")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Approve Sources & Synthesize", use_container_width=True):
                compiled_graph.update_state(
                    st.session_state.thread_config,
                    {"human_approved": True},
                    as_node="human_review"
                )
                with st.spinner("Synthesizing report & validating claims via Pro 3.1 High Thinking..."):
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(execute_graph_step(None, st.session_state.thread_config))
                st.session_state.checkpoint_reached = True
                st.session_state.state = compiled_graph.get_state(st.session_state.thread_config).values
                st.rerun()
        with col2:
            if st.button("🛑 Abort", use_container_width=True):
                st.error("Investigation halted by operator.")


# --- FINAL DOSSIER DISPLAY ---
if st.session_state.state and st.session_state.state.get("final_report"):
    state = st.session_state.state
    st.success("🎯 **Investigation Complete: Validated Dossier Generated**")

    # --- AUTO-PERSIST TO DISK (HOST MOUNT) ---
    default_output = "/app/output" if Path("/app/output").exists() else "output"
    output_dir = Path(os.getenv("OUTPUT_DIR", default_output))
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        safe_report = render_safe_markdown(state.get("final_report", ""))
        bibtex_content = state.get("bibtex_file", "")
        ledger_content = state.get("audit_table", "")

        (output_dir / "report.md").write_text(safe_report, encoding="utf-8")
        (output_dir / "references.bib").write_text(bibtex_content, encoding="utf-8")
        (output_dir / "audit_ledger.md").write_text(ledger_content, encoding="utf-8")
        st.info(f"💾 Files auto-saved to disk at `{output_dir.resolve()}`")
        
        # Determine if we have pandoc available and attempt PDF compilation
        import shutil
        if shutil.which("pandoc"):
            with st.spinner("Compiling publication-grade PDF..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                pdf_success = loop.run_until_complete(
                    PDFExporter.compile_to_pdf(
                        output_dir / "report.md",
                        output_dir / "references.bib",
                        output_dir / "report.pdf"
                    )
                )
                if pdf_success:
                    st.success("📄 PDF successfully compiled!")
                else:
                    st.warning("⚠️ PDF compilation failed (check container logs).")

    except Exception as e:
        st.error(f"Failed to auto-save files to {output_dir}: {e}")

    tab1, tab2, tab3 = st.tabs(["📄 Research Dossier", "🛡️ Fact-Checking Ledger", "📚 BibTeX Citations"])

    with tab1:
        safe_report = render_safe_markdown(state.get("final_report", ""))
        st.markdown(safe_report)
        st.download_button(
            label="📥 Download report.md",
            data=safe_report,
            file_name="report.md",
            mime="text/markdown"
        )

    with tab2:
        ledger = state.get("audit_table", "No verification table generated.")
        st.markdown(ledger)
        st.download_button(
            label="📥 Download audit_ledger.md",
            data=ledger,
            file_name="audit_ledger.md",
            mime="text/markdown"
        )

    with tab3:
        bibtex = state.get("bibtex_file", "")
        st.code(bibtex, language="bibtex")
        st.download_button(
            label="📥 Download references.bib",
            data=bibtex,
            file_name="references.bib",
            mime="text/plain"
        )
