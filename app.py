import os
import json
import streamlit as st
import pandas as pd
from datetime import datetime

from rag_engine import ThreatRAGEngine
from ioc_extractor import extract_iocs, format_iocs_for_display, ioc_summary


# ==============================================================================
# Page Config
# ==============================================================================
st.set_page_config(
    page_title="ThreatScope",
    page_icon="🔍",
    layout="wide",
)

# ==============================================================================
# Cached RAG Engine
# ==============================================================================
@st.cache_resource
def get_engine():
    engine = ThreatRAGEngine()
    engine.build_index()
    return engine


# ==============================================================================
# Sidebar
# ==============================================================================
st.sidebar.title("ThreatScope")
st.sidebar.caption("AI-Powered Threat Intelligence RAG")

if st.sidebar.button("Rebuild Index (Re-download Data)"):
    engine = get_engine()
    engine.build_index(force_rebuild=True)
    st.sidebar.success("Index rebuilt successfully!")

# Metadata filter options
st.sidebar.markdown("---")
st.sidebar.markdown("**Search Filters**")
source_filter = st.sidebar.selectbox(
    "Filter by source:",
    ["All Sources", "MITRE ATT&CK", "CISA KEV", "Threat Reports"],
)

FILTER_MAP = {
    "All Sources": None,
    "MITRE ATT&CK": {"source_type": "mitre_attack"},
    "CISA KEV": {"source_type": "cisa_kev"},
    "Threat Reports": {"source_type": "threat_report"},
}

# ==============================================================================
# Main Tabs
# ==============================================================================
tab_query, tab_analyze, tab_dashboard = st.tabs(
    ["Query Intelligence", "Analyze Report", "Dashboard"]
)

engine = get_engine()

# ==============================================================================
# Tab 1: Query Intelligence
# ==============================================================================
with tab_query:
    st.header("Query Threat Intelligence")
    st.caption(
        "Ask questions about MITRE ATT&CK techniques, CVEs, threat actors, and more."
    )

    # Example queries
    with st.expander("Example queries"):
        examples = [
            "What techniques does APT29 use for initial access?",
            "Explain T1059 Command and Scripting Interpreter",
            "What are the latest CVEs affecting Microsoft Exchange?",
            "How does credential dumping work and how do I detect it?",
            "What vulnerabilities have been used in ransomware campaigns?",
            "What is lateral movement and what MITRE techniques cover it?",
        ]
        for ex in examples:
            if st.button(ex, key=f"ex_{ex[:30]}"):
                st.session_state["query_input"] = ex

    # Query input
    query = st.text_area(
        "Enter your query:",
        value=st.session_state.get("query_input", ""),
        height=100,
        placeholder="e.g., What MITRE techniques are used for privilege escalation on Windows?",
    )

    col1, col2 = st.columns([1, 4])
    with col1:
        search_btn = st.button("Search", type="primary")

    if search_btn and query.strip():
        filters = FILTER_MAP.get(source_filter)

        with st.spinner("Searching threat intelligence..."):
            result = engine.query(query.strip(), filters=filters)

        # Display answer
        st.markdown("### Answer")
        st.markdown(result["answer"])

        # Display sources
        if result["sources"]:
            with st.expander(f"Sources ({len(result['sources'])} retrieved)"):
                for i, src in enumerate(result["sources"], 1):
                    source_type = src.get("source_type", "unknown")
                    score = src.get("relevance_score", 0)

                    label = f"**[{i}] {source_type}**"
                    if src.get("technique_id"):
                        label += f" | {src['technique_id']} - {src.get('technique_name', '')}"
                    if src.get("cve_id"):
                        label += f" | {src['cve_id']}"
                    if src.get("filename"):
                        label += f" | {src['filename']}"

                    st.markdown(f"{label} (score: {score})")

        # Display IOCs if found in query
        if result["iocs"]:
            with st.expander("IOCs detected in query"):
                st.code(format_iocs_for_display(result["iocs"]))

        # Metadata
        st.caption(
            f"Model: {result['model']} | "
            f"Retrieval: {result['retrieval_time']}s | "
            f"Filter: {source_filter}"
        )


# ==============================================================================
# Tab 2: Analyze Report
# ==============================================================================
with tab_analyze:
    st.header("Analyze Threat Report")
    st.caption("Paste or upload a threat report for IOC extraction and AI analysis.")

    input_method = st.radio(
        "Input method:", ["Paste text", "Upload file"], horizontal=True
    )

    report_text = ""

    if input_method == "Paste text":
        report_text = st.text_area(
            "Paste threat report or log data:",
            height=300,
            placeholder=(
                "Paste a threat advisory, incident report, or raw logs here.\n\n"
                "Example:\n"
                "On 2024-03-15, we observed the threat actor APT28 leveraging "
                "CVE-2024-3400 to gain initial access to Palo Alto Networks "
                "GlobalProtect appliances. The C2 callback was observed to "
                "45.77.123.42 over port 443. The malware hash "
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 was identified..."
            ),
        )
    else:
        uploaded = st.file_uploader(
            "Upload a TXT, LOG, or PDF file", type=["txt", "log", "pdf"]
        )
        if uploaded:
            if uploaded.name.lower().endswith(".pdf"):
                try:
                    from PyPDF2 import PdfReader
                    reader = PdfReader(uploaded)
                    report_text = "\n".join(
                        page.extract_text() for page in reader.pages
                        if page.extract_text()
                    )
                except Exception as e:
                    st.error(f"Error reading PDF: {e}")
            else:
                report_text = uploaded.read().decode("utf-8", errors="ignore")

    if report_text:
        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("### Extracted IOCs")
            iocs = extract_iocs(report_text)
            if iocs:
                st.code(format_iocs_for_display(iocs))
                st.caption(ioc_summary(iocs))
            else:
                st.info("No IOCs detected in the input text.")

        with col_b:
            if st.button("Run AI Analysis", type="primary"):
                with st.spinner("Analyzing with RAG engine..."):
                    # Truncate very long reports
                    truncated = report_text[:4000]
                    analysis_query = (
                        f"Analyze this threat report. Identify the threat actor, "
                        f"TTPs, affected systems, and recommended mitigations:\n\n"
                        f"{truncated}"
                    )
                    result = engine.query(analysis_query)

                st.markdown("### AI Analysis")
                st.markdown(result["answer"])

                if result["sources"]:
                    with st.expander("Referenced intelligence"):
                        for src in result["sources"]:
                            parts = [src.get("source_type", "")]
                            if src.get("technique_id"):
                                parts.append(src["technique_id"])
                            if src.get("cve_id"):
                                parts.append(src["cve_id"])
                            st.markdown(f"- {' | '.join(parts)}")


# ==============================================================================
# Tab 3: Dashboard (Observability)
# ==============================================================================
with tab_dashboard:
    st.header("ThreatScope Dashboard")

    # Index stats
    stats = engine.get_index_stats()

    col_m1, col_m2, col_m3 = st.columns(3)
    col_m1.metric("Total Documents Indexed", stats.get("total_documents", 0))
    col_m2.metric("MITRE Techniques", stats.get("by_source", {}).get("mitre_attack", 0))
    col_m3.metric("CISA KEV Entries", stats.get("by_source", {}).get("cisa_kev", 0))

    # Tactic distribution
    if stats.get("top_tactics"):
        st.markdown("### MITRE ATT&CK Tactic Distribution")
        tactic_df = pd.DataFrame(
            list(stats["top_tactics"].items()),
            columns=["Tactic", "Count"],
        ).sort_values("Count", ascending=True)
        st.bar_chart(tactic_df.set_index("Tactic"))

    # Top vendors from CISA KEV
    if stats.get("top_vendors"):
        st.markdown("### Top Vendors in CISA KEV")
        vendor_df = pd.DataFrame(
            list(stats["top_vendors"].items()),
            columns=["Vendor", "Count"],
        ).sort_values("Count", ascending=True)
        st.bar_chart(vendor_df.set_index("Vendor"))

    # Query logs
    st.markdown("### Recent Query Log")
    logs = engine.get_query_logs(20)
    if logs:
        log_df = pd.DataFrame(logs)
        display_cols = [
            "timestamp", "query", "model", "retrieval_time_sec",
            "num_sources", "answer_length"
        ]
        available_cols = [c for c in display_cols if c in log_df.columns]
        st.dataframe(log_df[available_cols], use_container_width=True)
    else:
        st.info("No queries logged yet. Start searching to populate this log.")
