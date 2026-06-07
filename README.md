# ThreatScope -- Cybersecurity Threat Intelligence RAG Pipeline

RAG-powered threat intelligence assistant. Indexes real MITRE ATT&CK techniques, CISA Known Exploited Vulnerabilities, and custom threat reports into a hybrid search engine, then uses an LLM to answer analyst questions grounded in that data.

Built because every "RAG tutorial" project indexes a PDF and calls it done. This one indexes 1,800+ real threat intelligence documents, combines keyword and semantic search, extracts IOCs from raw text, and logs every query for observability.

## What It Does

**Hybrid Retrieval** -- BM25 keyword search + ChromaDB dense vector search, combined via Reciprocal Rank Fusion. Security data is full of exact identifiers (CVE-2024-3400, T1059.001, APT29) that pure semantic search misses. BM25 catches those. Vector search handles fuzzy conceptual queries. Both results are fused into a single ranking.

**Real Data, Not Toy Data** -- Auto-downloads the full MITRE ATT&CK Enterprise knowledge base (~700 techniques) and the CISA KEV catalog (~1,100 exploited vulnerabilities) on first run. Also ingests any custom threat reports you drop in `data/threat_reports/`. Every chunk is tagged with structured metadata at ingestion time.

**Metadata-Filtered Search** -- Chunks are tagged with source_type, technique_id, tactic, platform, vendor, cve_id. Analysts can scope searches to specific data sources ("only MITRE ATT&CK" or "only CISA KEV entries for Microsoft") without changing the query.

**IOC Extraction** -- Regex-based extraction of IPv4/IPv6 addresses, domains, URLs, MD5/SHA1/SHA256 hashes, CVE IDs, email addresses, and MITRE technique IDs from any pasted text. Handles defanged IOCs (`192[.]168[.]1[.]1`, `hxxps://`).

**Multi-Provider LLM** -- Groq (free tier, default), OpenAI, and Ollama (local). Switch with a single environment variable. Groq makes this runnable by anyone with no credit card.

**Evaluation Pipeline** -- 10 curated test cases measuring retrieval precision, answer relevance, and technique ID matching. Run `python evaluate.py` to benchmark.

**Observability** -- Every query logged to JSONL with timestamp, model, retrieval latency, source count, IOCs found. Dashboard tab displays index stats and query history.

## Architecture

```
                   ┌─────────────────────────────────────┐
                   │          Data Ingestion              │
                   │  MITRE ATT&CK │ CISA KEV │ Reports  │
                   └────────┬──────┴────┬─────┴────┬─────┘
                            │           │          │
                            ▼           ▼          ▼
                   ┌─────────────────────────────────────┐
                   │   Chunking + Metadata Tagging        │
                   │   source_type · technique_id · cve   │
                   │   vendor · tactic · platform          │
                   └────────┬────────────────────┬────────┘
                            │                    │
                   ┌────────▼────────┐  ┌───────▼─────────┐
                   │   ChromaDB      │  │   BM25 Index     │
                   │ (Dense Vector)  │  │ (Sparse Keyword) │
                   └────────┬────────┘  └───────┬─────────┘
                            │                    │
                            ▼                    ▼
                   ┌─────────────────────────────────────┐
                   │   Reciprocal Rank Fusion (RRF)       │
                   │   Hybrid ranking + metadata filters   │
                   └────────────────┬────────────────────┘
                                    │
           User Query ──► IOC Extraction ──► Prompt Construction
                                    │
                                    ▼
                   ┌─────────────────────────────────────┐
                   │          LLM Generation              │
                   │   Groq (free) │ OpenAI │ Ollama      │
                   └────────────────┬────────────────────┘
                                    │
                                    ▼
                        Answer + Sources + IOCs
                                    │
                             Query Log (JSONL)
```

## Quick Start

```bash
git clone https://github.com/tejalgoyal2/threatscope.git
cd threatscope
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Get a free Groq API key at [console.groq.com](https://console.groq.com) (takes 30 seconds, no credit card):

```bash
cp .env.example .env
# Edit .env → paste your GROQ_API_KEY
```

Run:

```bash
streamlit run app.py
```

First run downloads MITRE ATT&CK (~15MB) and CISA KEV (~2MB), chunks everything, and builds the vectorstore. Takes 2-5 minutes once. Subsequent runs load in seconds.

Evaluate:

```bash
python evaluate.py
```

## Tech Stack

- **Retrieval**: LangChain + ChromaDB (dense) + rank-bm25 (sparse), fused via RRF
- **Embeddings**: HuggingFace `all-MiniLM-L6-v2` (local, no API key)
- **LLM**: Groq free tier (default) / OpenAI / Ollama
- **Data**: MITRE ATT&CK STIX, CISA KEV JSON, custom reports (TXT/PDF)
- **UI**: Streamlit
- **Evaluation**: Custom precision/relevance/technique-match metrics

## Structure

```
threatscope/
├── app.py                  # Streamlit UI (Query, Analyze, Dashboard tabs)
├── rag_engine.py           # Hybrid retrieval engine, query pipeline, logging
├── ingest.py               # Data download + parsing (MITRE, CISA KEV, reports)
├── ioc_extractor.py        # IOC extraction from raw text
├── evaluate.py             # Evaluation pipeline with 10 curated test cases
├── config.py               # All configuration (LLM, embeddings, paths, params)
├── requirements.txt
├── .env.example
├── data/
│   ├── mitre/              # MITRE ATT&CK STIX data (auto-downloaded)
│   ├── cisa_kev/           # CISA KEV catalog (auto-downloaded)
│   └── threat_reports/     # Custom reports — add your own here
│       ├── apt29_campaign_2024.txt    # Synthetic APT29 spear-phishing report
│       └── lockbit_ir_report_2024.txt # Synthetic LockBit IR timeline
├── vectorstore/            # ChromaDB persistent storage (auto-generated)
├── eval/                   # Evaluation results (auto-generated)
└── query_log.jsonl         # Query observability log (auto-generated)
```

## Indexed Data

| Source | Documents | What's In It |
|---|---|---|
| MITRE ATT&CK | ~700 techniques | IDs, descriptions, tactics, platforms, kill chain phases |
| CISA KEV | ~1,100 CVEs | CVE IDs, vendors, products, remediation dates, ransomware flags |
| Sample Reports | 2 synthetic | APT29 campaign TIR + LockBit ransomware IR report |

## Design Decisions

| Decision | Why |
|---|---|
| BM25 + vector hybrid | Security identifiers (CVE-2024-3400, T1059) are exact strings. Vector search alone misses them. BM25 catches exact matches; vector catches conceptual similarity. |
| Reciprocal Rank Fusion | Combines both rankers without needing to normalize their score distributions. Standard approach from IR research. |
| Groq free tier as default | Fast inference, no credit card, generous limits. Anyone can clone and run this. Swap to OpenAI or Ollama with one env var. |
| HuggingFace embeddings (local) | No API key for embeddings. all-MiniLM-L6-v2 runs on CPU in ~200ms. Good enough for this corpus size. |
| Metadata tagging at ingestion | Enables scoped search. An analyst filtering to "only MITRE" doesn't need to change their query — just select a filter. |
| JSONL query logging | Append-only, no database dependency, easy to analyze with pandas. Demonstrates production observability thinking. |
| ChromaDB over Pinecone | Free, local, zero config. Swap to Pinecone for production with ~5 lines. |

## Data Sources

- **MITRE ATT&CK**: Public domain. Sourced from [github.com/mitre/cti](https://github.com/mitre/cti) (STIX format, Enterprise matrix).
- **CISA KEV**: Public domain. Sourced from [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **Sample threat reports**: 100% synthetic. No real organizational data, production logs, or confidential IOCs. Safe for public release.

## Known Issues

- BM25 tokenization is naive (`.split()`) — no stopword removal or stemming. Works fine for security identifiers but could be improved for natural language queries.
- `_rebuild_bm25_from_chroma` accesses ChromaDB's private `_collection` API. May break on major ChromaDB version bumps.
- Evaluation metrics are custom, not RAGAS. RAGAS integration is a planned addition.
- No streaming support — full response is generated before display.

## Future Work

- [ ] RAGAS integration for standardized evaluation
- [ ] Streaming LLM responses in Streamlit
- [ ] NVD API integration for real-time CVE lookup
- [ ] Hybrid search weight tuning via evaluation feedback loop
- [ ] Docker compose for one-command setup
- [ ] Export IOC extraction results as STIX/OpenIOC

---

Built by [Tejal Goyal](https://tgoyal.me) | Cybersecurity Analyst & ML Engineer
