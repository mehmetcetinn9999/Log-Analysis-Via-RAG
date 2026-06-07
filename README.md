# Predictive Log Analysis via RAG

A Retrieval-Augmented Generation (RAG) based cybersecurity assistant designed for intelligent log analysis, threat detection, and predictive security assessment.

---

## Overview

Predictive Log Analysis via RAG combines Large Language Models (LLMs), threat intelligence sources, and hybrid information retrieval techniques to analyze security logs and provide context-aware cybersecurity insights.

The system integrates multiple cybersecurity knowledge sources, including MITRE ATT&CK and CISA Known Exploited Vulnerabilities (KEV), enabling security analysts to investigate suspicious events using evidence-backed responses.

---

## Features

### Hybrid Retrieval

* BM25 keyword retrieval
* ChromaDB vector similarity search
* Reciprocal Rank Fusion (RRF)

### Threat Intelligence Integration

* MITRE ATT&CK Knowledge Base
* CISA KEV Catalog
* Custom Threat Reports

### IOC Extraction

Automatically extracts:

* IPv4 / IPv6 addresses
* Domains
* URLs
* Email addresses
* CVE identifiers
* MITRE ATT&CK Technique IDs
* MD5 / SHA1 / SHA256 hashes

### Predictive Security Assessment

The system not only explains observed security events but also identifies potential future risks and attack patterns based on retrieved threat intelligence.

### Evaluation and Observability

* Retrieval evaluation pipeline
* Query logging
* Latency tracking
* Source attribution

---

## Architecture

```text
Security Logs
      │
      ▼
IOC Extraction
      │
      ▼
Hybrid Retrieval
(BM25 + ChromaDB)
      │
      ▼
Threat Intelligence Context
(MITRE + CISA + Reports)
      │
      ▼
LLM Analysis
      │
      ▼
Threat Detection & Prediction
```

---

## Tech Stack

| Component        | Technology             |
| ---------------- | ---------------------- |
| LLM              | Groq / OpenAI / Ollama |
| Embeddings       | all-MiniLM-L6-v2       |
| Vector Database  | ChromaDB               |
| Sparse Retrieval | BM25                   |
| Framework        | LangChain              |
| Interface        | Streamlit              |
| Evaluation       | Custom Metrics         |

---

## Installation

```bash
git clone <repository-url>
cd project

python -m venv venv

source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
```

Run:

```bash
streamlit run app.py
```

---

## Project Structure

```text
project/
├── app.py
├── rag_engine.py
├── ingest.py
├── ioc_extractor.py
├── evaluate.py
├── config.py
├── data/
├── vectorstore/
├── eval/
└── query_log.jsonl
```

---

## Academic References

1. Lewis et al. (2020) – Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks
2. MITRE ATT&CK Framework
3. CISA Known Exploited Vulnerabilities Catalog
4. Shajarian et al. (2024) – RAG-Enhanced LLMs for Log Analysis, Troubleshooting and Documentation

---

## Use of Generative AI

Generative AI tools were used for:

* Documentation improvement
* Code debugging
* Literature exploration

Core system design, implementation, integration, evaluation, and project development were completed by the project authors.

---

## Authors

Computer Engineering Department

Muğla Sıtkı Koçman University

2025–2026 Spring Semester Project
