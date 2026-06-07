"""
ThreatScope Data Ingestion
--------------------------
Downloads and processes real threat intelligence data:
  1. MITRE ATT&CK techniques (from GitHub STIX data)
  2. CISA Known Exploited Vulnerabilities (KEV) catalog
  3. Custom threat report files (TXT/PDF in data/threat_reports/)

Each document is tagged with metadata for filtered retrieval:
  - source_type: "mitre_attack" | "cisa_kev" | "threat_report"
  - technique_id, tactic, platform (for MITRE)
  - cve_id, vendor, severity (for CISA KEV)
  - filename (for custom reports)
"""

import os
import json
import requests
from datetime import datetime

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import TextLoader, PyPDFLoader

import config


# ==============================================================================
# MITRE ATT&CK Ingestion
# ==============================================================================

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def download_mitre_attack():
    """Download MITRE ATT&CK Enterprise STIX bundle."""
    output_path = os.path.join(config.MITRE_DATA_DIR, "enterprise-attack.json")
    if os.path.exists(output_path):
        print(f"[*] MITRE ATT&CK data already exists at {output_path}")
        return output_path

    print("[+] Downloading MITRE ATT&CK Enterprise data...")
    resp = requests.get(MITRE_ATTACK_URL, timeout=120)
    resp.raise_for_status()
    os.makedirs(config.MITRE_DATA_DIR, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(resp.text)
    print(f"[+] Saved to {output_path}")
    return output_path


def parse_mitre_attack(filepath):
    """
    Parse MITRE ATT&CK STIX JSON into LangChain Documents.
    Extracts: techniques, their descriptions, tactics, platforms, mitigations.
    """
    print("[+] Parsing MITRE ATT&CK techniques...")
    with open(filepath, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    documents = []
    technique_count = 0

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract external ID (e.g., T1059)
        ext_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        name = obj.get("name", "Unknown")
        description = obj.get("description", "No description available.")
        platforms = obj.get("x_mitre_platforms", [])
        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
        ]

        # Build a rich text document for this technique
        content = (
            f"MITRE ATT&CK Technique: {technique_id} - {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Platforms: {', '.join(platforms)}\n"
            f"URL: {url}\n\n"
            f"Description:\n{description}"
        )

        metadata = {
            "source_type": "mitre_attack",
            "technique_id": technique_id,
            "technique_name": name,
            "tactics": ", ".join(tactics),
            "platforms": ", ".join(platforms),
            "url": url,
        }

        documents.append(Document(page_content=content, metadata=metadata))
        technique_count += 1

    print(f"[+] Parsed {technique_count} MITRE ATT&CK techniques.")
    return documents


# ==============================================================================
# CISA KEV Ingestion
# ==============================================================================

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def download_cisa_kev():
    """Download CISA Known Exploited Vulnerabilities catalog."""
    output_path = os.path.join(config.CISA_KEV_DIR, "kev.json")
    if os.path.exists(output_path):
        print(f"[*] CISA KEV data already exists at {output_path}")
        return output_path

    print("[+] Downloading CISA KEV catalog...")
    resp = requests.get(CISA_KEV_URL, timeout=60)
    resp.raise_for_status()
    os.makedirs(config.CISA_KEV_DIR, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(resp.text)
    print(f"[+] Saved to {output_path}")
    return output_path


def parse_cisa_kev(filepath):
    """Parse CISA KEV JSON into LangChain Documents."""
    print("[+] Parsing CISA KEV vulnerabilities...")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    documents = []
    vulns = data.get("vulnerabilities", [])

    for vuln in vulns:
        cve_id = vuln.get("cveID", "Unknown")
        vendor = vuln.get("vendorProject", "Unknown")
        product = vuln.get("product", "Unknown")
        name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "No description.")
        date_added = vuln.get("dateAdded", "")
        due_date = vuln.get("dueDate", "")
        action = vuln.get("requiredAction", "")
        known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
        notes = vuln.get("notes", "")

        content = (
            f"CISA Known Exploited Vulnerability: {cve_id}\n"
            f"Vendor: {vendor} | Product: {product}\n"
            f"Vulnerability Name: {name}\n"
            f"Date Added to KEV: {date_added}\n"
            f"Remediation Due Date: {due_date}\n"
            f"Known Ransomware Use: {known_ransomware}\n\n"
            f"Description:\n{description}\n\n"
            f"Required Action:\n{action}\n"
            f"Notes: {notes}"
        )

        metadata = {
            "source_type": "cisa_kev",
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "date_added": date_added,
            "known_ransomware": known_ransomware,
        }

        documents.append(Document(page_content=content, metadata=metadata))

    print(f"[+] Parsed {len(documents)} CISA KEV entries.")
    return documents


# ==============================================================================
# Custom Threat Report Ingestion
# ==============================================================================

def load_threat_reports():
    """Load TXT and PDF files from data/threat_reports/ directory."""
    print("[+] Loading custom threat reports...")
    report_dir = config.THREAT_REPORTS_DIR
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        print("[*] No threat reports found. Add files to data/threat_reports/")
        return []

    documents = []
    for filename in os.listdir(report_dir):
        filepath = os.path.join(report_dir, filename)

        if filename.lower().endswith(".txt") or filename.lower().endswith(".log"):
            loader = TextLoader(filepath, encoding="utf-8")
            docs = loader.load()
        elif filename.lower().endswith(".pdf"):
            loader = PyPDFLoader(filepath)
            docs = loader.load()
        else:
            continue

        # Tag each doc with metadata
        for doc in docs:
            doc.metadata["source_type"] = "threat_report"
            doc.metadata["filename"] = filename

        documents.extend(docs)
        print(f"    Loaded: {filename} ({len(docs)} pages/sections)")

    print(f"[+] Loaded {len(documents)} documents from threat reports.")
    return documents


# ==============================================================================
# Full Ingestion Pipeline
# ==============================================================================

def ingest_all():
    """
    Download, parse, chunk, and return all documents ready for vectorstore.
    Returns a list of LangChain Document objects with metadata.
    """
    all_docs = []

    # 1. MITRE ATT&CK
    try:
        mitre_path = download_mitre_attack()
        mitre_docs = parse_mitre_attack(mitre_path)
        all_docs.extend(mitre_docs)
    except Exception as e:
        print(f"[!] Error ingesting MITRE ATT&CK: {e}")

    # 2. CISA KEV
    try:
        kev_path = download_cisa_kev()
        kev_docs = parse_cisa_kev(kev_path)
        all_docs.extend(kev_docs)
    except Exception as e:
        print(f"[!] Error ingesting CISA KEV: {e}")

    # 3. Custom threat reports
    try:
        report_docs = load_threat_reports()
        all_docs.extend(report_docs)
    except Exception as e:
        print(f"[!] Error loading threat reports: {e}")

    # 4. Chunk all documents
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=config.CHUNK_SIZE,
        chunk_overlap=config.CHUNK_OVERLAP,
        separators=["\n\n", "\n", ". ", " ", ""],
    )

    # For MITRE techniques, keep them whole if under chunk_size
    # (most are ~500-800 chars). Only split longer ones.
    chunked = []
    for doc in all_docs:
        if len(doc.page_content) <= config.CHUNK_SIZE:
            chunked.append(doc)
        else:
            splits = splitter.split_documents([doc])
            # Propagate metadata to all chunks
            for s in splits:
                s.metadata.update(doc.metadata)
            chunked.extend(splits)

    print(f"\n[+] Total documents after chunking: {len(chunked)}")
    print(f"    MITRE ATT&CK: {sum(1 for d in chunked if d.metadata.get('source_type') == 'mitre_attack')}")
    print(f"    CISA KEV:     {sum(1 for d in chunked if d.metadata.get('source_type') == 'cisa_kev')}")
    print(f"    Reports:      {sum(1 for d in chunked if d.metadata.get('source_type') == 'threat_report')}")

    return chunked


if __name__ == "__main__":
    docs = ingest_all()
    print(f"\n[+] Ingestion complete. {len(docs)} chunks ready for vectorstore.")
