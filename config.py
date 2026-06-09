import os
from dotenv import load_dotenv

load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()  # groq | openai | ollama

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Default: HuggingFace sentence-transformers (free, local, no API key needed)
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "vectorstore")
CHROMA_COLLECTION_NAME = os.getenv("CHROMA_COLLECTION_NAME", "threat_intel")

CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "800"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "200"))
RETRIEVAL_K = int(os.getenv("RETRIEVAL_K", "15"))

MITRE_DATA_DIR = "data/mitre"
CISA_KEV_DIR = "data/cisa_kev"
THREAT_REPORTS_DIR = "data/threat_reports"

QUERY_LOG_FILE = "query_log.jsonl"
