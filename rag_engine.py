import os
import re
import json
import time
import shutil
from datetime import datetime
from collections import Counter

from langchain_core.documents import Document
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from rank_bm25 import BM25Okapi

import config
from ingest import ingest_all
from ioc_extractor import extract_iocs


class ThreatRAGEngine:
    """
    Hybrid RAG engine combining dense vector search (ChromaDB) with
    sparse keyword search (BM25) for cybersecurity threat intelligence.
    """

    def __init__(self):
        self.embeddings = HuggingFaceEmbeddings(
            model_name=config.EMBEDDING_MODEL,
            model_kwargs={"device": "cpu"},
        )
        self.vectorstore = None
        self.bm25_index = None
        self.bm25_docs = []  # parallel list of Documents for BM25
        self.llm = None
        self._init_llm()

    def _init_llm(self):
        """Initialize LLM based on configured provider."""
        provider = config.LLM_PROVIDER

        if provider == "groq" and config.GROQ_API_KEY:
            from langchain_groq import ChatGroq
            self.llm = ChatGroq(
                api_key=config.GROQ_API_KEY,
                model_name=config.GROQ_MODEL,
                temperature=0,
                max_tokens=2048,
            )
            print(f"[+] LLM: Groq ({config.GROQ_MODEL})")

        elif provider == "openai" and config.OPENAI_API_KEY:
            from langchain_openai import ChatOpenAI
            self.llm = ChatOpenAI(
                api_key=config.OPENAI_API_KEY,
                model=config.OPENAI_MODEL,
                temperature=0,
                max_tokens=2048,
            )
            print(f"[+] LLM: OpenAI ({config.OPENAI_MODEL})")

        elif provider == "ollama":
            from langchain_community.llms import Ollama
            self.llm = Ollama(
                model=config.OLLAMA_MODEL,
                base_url=config.OLLAMA_BASE_URL,
            )
            print(f"[+] LLM: Ollama ({config.OLLAMA_MODEL})")

        else:
            print(f"[!] No valid LLM configured. Provider='{provider}'")
            print("    Set LLM_PROVIDER and the corresponding API key in .env")
            self.llm = None

    def build_index(self, force_rebuild=False):
        """
        Ingest all data sources, build ChromaDB vectorstore and BM25 index.

        Args:
            force_rebuild: If True, delete existing vectorstore and rebuild.
        """
        # Check if vectorstore already exists
        if not force_rebuild and os.path.exists(config.CHROMA_PERSIST_DIR):
            chroma_files = os.listdir(config.CHROMA_PERSIST_DIR)
            if len(chroma_files) > 0:
                print("[*] Loading existing vectorstore...")
                self.vectorstore = Chroma(
                    persist_directory=config.CHROMA_PERSIST_DIR,
                    embedding_function=self.embeddings,
                    collection_name=config.CHROMA_COLLECTION_NAME,
                )
                # Rebuild BM25 from stored docs
                self._rebuild_bm25_from_chroma()
                return

        # Full rebuild
        print("[+] Building index from all data sources...")
        documents = ingest_all()

        if not documents:
            print("[!] No documents to index.")
            return

        # Delete existing vectorstore
        if os.path.exists(config.CHROMA_PERSIST_DIR):
            shutil.rmtree(config.CHROMA_PERSIST_DIR)

        # Build ChromaDB
        self.vectorstore = Chroma.from_documents(
            documents=documents,
            embedding=self.embeddings,
            persist_directory=config.CHROMA_PERSIST_DIR,
            collection_name=config.CHROMA_COLLECTION_NAME,
        )
        print(f"[+] ChromaDB vectorstore built with {len(documents)} documents.")

        # Build BM25
        self._build_bm25(documents)

    def _build_bm25(self, documents):
        """Build BM25 index from document list."""
        self.bm25_docs = documents
        tokenized = [doc.page_content.lower().split() for doc in documents]
        self.bm25_index = BM25Okapi(tokenized)
        print(f"[+] BM25 index built with {len(documents)} documents.")

    def _rebuild_bm25_from_chroma(self):
        """Reconstruct BM25 index from ChromaDB contents."""
        if self.vectorstore is None:
            return
        try:
            collection = self.vectorstore._collection
            result = collection.get(include=["documents", "metadatas"])
            docs = []
            for text, meta in zip(result["documents"], result["metadatas"]):
                docs.append(Document(page_content=text, metadata=meta or {}))
            self._build_bm25(docs)
        except Exception as e:
            print(f"[!] Could not rebuild BM25 from Chroma: {e}")
          
    def _vector_search(self, query, k=None, filters=None):
        """Dense vector similarity search via ChromaDB."""
        k = k or config.RETRIEVAL_K
        if self.vectorstore is None:
            return []

        where_filter = None
        if filters:
            if len(filters) == 1:
                key, value = list(filters.items())[0]
                where_filter = {key: value}
            else:
                where_filter = {
                    "$and": [{fk: fv} for fk, fv in filters.items()]
                }

        try:
            results = self.vectorstore.similarity_search_with_score(
                query, k=k, filter=where_filter
            )
            return [(doc, score) for doc, score in results]
        except Exception as e:
            print(f"[!] Vector search error: {e}")
            return []

    def _bm25_search(self, query, k=None):
        """Sparse keyword search via BM25."""
        k = k or config.RETRIEVAL_K
        if self.bm25_index is None or not self.bm25_docs:
            return []

        tokenized_query = query.lower().split()
        scores = self.bm25_index.get_scores(tokenized_query)

        # Get top-k indices
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]

        results = []
        for idx in top_indices:
            if scores[idx] > 0:
                results.append((self.bm25_docs[idx], scores[idx]))

        return results

    def hybrid_search(self, query, k=None, filters=None, vector_weight=0.6):
        """
        Combine BM25 and vector search results using Reciprocal Rank Fusion (RRF).

        Args:
            query: User's search query.
            k: Number of results to return.
            filters: Optional metadata filters for vector search.
            vector_weight: Weight for vector results (0-1). BM25 gets 1-weight.

        Returns:
            List of (Document, score) tuples, ranked by combined score.
        """
        k = k or config.RETRIEVAL_K

        vector_results = self._vector_search(query, k=k * 2, filters=filters)
        bm25_results = self._bm25_search(query, k=k * 2)


        rrf_constant = 60  # standard RRF constant from the original RRF paper
        scored_docs = {}
        for rank, (doc, _) in enumerate(vector_results):
            key = doc.page_content[:200]
            if key not in scored_docs:
                scored_docs[key] = {"doc": doc, "score": 0}
            scored_docs[key]["score"] += vector_weight / (rrf_constant + rank + 1)

        bm25_weight = 1 - vector_weight
        for rank, (doc, _) in enumerate(bm25_results):
            key = doc.page_content[:200]
            if key not in scored_docs:
                scored_docs[key] = {"doc": doc, "score": 0}
            scored_docs[key]["score"] += bm25_weight / (rrf_constant + rank + 1)

        # Sort by combined score
        ranked = sorted(scored_docs.values(), key=lambda x: x["score"], reverse=True)

        return [(item["doc"], item["score"]) for item in ranked[:k]]

    def query(self, user_query, filters=None):

        if self.llm is None:
            return {
                "answer": "Error: No LLM configured. Set LLM_PROVIDER and API key in .env file.",
                "sources": [],
                "iocs": {},
                "retrieval_time": 0,
                "model": "none",
            }

        # Ensure index is loaded
        if self.vectorstore is None:
            self.build_index()

        # Step 1: Extract IOCs
        iocs = extract_iocs(user_query)

        # Step 2: Hybrid retrieval
        start_time = time.time()
        results = self.hybrid_search(user_query, filters=filters)
        retrieval_time = round(time.time() - start_time, 3)

        # Step 3: Build context from retrieved docs
        context_parts = []
        sources = []
        for doc, score in results:
            context_parts.append(doc.page_content)
            source_info = {
                "source_type": doc.metadata.get("source_type", "unknown"),
                "relevance_score": round(score, 4),
            }
            # Add type-specific metadata
            if doc.metadata.get("technique_id"):
                source_info["technique_id"] = doc.metadata["technique_id"]
                source_info["technique_name"] = doc.metadata.get("technique_name", "")
            if doc.metadata.get("cve_id"):
                source_info["cve_id"] = doc.metadata["cve_id"]
            if doc.metadata.get("filename"):
                source_info["filename"] = doc.metadata["filename"]
            sources.append(source_info)

        context = "\n\n---\n\n".join(context_parts)

        # Step 4: Construct prompt
        prompt = self._build_prompt(user_query, context, iocs)

        # Step 5: Generate response
        try:
            if hasattr(self.llm, "invoke"):
                response = self.llm.invoke(prompt)
                if hasattr(response, "content"):
                    answer = response.content
                else:
                    answer = str(response)
            else:
                answer = self.llm(prompt)
        except Exception as e:
            answer = f"LLM Error: {str(e)}"

        # Step 6: Log query
        result = {
            "answer": answer,
            "sources": sources,
            "iocs": iocs,
            "retrieval_time": retrieval_time,
            "model": self._get_model_name(),
        }
        self._log_query(user_query, result, filters)

        return result

    def _build_prompt(self, query, context, iocs):
        """Build the augmented prompt for the LLM."""
        ioc_section = ""
        if iocs:
            ioc_lines = []
            for ioc_type, values in iocs.items():
                ioc_lines.append(f"  {ioc_type}: {', '.join(values[:10])}")
            ioc_section = f"\n\nIOCs detected in the query:\n" + "\n".join(ioc_lines)

        return f"""You are a cybersecurity threat intelligence analyst. Analyze the user's query and
using ONLY the retrieved intelligence context below. Be specific, cite technique IDs
and CVE numbers when relevant. If the context doesn't contain enough information
to answer, say so explicitly.

=== Retrieved Threat Intelligence ===
{context}

=== User Query ===
{query}{ioc_section}

=== Instructions ===
1. Answer the query based on the retrieved context.
2. Reference specific MITRE ATT&CK technique IDs (e.g., T1059) when applicable.
3. Reference specific CVE IDs when applicable.
4. Indicate severity (Critical/High/Medium/Low) if the query is about a threat.
5. Suggest defensive actions or mitigations when relevant.
6. Be concise but thorough.
"""

    def _get_model_name(self):
        """Return the active model name for logging."""
        provider = config.LLM_PROVIDER
        if provider == "groq":
            return f"groq/{config.GROQ_MODEL}"
        elif provider == "openai":
            return f"openai/{config.OPENAI_MODEL}"
        elif provider == "ollama":
            return f"ollama/{config.OLLAMA_MODEL}"
        return "unknown"

    def _log_query(self, query, result, filters):
        """Append query details to JSONL log file for observability."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "query": query[:500],
            "filters": filters,
            "model": result.get("model", ""),
            "retrieval_time_sec": result.get("retrieval_time", 0),
            "num_sources": len(result.get("sources", [])),
            "iocs_found": {k: len(v) for k, v in result.get("iocs", {}).items()},
            "answer_length": len(result.get("answer", "")),
        }
        try:
            with open(config.QUERY_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass  # Don't crash on logging failure

    def get_query_logs(self, n=50):
        """Read the last n query log entries."""
        if not os.path.exists(config.QUERY_LOG_FILE):
            return []
        logs = []
        try:
            with open(config.QUERY_LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        logs.append(json.loads(line))
        except Exception:
            pass
        return logs[-n:]

    def get_index_stats(self):
        """Return statistics about the indexed data."""
        if self.vectorstore is None:
            return {"status": "not_loaded", "total_documents": 0}

        try:
            collection = self.vectorstore._collection
            count = collection.count()
            result = collection.get(include=["metadatas"])
            metadatas = result.get("metadatas", [])

            source_counts = Counter(m.get("source_type", "unknown") for m in metadatas)
            vendor_counts = Counter(
                m.get("vendor", "N/A") for m in metadatas if m.get("vendor")
            )
            tactic_list = []
            for m in metadatas:
                if m.get("tactics"):
                    tactic_list.extend(m["tactics"].split(", "))
            tactic_counts = Counter(tactic_list)

            return {
                "status": "loaded",
                "total_documents": count,
                "by_source": dict(source_counts),
                "top_vendors": dict(vendor_counts.most_common(10)),
                "top_tactics": dict(tactic_counts.most_common(14)),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
