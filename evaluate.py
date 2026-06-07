"""
ThreatScope Evaluation Pipeline
--------------------------------
Measures retrieval quality and answer accuracy using a curated Q&A test set.

Metrics:
  - Retrieval Precision: Are the retrieved docs relevant to the query?
  - Answer Relevance: Does the answer address the question?
  - Source Coverage: Did we retrieve from the right data source?
  - Latency: How fast is the retrieval?

Usage:
    python evaluate.py
"""

import json
import os
import time
from datetime import datetime

from rag_engine import ThreatRAGEngine


# ==============================================================================
# Test Cases: Curated question-answer pairs with expected attributes
# ==============================================================================

TEST_CASES = [
    {
        "query": "What is MITRE ATT&CK technique T1059?",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["command", "scripting", "interpreter"],
        "expected_technique_id": "T1059",
    },
    {
        "query": "What is credential dumping and what MITRE techniques cover it?",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["credential", "LSASS", "dump"],
        "expected_technique_id": "T1003",
    },
    {
        "query": "What is T1566 phishing?",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["phishing", "spearphishing", "attachment"],
        "expected_technique_id": "T1566",
    },
    {
        "query": "What MITRE techniques relate to lateral movement?",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["lateral", "movement", "remote"],
    },
    {
        "query": "What CVEs have been exploited by ransomware?",
        "expected_source_type": "cisa_kev",
        "expected_keywords": ["ransomware", "CVE"],
    },
    {
        "query": "What vulnerabilities affect Microsoft products in the CISA KEV catalog?",
        "expected_source_type": "cisa_kev",
        "expected_keywords": ["Microsoft", "vulnerability"],
    },
    {
        "query": "What is privilege escalation and how is it performed?",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["privilege", "escalation"],
    },
    {
        "query": "Explain persistence techniques in MITRE ATT&CK",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["persistence", "registry", "startup"],
    },
    {
        "query": "What is T1071 Application Layer Protocol?",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["application", "protocol", "C2"],
        "expected_technique_id": "T1071",
    },
    {
        "query": "What are the most common initial access techniques?",
        "expected_source_type": "mitre_attack",
        "expected_keywords": ["initial", "access", "phishing"],
    },
]


# ==============================================================================
# Evaluation Functions
# ==============================================================================

def evaluate_retrieval_precision(result, test_case):
    """
    Check if retrieved sources are from the expected source_type.
    Returns ratio of relevant sources / total sources.
    """
    sources = result.get("sources", [])
    if not sources:
        return 0.0

    expected = test_case.get("expected_source_type")
    if not expected:
        return 1.0  # no expectation = pass

    relevant = sum(1 for s in sources if s.get("source_type") == expected)
    return relevant / len(sources)


def evaluate_answer_relevance(result, test_case):
    """
    Check if the answer contains expected keywords.
    Returns ratio of keywords found / total expected keywords.
    """
    answer = result.get("answer", "").lower()
    keywords = test_case.get("expected_keywords", [])
    if not keywords:
        return 1.0

    found = sum(1 for kw in keywords if kw.lower() in answer)
    return found / len(keywords)


def evaluate_technique_match(result, test_case):
    """
    Check if the expected technique ID appears in retrieved sources.
    """
    expected_id = test_case.get("expected_technique_id")
    if not expected_id:
        return None  # not applicable

    sources = result.get("sources", [])
    answer = result.get("answer", "")

    # Check sources
    for s in sources:
        if s.get("technique_id", "").startswith(expected_id):
            return 1.0

    # Check answer text
    if expected_id in answer:
        return 1.0

    return 0.0


def run_evaluation(engine):
    """
    Run all test cases and compute aggregate metrics.
    """
    results = []
    total_retrieval_time = 0

    print(f"\n{'='*70}")
    print(f"ThreatScope Evaluation - {datetime.now().isoformat()}")
    print(f"{'='*70}\n")

    for i, test_case in enumerate(TEST_CASES, 1):
        query = test_case["query"]
        print(f"[{i}/{len(TEST_CASES)}] {query[:80]}...")

        start = time.time()
        result = engine.query(query)
        elapsed = time.time() - start
        total_retrieval_time += elapsed

        precision = evaluate_retrieval_precision(result, test_case)
        relevance = evaluate_answer_relevance(result, test_case)
        technique = evaluate_technique_match(result, test_case)

        eval_result = {
            "query": query,
            "retrieval_precision": round(precision, 2),
            "answer_relevance": round(relevance, 2),
            "technique_match": technique,
            "latency_sec": round(elapsed, 2),
            "num_sources": len(result.get("sources", [])),
        }
        results.append(eval_result)

        status = "PASS" if relevance >= 0.5 and precision >= 0.3 else "FAIL"
        print(f"  Precision: {precision:.0%} | Relevance: {relevance:.0%} | "
              f"Latency: {elapsed:.1f}s | {status}")

    # Aggregate metrics
    avg_precision = sum(r["retrieval_precision"] for r in results) / len(results)
    avg_relevance = sum(r["answer_relevance"] for r in results) / len(results)
    technique_scores = [r["technique_match"] for r in results if r["technique_match"] is not None]
    avg_technique = sum(technique_scores) / len(technique_scores) if technique_scores else 0
    avg_latency = total_retrieval_time / len(results)

    summary = {
        "timestamp": datetime.now().isoformat(),
        "num_test_cases": len(results),
        "avg_retrieval_precision": round(avg_precision, 3),
        "avg_answer_relevance": round(avg_relevance, 3),
        "avg_technique_match": round(avg_technique, 3),
        "avg_latency_sec": round(avg_latency, 2),
        "total_time_sec": round(total_retrieval_time, 2),
        "model": results[0].get("model", engine._get_model_name()) if results else "unknown",
        "details": results,
    }

    print(f"\n{'='*70}")
    print(f"EVALUATION SUMMARY")
    print(f"{'='*70}")
    print(f"  Test Cases:           {summary['num_test_cases']}")
    print(f"  Avg Retrieval Prec:   {summary['avg_retrieval_precision']:.1%}")
    print(f"  Avg Answer Relevance: {summary['avg_answer_relevance']:.1%}")
    print(f"  Avg Technique Match:  {summary['avg_technique_match']:.1%}")
    print(f"  Avg Latency:          {summary['avg_latency_sec']:.2f}s")
    print(f"  Total Time:           {summary['total_time_sec']:.1f}s")
    print(f"  Model:                {summary['model']}")
    print(f"{'='*70}\n")

    # Save results
    output_path = "eval/eval_results.json"
    os.makedirs("eval", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Results saved to {output_path}")

    return summary


if __name__ == "__main__":
    print("[+] Initializing ThreatScope RAG engine...")
    engine = ThreatRAGEngine()
    engine.build_index()
    run_evaluation(engine)
