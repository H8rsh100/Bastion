"""
RAG + LLM answer synthesis.

Wires the retriever output into the LLM prompt with purpose-built
templates for each tool type (CVE search, explanation, IOC scanning,
dependency risk). Includes source attribution in responses.
"""

import logging
from typing import Optional
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.rag.retriever import Retriever
from backend.llm.quantized_runner import QuantizedRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── Prompt Templates ─────────────────────────────────────────────────────

SEARCH_CVE_TEMPLATE = """You are a security analyst. Based on the following CVE intelligence retrieved from the knowledge base, answer the user's query.

## Retrieved Context
{context}

## User Query
{query}

## Instructions
- Summarize the most relevant CVEs found
- Include CVE IDs, severity levels, and CVSS scores
- Explain the practical impact of each vulnerability
- If the context doesn't fully answer the query, state what's missing
- Keep your response concise and actionable"""

EXPLAIN_VULN_TEMPLATE = """You are a security educator explaining a vulnerability to a development team.

## CVE Intelligence
{context}

## Target CVE
{query}

## Instructions
- Explain this vulnerability in clear, non-jargon language
- Describe: what it is, how it works, who is affected, how severe it is
- Include the CVSS score and severity rating
- List any known affected products/versions
- Suggest mitigation steps (patch, workaround, or compensating controls)
- Keep it practical — this will be read by developers, not security researchers"""

SCAN_IOC_TEMPLATE = """You are a threat analyst reviewing log data for indicators of compromise (IOCs).

## Known Threat Intelligence
{context}

## Log Data to Analyze
{query}

## Instructions
- Identify all potential indicators of compromise in the log data
- Look for: suspicious IPs, malicious domains, file hashes, unusual ports, known attack patterns
- For each IOC found, explain why it's suspicious
- Cross-reference against the threat intelligence context if relevant
- Rate the overall threat level: LOW / MEDIUM / HIGH / CRITICAL
- Format findings clearly with each IOC on its own line"""

DEPENDENCY_RISK_TEMPLATE = """You are a software supply chain security analyst.

## CVE Intelligence for This Dependency
{context}

## Dependency to Assess
{query}

## Instructions
- List all known CVEs affecting this package/version
- For each CVE: state the ID, severity, CVSS score, and a one-line summary
- Assess the overall risk level for using this dependency
- Recommend: upgrade path, alternative packages, or mitigations
- If no CVEs are found in the knowledge base, state that clearly
- Do not invent or hallucinate CVE numbers"""


# Template registry
TEMPLATES = {
    "search_cve": SEARCH_CVE_TEMPLATE,
    "explain_vulnerability": EXPLAIN_VULN_TEMPLATE,
    "scan_log_for_iocs": SCAN_IOC_TEMPLATE,
    "check_dependency_risk": DEPENDENCY_RISK_TEMPLATE,
}


class Synthesizer:
    """
    Orchestrates RAG retrieval + LLM synthesis.

    For each query:
    1. Retrieves relevant context from Qdrant
    2. Formats a purpose-built prompt with the context
    3. Sends to the quantized LLM for synthesis
    4. Returns the result with source attribution
    """

    def __init__(
        self,
        retriever: Optional[Retriever] = None,
        runner: Optional[QuantizedRunner] = None,
    ):
        self.retriever = retriever or Retriever()
        self.runner = runner or QuantizedRunner()

    def synthesize(
        self,
        query: str,
        tool_type: str = "search_cve",
        top_k: int = 5,
        max_tokens: int = 1024,
        severity_filter: Optional[str] = None,
    ) -> dict:
        """
        Full RAG synthesis: retrieve → build prompt → generate → attribute.

        Args:
            query: The user's query or input data
            tool_type: Which template to use (search_cve, explain_vulnerability, etc.)
            top_k: Number of context documents to retrieve
            max_tokens: Max LLM response tokens
            severity_filter: Optional CVE severity filter

        Returns:
            Dict with: answer, sources, retrieval_results, llm_metrics
        """
        # Step 1: Retrieve
        logger.info(f"[Synthesize] Retrieving context for: {query[:80]}...")

        if tool_type == "explain_vulnerability" and query.upper().startswith("CVE-"):
            # Direct CVE lookup
            results = self.retriever.search_by_cve_id(query.upper(), top_k=top_k)
        else:
            results = self.retriever.search(
                query,
                top_k=top_k,
                severity=severity_filter,
            )

        # Step 2: Build context
        context = self.retriever.build_context(results)

        # Step 3: Format prompt
        template = TEMPLATES.get(tool_type, SEARCH_CVE_TEMPLATE)
        prompt = template.format(context=context, query=query)

        # Step 4: Generate
        logger.info(f"[Synthesize] Generating response ({tool_type})...")
        llm_result = self.runner.generate(prompt, max_tokens=max_tokens)

        # Step 5: Build source attribution
        sources = []
        seen_cve_ids = set()
        for r in results:
            cve_id = r.get("cve_id", "")
            if cve_id and cve_id not in seen_cve_ids:
                seen_cve_ids.add(cve_id)
                sources.append({
                    "cve_id": cve_id,
                    "severity": r.get("severity", ""),
                    "base_score": r.get("base_score", 0),
                    "relevance_score": r.get("score", 0),
                })

        return {
            "answer": llm_result.get("text", ""),
            "sources": sources,
            "retrieval_count": len(results),
            "tool_type": tool_type,
            "llm_metrics": {
                "tokens_generated": llm_result.get("tokens_generated", 0),
                "latency_ms": llm_result.get("latency_ms", 0),
                "tokens_per_sec": llm_result.get("tokens_per_sec", 0),
                "memory_mb": llm_result.get("memory_mb", 0),
                "quant_level": llm_result.get("quant_level", ""),
            },
            "error": llm_result.get("error", False),
        }

    def search_cve(self, query: str, **kwargs) -> dict:
        """Convenience method for CVE search."""
        return self.synthesize(query, tool_type="search_cve", **kwargs)

    def explain_vulnerability(self, cve_id: str, **kwargs) -> dict:
        """Convenience method for CVE explanation."""
        return self.synthesize(cve_id, tool_type="explain_vulnerability", **kwargs)

    def scan_log_for_iocs(self, log_text: str, **kwargs) -> dict:
        """Convenience method for IOC scanning."""
        return self.synthesize(log_text, tool_type="scan_log_for_iocs", **kwargs)

    def check_dependency_risk(self, package_query: str, **kwargs) -> dict:
        """Convenience method for dependency risk check."""
        return self.synthesize(package_query, tool_type="check_dependency_risk", **kwargs)

    @property
    def is_ready(self) -> bool:
        """Check if both retriever and LLM are ready."""
        return self.runner.is_loaded

    def status(self) -> dict:
        """Get system status."""
        return {
            "llm": self.runner.model_info,
            "retriever": self.retriever.get_stats(),
            "ready": self.is_ready,
        }


# ── CLI ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test RAG synthesis pipeline")
    parser.add_argument("query", type=str, help="Query to synthesize")
    parser.add_argument(
        "--tool",
        type=str,
        default="search_cve",
        choices=list(TEMPLATES.keys()),
    )
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args()

    synth = Synthesizer()
    result = synth.synthesize(args.query, tool_type=args.tool, top_k=args.top_k, max_tokens=args.max_tokens)

    print(f"\n{'='*60}")
    print(f"Answer ({args.tool}):")
    print(f"{'='*60}")
    print(result["answer"])
    print(f"\n--- Sources ---")
    for s in result["sources"]:
        print(f"  {s['cve_id']} ({s['severity']}, CVSS {s['base_score']}) — relevance: {s['relevance_score']}")
    print(f"\n--- Metrics ---")
    m = result["llm_metrics"]
    print(f"  Tokens: {m['tokens_generated']} | Latency: {m['latency_ms']}ms | Speed: {m['tokens_per_sec']} tok/s")
