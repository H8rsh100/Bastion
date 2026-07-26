"""
RAG retriever — top-k semantic search over Qdrant.

Provides:
- Semantic similarity search with score-based filtering
- Metadata-enriched result formatting
- Context window builder for LLM prompt injection
"""

import logging
from typing import Optional
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.http.models import Filter, FieldCondition, MatchValue
from sentence_transformers import SentenceTransformer

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from backend.config import (
    QDRANT_HOST,
    QDRANT_PORT,
    QDRANT_COLLECTION,
    EMBEDDING_MODEL,
    RAG_TOP_K,
    RAG_SCORE_THRESHOLD,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class Retriever:
    """Semantic search over the Qdrant vector store."""

    def __init__(
        self,
        qdrant_host: str = QDRANT_HOST,
        qdrant_port: int = QDRANT_PORT,
        collection_name: str = QDRANT_COLLECTION,
        model_name: str = EMBEDDING_MODEL,
    ):
        self.collection_name = collection_name
        self.qdrant = QdrantClient(host=qdrant_host, port=qdrant_port)
        logger.info(f"Loading embedding model for retrieval: {model_name}")
        self.model = SentenceTransformer(model_name)

    def _embed_query(self, query: str) -> list[float]:
        """Embed a single query string."""
        return self.model.encode(query).tolist()

    def search(
        self,
        query: str,
        top_k: int = RAG_TOP_K,
        score_threshold: float = RAG_SCORE_THRESHOLD,
        source_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[dict]:
        """
        Perform semantic search over the vector store.

        Args:
            query: Natural language search query
            top_k: Number of results to return
            score_threshold: Minimum similarity score (0-1 for cosine)
            source_type: Filter by source type ("cve" or "log")
            severity: Filter by CVE severity ("CRITICAL", "HIGH", etc.)

        Returns:
            List of results, each with: text, score, metadata
        """
        query_vector = self._embed_query(query)

        # Build optional filters
        filter_conditions = []
        if source_type:
            filter_conditions.append(
                FieldCondition(key="source_type", match=MatchValue(value=source_type))
            )
        if severity:
            filter_conditions.append(
                FieldCondition(key="severity", match=MatchValue(value=severity.upper()))
            )

        search_filter = Filter(must=filter_conditions) if filter_conditions else None

        results = self.qdrant.search(
            collection_name=self.collection_name,
            query_vector=query_vector,
            limit=top_k,
            score_threshold=score_threshold,
            query_filter=search_filter,
        )

        parsed_results = []
        for hit in results:
            parsed_results.append({
                "text": hit.payload.get("text", ""),
                "score": round(hit.score, 4),
                "cve_id": hit.payload.get("cve_id", ""),
                "severity": hit.payload.get("severity", ""),
                "base_score": hit.payload.get("base_score", 0),
                "published": hit.payload.get("published", ""),
                "source_type": hit.payload.get("source_type", ""),
                "weaknesses": hit.payload.get("weaknesses", []),
                "chunk_index": hit.payload.get("chunk_index", 0),
            })

        logger.info(
            f"Search for '{query[:50]}...' returned {len(parsed_results)} results "
            f"(threshold={score_threshold})"
        )
        return parsed_results

    def search_by_cve_id(self, cve_id: str, top_k: int = 10) -> list[dict]:
        """
        Search specifically for a CVE by its ID.

        Uses both semantic search (for related CVEs) and exact metadata filter.
        """
        # First, try exact match via metadata filter
        exact_results = self.qdrant.scroll(
            collection_name=self.collection_name,
            scroll_filter=Filter(
                must=[FieldCondition(key="cve_id", match=MatchValue(value=cve_id))]
            ),
            limit=top_k,
        )

        results = []
        if exact_results and exact_results[0]:
            for point in exact_results[0]:
                results.append({
                    "text": point.payload.get("text", ""),
                    "score": 1.0,  # Exact match
                    "cve_id": point.payload.get("cve_id", ""),
                    "severity": point.payload.get("severity", ""),
                    "base_score": point.payload.get("base_score", 0),
                    "published": point.payload.get("published", ""),
                    "source_type": point.payload.get("source_type", ""),
                    "weaknesses": point.payload.get("weaknesses", []),
                    "chunk_index": point.payload.get("chunk_index", 0),
                })

        # If no exact match, fall back to semantic search
        if not results:
            results = self.search(f"CVE vulnerability {cve_id}", top_k=top_k)

        return results

    def build_context(
        self,
        results: list[dict],
        max_context_chars: int = 3000,
    ) -> str:
        """
        Build a context string from search results for LLM prompt injection.

        Formats results into a structured context block that the LLM can
        reference when generating answers. Respects a character budget.
        """
        if not results:
            return "No relevant documents found in the knowledge base."

        context_parts = []
        total_chars = 0

        for i, result in enumerate(results):
            entry = f"[Source {i+1}] (score: {result['score']})"
            if result.get("cve_id"):
                entry += f" | {result['cve_id']}"
            if result.get("severity"):
                entry += f" | {result['severity']}"
            if result.get("base_score"):
                entry += f" | CVSS {result['base_score']}"
            entry += f"\n{result['text']}"

            if total_chars + len(entry) > max_context_chars:
                # Truncate this entry to fit
                remaining = max_context_chars - total_chars - len(entry.split("\n")[0]) - 10
                if remaining > 50:
                    entry = entry[:total_chars + remaining] + "..."
                    context_parts.append(entry)
                break

            context_parts.append(entry)
            total_chars += len(entry)

        return "\n\n".join(context_parts)

    def get_stats(self) -> dict:
        """Get collection statistics."""
        try:
            info = self.qdrant.get_collection(self.collection_name)
            return {
                "collection": self.collection_name,
                "points_count": info.points_count,
                "status": str(info.status),
            }
        except Exception as e:
            return {"error": str(e)}


# ── CLI ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Search the Bastion CVE knowledge base")
    parser.add_argument("query", type=str, help="Search query")
    parser.add_argument("--top-k", type=int, default=5, help="Number of results")
    parser.add_argument("--threshold", type=float, default=0.3, help="Min score threshold")
    parser.add_argument("--severity", type=str, default=None, help="Filter by severity")
    parser.add_argument("--context", action="store_true", help="Output as LLM context block")
    args = parser.parse_args()

    retriever = Retriever()

    results = retriever.search(
        args.query,
        top_k=args.top_k,
        score_threshold=args.threshold,
        severity=args.severity,
    )

    if args.context:
        print(retriever.build_context(results))
    else:
        print(f"\n{'='*60}")
        print(f"Results for: {args.query}")
        print(f"{'='*60}")
        for r in results:
            print(f"\n[{r['score']}] {r.get('cve_id', 'N/A')} — {r.get('severity', '?')}")
            print(f"  {r['text'][:200]}...")
        print(f"\nStats: {retriever.get_stats()}")
