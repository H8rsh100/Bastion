"""
Embedding pipeline — embeds chunks and upserts into Qdrant.

Uses sentence-transformers for local embedding (all-MiniLM-L6-v2 by default).
Handles collection creation, batch embedding, and upsert with metadata payloads.
"""

import uuid
import logging
from typing import Optional
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    Distance,
    VectorParams,
    PointStruct,
    CollectionInfo,
)
from sentence_transformers import SentenceTransformer

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from backend.config import (
    QDRANT_HOST,
    QDRANT_PORT,
    QDRANT_COLLECTION,
    EMBEDDING_MODEL,
    EMBEDDING_DIM,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Batch size for Qdrant upserts
UPSERT_BATCH_SIZE = 100


class EmbeddingPipeline:
    """Manages embedding and upserting chunks into Qdrant."""

    def __init__(
        self,
        qdrant_host: str = QDRANT_HOST,
        qdrant_port: int = QDRANT_PORT,
        collection_name: str = QDRANT_COLLECTION,
        model_name: str = EMBEDDING_MODEL,
    ):
        self.collection_name = collection_name
        self.qdrant = QdrantClient(host=qdrant_host, port=qdrant_port)
        logger.info(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self._ensure_collection()

    def _ensure_collection(self):
        """Create the Qdrant collection if it doesn't exist."""
        try:
            self.qdrant.get_collection(self.collection_name)
            logger.info(f"Collection '{self.collection_name}' already exists")
        except Exception:
            logger.info(f"Creating collection '{self.collection_name}' (dim={EMBEDDING_DIM})")
            self.qdrant.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(
                    size=EMBEDDING_DIM,
                    distance=Distance.COSINE,
                ),
            )

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of texts using the sentence-transformer model."""
        embeddings = self.model.encode(texts, show_progress_bar=True, convert_to_numpy=True)
        return embeddings.tolist()

    def upsert_chunks(self, chunks: list[dict]) -> int:
        """
        Embed and upsert chunks into Qdrant.

        Each chunk must have:
        - "text": the text to embed
        - "metadata": dict of metadata to store as payload

        Returns the number of points upserted.
        """
        if not chunks:
            logger.warning("No chunks to upsert")
            return 0

        texts = [c["text"] for c in chunks]
        logger.info(f"Embedding {len(texts)} chunks...")
        embeddings = self.embed_texts(texts)

        # Build points
        points = []
        for chunk, embedding in zip(chunks, embeddings):
            point_id = str(uuid.uuid4())
            payload = {**chunk["metadata"], "text": chunk["text"]}
            points.append(PointStruct(
                id=point_id,
                vector=embedding,
                payload=payload,
            ))

        # Batch upsert
        total_upserted = 0
        for i in range(0, len(points), UPSERT_BATCH_SIZE):
            batch = points[i : i + UPSERT_BATCH_SIZE]
            self.qdrant.upsert(
                collection_name=self.collection_name,
                points=batch,
            )
            total_upserted += len(batch)
            logger.info(f"  Upserted batch: {total_upserted}/{len(points)}")

        logger.info(f"Upserted {total_upserted} points into '{self.collection_name}'")
        return total_upserted

    def get_collection_info(self) -> dict:
        """Get current collection stats."""
        try:
            info = self.qdrant.get_collection(self.collection_name)
            return {
                "name": self.collection_name,
                "points_count": info.points_count,
                "vectors_count": info.vectors_count,
                "status": str(info.status),
            }
        except Exception as e:
            return {"error": str(e)}

    def delete_collection(self):
        """Delete the collection (useful for re-indexing)."""
        self.qdrant.delete_collection(self.collection_name)
        logger.info(f"Deleted collection '{self.collection_name}'")

    def reset_and_reindex(self, chunks: list[dict]) -> int:
        """Delete collection, recreate, and upsert all chunks."""
        self.delete_collection()
        self._ensure_collection()
        return self.upsert_chunks(chunks)


# ── CLI Entry Point ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    from backend.ingestion.fetch_cve import load_from_cache, load_all_cached
    from backend.ingestion.chunk import chunk_cves

    parser = argparse.ArgumentParser(description="Embed CVE chunks into Qdrant")
    parser.add_argument("--file", type=str, default=None, help="Specific cache file to embed")
    parser.add_argument("--all", action="store_true", help="Embed all cached CVE files")
    parser.add_argument("--reset", action="store_true", help="Delete collection and re-index")
    parser.add_argument("--info", action="store_true", help="Show collection info only")
    args = parser.parse_args()

    pipeline = EmbeddingPipeline()

    if args.info:
        info = pipeline.get_collection_info()
        for k, v in info.items():
            print(f"  {k}: {v}")
    else:
        # Load CVEs
        if args.all:
            cves = load_all_cached()
        else:
            cves = load_from_cache(filename=args.file)

        if not cves:
            print("No CVE data found. Run fetch_cve.py first.")
        else:
            chunks = chunk_cves(cves)
            if args.reset:
                count = pipeline.reset_and_reindex(chunks)
            else:
                count = pipeline.upsert_chunks(chunks)
            print(f"\nDone. {count} chunks embedded.")
            info = pipeline.get_collection_info()
            for k, v in info.items():
                print(f"  {k}: {v}")
