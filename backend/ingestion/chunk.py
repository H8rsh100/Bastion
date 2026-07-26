"""
Chunking utility for CVE text and log files before embedding.

Provides:
- Sliding-window chunking with overlap for CVE descriptions
- Log file chunker that preserves log-line boundaries
- Metadata extraction (CVE-ID, severity, dates)
"""

import re
import logging
from typing import Optional
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from backend.config import CHUNK_SIZE, CHUNK_OVERLAP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _sliding_window(text: str, chunk_size: int, overlap: int) -> list[str]:
    """
    Split text into overlapping chunks by character count,
    breaking at word boundaries when possible.
    """
    if len(text) <= chunk_size:
        return [text]

    chunks = []
    start = 0

    while start < len(text):
        end = start + chunk_size

        # Try to break at a word boundary (look back from end)
        if end < len(text):
            # Find the last space before `end`
            last_space = text.rfind(" ", start, end)
            if last_space > start:
                end = last_space

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)

        # Advance by chunk_size minus overlap
        start = end - overlap
        if start <= (end - chunk_size):
            # Prevent infinite loops on very small texts
            start = end

    return chunks


def chunk_cve(cve: dict, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[dict]:
    """
    Chunk a single CVE record into embeddable pieces.

    Each chunk carries metadata for retrieval context:
    - cve_id, severity, base_score, published date
    - chunk_index for ordering
    - The chunk text itself

    For short CVEs (< chunk_size), produces a single enriched chunk.
    For longer ones, uses sliding-window with overlap.
    """
    cve_id = cve.get("cve_id", "UNKNOWN")
    description = cve.get("description", "")
    severity = cve.get("severity", "UNKNOWN")
    base_score = cve.get("base_score", 0.0)
    published = cve.get("published", "")
    weaknesses = cve.get("weaknesses", [])
    affected = cve.get("affected_products", [])

    # Build enriched text: CVE ID + severity context + description + affected products
    header = f"CVE: {cve_id} | Severity: {severity} | Score: {base_score}"
    if weaknesses:
        header += f" | CWE: {', '.join(weaknesses[:3])}"

    affected_text = ""
    if affected:
        products = [f"{p['vendor']}/{p['product']}" for p in affected[:5]]
        affected_text = f"\nAffected: {', '.join(products)}"

    full_text = f"{header}\n{description}{affected_text}"

    # Chunk the enriched text
    text_chunks = _sliding_window(full_text, chunk_size, overlap)

    results = []
    for i, chunk_text in enumerate(text_chunks):
        results.append({
            "text": chunk_text,
            "metadata": {
                "cve_id": cve_id,
                "severity": severity,
                "base_score": base_score,
                "published": published,
                "weaknesses": weaknesses,
                "chunk_index": i,
                "total_chunks": len(text_chunks),
                "source_type": "cve",
            },
        })

    return results


def chunk_cves(cves: list[dict], chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[dict]:
    """Chunk a list of CVE records."""
    all_chunks = []
    for cve in cves:
        all_chunks.extend(chunk_cve(cve, chunk_size, overlap))
    logger.info(f"Chunked {len(cves)} CVEs into {len(all_chunks)} chunks")
    return all_chunks


def chunk_log_text(
    log_text: str,
    chunk_size: int = CHUNK_SIZE,
    source_name: str = "log",
) -> list[dict]:
    """
    Chunk log text preserving line boundaries.

    Unlike CVE chunking, log lines shouldn't be split mid-line.
    Groups consecutive lines until chunk_size is reached.
    """
    lines = log_text.strip().split("\n")
    chunks = []
    current_chunk_lines = []
    current_size = 0

    for line in lines:
        line_size = len(line) + 1  # +1 for newline
        if current_size + line_size > chunk_size and current_chunk_lines:
            chunk_text = "\n".join(current_chunk_lines)
            chunks.append({
                "text": chunk_text,
                "metadata": {
                    "source_type": "log",
                    "source_name": source_name,
                    "chunk_index": len(chunks),
                    "line_count": len(current_chunk_lines),
                },
            })
            current_chunk_lines = []
            current_size = 0

        current_chunk_lines.append(line)
        current_size += line_size

    # Final chunk
    if current_chunk_lines:
        chunk_text = "\n".join(current_chunk_lines)
        chunks.append({
            "text": chunk_text,
            "metadata": {
                "source_type": "log",
                "source_name": source_name,
                "chunk_index": len(chunks),
                "line_count": len(current_chunk_lines),
            },
        })

    logger.info(f"Chunked log '{source_name}' ({len(lines)} lines) into {len(chunks)} chunks")
    return chunks


def chunk_log_file(
    file_path: str | Path,
    chunk_size: int = CHUNK_SIZE,
) -> list[dict]:
    """Chunk a log file from disk."""
    path = Path(file_path)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return chunk_log_text(text, chunk_size, source_name=path.name)


# ── CLI ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Quick demo: chunk a sample CVE
    sample_cve = {
        "cve_id": "CVE-2024-1234",
        "description": "A buffer overflow vulnerability in ExampleLib 2.x allows remote attackers to execute arbitrary code via a crafted HTTP request to the /api/parse endpoint. The vulnerability exists due to improper bounds checking in the input parsing module.",
        "severity": "CRITICAL",
        "base_score": 9.8,
        "published": "2024-01-15T00:00:00",
        "weaknesses": ["CWE-120"],
        "affected_products": [{"vendor": "example", "product": "examplelib", "version_start": "2.0", "version_end": "2.5.3", "criteria": ""}],
    }

    chunks = chunk_cve(sample_cve)
    for chunk in chunks:
        print(f"\n--- Chunk {chunk['metadata']['chunk_index']} ---")
        print(chunk["text"][:200])
        print(f"Metadata: {chunk['metadata']}")
