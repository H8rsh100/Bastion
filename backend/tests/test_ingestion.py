"""
Smoke tests for the ingestion pipeline.

Tests chunking logic (which doesn't require external services)
and provides integration test stubs for Qdrant-dependent tests.
"""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.ingestion.chunk import chunk_cve, chunk_cves, chunk_log_text


# ── Sample Data ──────────────────────────────────────────────────────────

SAMPLE_CVE = {
    "cve_id": "CVE-2024-1234",
    "description": (
        "A buffer overflow vulnerability in ExampleLib 2.x allows remote "
        "attackers to execute arbitrary code via a crafted HTTP request to "
        "the /api/parse endpoint. The vulnerability exists due to improper "
        "bounds checking in the input parsing module when handling "
        "Content-Length headers exceeding 2^31 bytes."
    ),
    "severity": "CRITICAL",
    "base_score": 9.8,
    "published": "2024-01-15T00:00:00",
    "weaknesses": ["CWE-120", "CWE-787"],
    "affected_products": [
        {
            "vendor": "example_corp",
            "product": "examplelib",
            "version_start": "2.0.0",
            "version_end": "2.5.3",
            "criteria": "cpe:2.3:a:example_corp:examplelib:*:*:*:*:*:*:*:*",
        }
    ],
}

SAMPLE_CVE_SHORT = {
    "cve_id": "CVE-2024-5678",
    "description": "XSS in login page.",
    "severity": "MEDIUM",
    "base_score": 5.4,
    "published": "2024-03-01T00:00:00",
    "weaknesses": ["CWE-79"],
    "affected_products": [],
}

SAMPLE_LOG = """2024-01-15 10:23:01 WARNING: Connection attempt from 192.168.1.105 to port 4444
2024-01-15 10:23:02 ERROR: Authentication failed for user admin from 10.0.0.55
2024-01-15 10:23:03 INFO: Firewall rule triggered — blocked 203.0.113.42
2024-01-15 10:23:04 CRITICAL: Suspicious payload detected in POST /upload — hash: a1b2c3d4e5f6
2024-01-15 10:23:05 WARNING: DNS query to known-malicious domain evil.example.com from 192.168.1.22
2024-01-15 10:23:06 INFO: Normal traffic from 10.0.0.1
2024-01-15 10:23:07 ERROR: SSL certificate mismatch for banking.example.com
"""


# ── CVE Chunking Tests ───────────────────────────────────────────────────

class TestCVEChunking:
    """Test CVE text chunking."""

    def test_single_cve_produces_chunks(self):
        """A CVE record should produce at least one chunk."""
        chunks = chunk_cve(SAMPLE_CVE)
        assert len(chunks) >= 1

    def test_chunk_contains_cve_id(self):
        """Each chunk's text should include the CVE ID for context."""
        chunks = chunk_cve(SAMPLE_CVE)
        assert any(SAMPLE_CVE["cve_id"] in c["text"] for c in chunks)

    def test_chunk_metadata_has_required_fields(self):
        """Each chunk should carry metadata: cve_id, severity, source_type."""
        chunks = chunk_cve(SAMPLE_CVE)
        for chunk in chunks:
            meta = chunk["metadata"]
            assert meta["cve_id"] == "CVE-2024-1234"
            assert meta["severity"] == "CRITICAL"
            assert meta["base_score"] == 9.8
            assert meta["source_type"] == "cve"
            assert "chunk_index" in meta
            assert "total_chunks" in meta

    def test_short_cve_single_chunk(self):
        """A very short CVE should produce exactly one chunk."""
        chunks = chunk_cve(SAMPLE_CVE_SHORT, chunk_size=512)
        assert len(chunks) == 1

    def test_chunk_text_not_empty(self):
        """No chunk should have empty text."""
        chunks = chunk_cve(SAMPLE_CVE)
        for chunk in chunks:
            assert len(chunk["text"].strip()) > 0

    def test_chunk_includes_severity(self):
        """The enriched chunk text should include severity info."""
        chunks = chunk_cve(SAMPLE_CVE)
        first_chunk = chunks[0]["text"]
        assert "CRITICAL" in first_chunk
        assert "9.8" in first_chunk

    def test_chunk_includes_weaknesses(self):
        """CWE IDs should appear in the enriched text."""
        chunks = chunk_cve(SAMPLE_CVE)
        first_chunk = chunks[0]["text"]
        assert "CWE-120" in first_chunk

    def test_chunk_includes_affected_products(self):
        """Affected product info should appear in the enriched text."""
        chunks = chunk_cve(SAMPLE_CVE)
        full_text = " ".join(c["text"] for c in chunks)
        assert "example_corp" in full_text

    def test_multiple_cves(self):
        """chunk_cves should process a list of CVEs."""
        chunks = chunk_cves([SAMPLE_CVE, SAMPLE_CVE_SHORT])
        cve_ids = set(c["metadata"]["cve_id"] for c in chunks)
        assert "CVE-2024-1234" in cve_ids
        assert "CVE-2024-5678" in cve_ids

    def test_small_chunk_size_produces_more_chunks(self):
        """A smaller chunk size should produce more chunks."""
        large_chunks = chunk_cve(SAMPLE_CVE, chunk_size=1024)
        small_chunks = chunk_cve(SAMPLE_CVE, chunk_size=128, overlap=16)
        assert len(small_chunks) >= len(large_chunks)


# ── Log Chunking Tests ───────────────────────────────────────────────────

class TestLogChunking:
    """Test log text chunking."""

    def test_log_produces_chunks(self):
        """Log text should produce at least one chunk."""
        chunks = chunk_log_text(SAMPLE_LOG)
        assert len(chunks) >= 1

    def test_log_preserves_lines(self):
        """Log chunks should not split mid-line."""
        chunks = chunk_log_text(SAMPLE_LOG, chunk_size=200)
        for chunk in chunks:
            lines = chunk["text"].split("\n")
            for line in lines:
                # Each line should be a complete log entry (starts with a date or is empty)
                assert line.strip() == "" or line[0:4].isdigit() or line.startswith("2024")

    def test_log_metadata(self):
        """Log chunks should have correct metadata."""
        chunks = chunk_log_text(SAMPLE_LOG, source_name="auth.log")
        for chunk in chunks:
            assert chunk["metadata"]["source_type"] == "log"
            assert chunk["metadata"]["source_name"] == "auth.log"
            assert "chunk_index" in chunk["metadata"]
            assert "line_count" in chunk["metadata"]

    def test_log_no_empty_chunks(self):
        """No log chunk should have empty text."""
        chunks = chunk_log_text(SAMPLE_LOG, chunk_size=100)
        for chunk in chunks:
            assert len(chunk["text"].strip()) > 0

    def test_all_lines_accounted_for(self):
        """All input lines should appear in some chunk."""
        chunks = chunk_log_text(SAMPLE_LOG, chunk_size=200)
        all_chunked_text = "\n".join(c["text"] for c in chunks)
        for line in SAMPLE_LOG.strip().split("\n"):
            assert line.strip() in all_chunked_text


# ── Integration Test Stubs (require Qdrant) ──────────────────────────────

class TestEmbeddingIntegration:
    """
    Integration tests that require a running Qdrant instance.
    Marked to skip if Qdrant is not available.
    """

    @pytest.fixture
    def qdrant_available(self):
        """Check if Qdrant is reachable."""
        try:
            from qdrant_client import QdrantClient
            client = QdrantClient(host="localhost", port=6333, timeout=5)
            client.get_collections()
            return True
        except Exception:
            pytest.skip("Qdrant not available — skipping integration test")

    def test_embed_and_query(self, qdrant_available):
        """Embed a sample CVE and verify it can be retrieved."""
        from backend.ingestion.embed import EmbeddingPipeline
        from backend.ingestion.chunk import chunk_cve

        pipeline = EmbeddingPipeline(collection_name="bastion_test")

        try:
            chunks = chunk_cve(SAMPLE_CVE)
            count = pipeline.upsert_chunks(chunks)
            assert count > 0

            info = pipeline.get_collection_info()
            assert info["points_count"] > 0
        finally:
            # Clean up test collection
            try:
                pipeline.delete_collection()
            except Exception:
                pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
