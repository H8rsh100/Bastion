"""
End-to-end smoke tests for Bastion security intelligence pipeline.
Verifies RAG synthesis and MCP server tool handling.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from backend.rag.synthesizer import Synthesizer
from backend.mcp_server.server import mcp_server, search_cve, explain_vulnerability, scan_log_for_iocs, check_dependency_risk


class TestE2EPipeline:
    def test_synthesizer_initialization_graceful(self):
        """Synthesizer should initialize gracefully even without local GGUF models loaded."""
        synth = Synthesizer()
        assert synth is not None
        status = synth.status()
        assert "ready" in status
        assert "llm" in status

    def test_mcp_server_metadata_registered(self):
        """Confirm all 4 required tools are registered in FastMCP server instance."""
        tools = mcp_server._tool_manager.list_tools()
        tool_names = {t.name for t in tools}
        assert "search_cve" in tool_names
        assert "explain_vulnerability" in tool_names
        assert "scan_log_for_iocs" in tool_names
        assert "check_dependency_risk" in tool_names

    def test_offline_fallback_execution(self):
        """Verify synthesizer returns structural output shape without throwing exceptions."""
        synth = Synthesizer()
        res = synth.search_cve("OpenSSL buffer overflow")
        assert isinstance(res, dict)
        assert "answer" in res
        assert "llm_metrics" in res
        assert "tool_type" in res
        assert res["tool_type"] == "search_cve"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
