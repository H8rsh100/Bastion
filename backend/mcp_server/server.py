"""
MCP server exposing Bastion security intelligence tools.

Tools: search_cve, explain_vulnerability, scan_log_for_iocs, check_dependency_risk.
Transport: SSE (Server-Sent Events) for network-accessible deployment.
"""

import logging
from pathlib import Path
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional

from mcp.server.fastmcp import FastMCP

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.config import API_HOST, API_PORT
from backend.rag.retriever import Retriever
from backend.rag.synthesizer import Synthesizer
from backend.llm.quantized_runner import QuantizedRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── Application Context ─────────────────────────────────────────────────

@dataclass
class BastionContext:
    """Shared application state for all tools."""
    synthesizer: Optional[Synthesizer] = None
    ready: bool = False


@asynccontextmanager
async def lifespan(server: FastMCP):
    """
    Initialize shared resources on startup, clean up on shutdown.

    Loads the RAG retriever and (optionally) the quantized LLM.
    Tools degrade gracefully if the LLM model file is not found.
    """
    ctx = BastionContext()

    logger.info("Bastion MCP server starting up...")

    try:
        retriever = Retriever()
        logger.info("Retriever initialized")
    except Exception as e:
        logger.warning(f"Retriever init failed (Qdrant may not be running): {e}")
        retriever = None

    try:
        runner = QuantizedRunner()
        logger.info(f"LLM runner initialized (loaded={runner.is_loaded})")
    except Exception as e:
        logger.warning(f"LLM runner init failed: {e}")
        runner = QuantizedRunner.__new__(QuantizedRunner)
        runner.model = None
        runner.quant_level = "Q4_K_M"
        runner._model_path = ""
        runner.n_ctx = 4096

    ctx.synthesizer = Synthesizer(retriever=retriever, runner=runner)
    ctx.ready = True

    logger.info("Bastion MCP server ready")
    yield ctx

    # Cleanup
    if runner and runner.is_loaded:
        runner.unload()
    logger.info("Bastion MCP server shut down")


# ── Server ───────────────────────────────────────────────────────────────

mcp_server = FastMCP(
    "Bastion",
    description=(
        "Security intelligence server. Searches CVE databases, explains "
        "vulnerabilities, scans logs for indicators of compromise, and "
        "assesses dependency risk — all running fully offline with a "
        "quantized LLM and RAG pipeline."
    ),
    lifespan=lifespan,
)


# ── CLI ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run the Bastion MCP server")
    parser.add_argument("--transport", type=str, default="sse", choices=["sse", "stdio"])
    parser.add_argument("--host", type=str, default=API_HOST)
    parser.add_argument("--port", type=int, default=API_PORT)
    args = parser.parse_args()

    logger.info(f"Starting Bastion MCP server ({args.transport} transport)")

    if args.transport == "sse":
        mcp_server.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp_server.run(transport="stdio")
