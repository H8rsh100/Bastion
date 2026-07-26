"""
Bastion — centralized configuration.

All tunables in one place. Override via environment variables or .env file.
"""

import os
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
CVE_CACHE_DIR = DATA_DIR / "cve_cache"
MODELS_DIR = PROJECT_ROOT / "models"

# Ensure directories exist
CVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ── Qdrant ───────────────────────────────────────────────────────────────
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "bastion_cve")

# ── Embedding ────────────────────────────────────────────────────────────
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 output dimension

# ── LLM ──────────────────────────────────────────────────────────────────
# Supported quant levels: "Q4_K_M", "Q8_0", "FP16"
QUANT_LEVEL = os.getenv("QUANT_LEVEL", "Q4_K_M")
MODEL_NAME = os.getenv("MODEL_NAME", "mistral-7b-instruct")

# Model file paths (GGUF format, download separately)
MODEL_PATHS = {
    "Q4_K_M": MODELS_DIR / f"{MODEL_NAME}-q4_k_m.gguf",
    "Q8_0": MODELS_DIR / f"{MODEL_NAME}-q8_0.gguf",
    "FP16": MODELS_DIR / f"{MODEL_NAME}-fp16.gguf",
}

LLM_CONTEXT_LENGTH = int(os.getenv("LLM_CONTEXT_LENGTH", "4096"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_GPU_LAYERS = int(os.getenv("LLM_GPU_LAYERS", "0"))

# ── RAG ──────────────────────────────────────────────────────────────────
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "5"))
RAG_SCORE_THRESHOLD = float(os.getenv("RAG_SCORE_THRESHOLD", "0.3"))
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "512"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "64"))

# ── NVD API ──────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = float(os.getenv("NVD_RATE_LIMIT_DELAY", "6.0"))  # seconds between requests (no API key)

# ── Server ───────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
