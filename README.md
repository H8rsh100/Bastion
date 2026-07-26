# Bastion

> Security intelligence that never leaves the building.

A locally-deployed, quantized-LLM security intelligence server exposed as an **MCP server**. Bastion runs fully offline — a quantized language model grounded by a RAG pipeline over CVE feeds and logs, exposed as tools that any MCP client (Claude Desktop, Cursor, custom agents) can call.

**The pitch in one line:** *A self-hosted security co-pilot that never sends sensitive logs to the cloud, and plugs into your existing agent tooling instead of being yet another chat window.*

---

## Why This Architecture

This isn't four toy projects stapled together — each component exists because the use case demands it:

- **Quantization** — air-gapped/on-prem security environments can't call cloud APIs. Quantization is the only way this product could exist in a real SOC.
- **RAG** — grounds the model in live threat intel (NVD/CVE feed) instead of hallucinating CVE details. A concrete, checkable use case.
- **MCP** — the distribution mechanism. Instead of building yet another dashboard nobody opens, Bastion's capabilities become *tools* other agents can call.
- **Cybersecurity** — the domain that makes the other three non-arbitrary.

---

## Architecture

```
                     ┌─────────────────────────┐
   CVE / NVD feed ─▶ │  Ingestion Pipeline      │
   Log files     ─▶  │  (chunk + embed)         │
   Your repos    ─▶  │                          │
                     └───────────┬──────────────┘
                                 ▼
                     ┌─────────────────────────┐
                     │  Vector Store (Qdrant)   │
                     └───────────┬──────────────┘
                                 ▼
                     ┌─────────────────────────┐
                     │  RAG Retriever           │
                     └───────────┬──────────────┘
                                 ▼
                     ┌─────────────────────────┐
                     │  Quantized LLM           │
                     │  (llama.cpp, GGUF,       │
                     │   Q4_K_M / Q8_0)         │
                     └───────────┬──────────────┘
                                 ▼
                     ┌─────────────────────────┐
                     │  MCP Server              │
                     │  tools:                  │
                     │   - search_cve           │
                     │   - explain_vulnerability│
                     │   - scan_log_for_iocs    │
                     │   - check_dependency_risk│
                     └───────────┬──────────────┘
                                 ▼
                     ┌─────────────────────────┐
                     │  Frontend (checkpoint UI)│
                     │  live "gate" schematic   │
                     └─────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI |
| Vector DB | Qdrant (Docker, local) |
| LLM Runtime | llama.cpp + GGUF quantized models (Mistral 7B) |
| Embeddings | all-MiniLM-L6-v2 via sentence-transformers |
| MCP Server | Python MCP SDK (SSE transport) |
| CVE Data | NVD API v2.0 + local JSON cache |
| Frontend | React + Vite, vanilla CSS, IBM Plex fonts |

---

## MCP Tools

| Tool | Input | What it does |
|------|-------|-------------|
| `search_cve` | query string | RAG search over CVE corpus, returns ranked matches |
| `explain_vulnerability` | CVE ID | Retrieves + LLM-summarizes a specific CVE in plain language |
| `scan_log_for_iocs` | log text/file | LLM + regex hybrid pass to flag indicators of compromise |
| `check_dependency_risk` | package name + version | Cross-references CVE DB for known vulns in that dependency |

---

## Quantization Benchmarks

*Results from running the same 20-question eval set across quantization levels:*

| Metric | Q4_K_M | Q8_0 | FP16 |
|--------|--------|------|------|
| Latency (avg) | — | — | — |
| Memory (peak) | — | — | — |
| Tokens/sec | — | — | — |
| Quality score | — | — | — |

> Benchmark results will be populated after running `python -m backend.llm.benchmark` with
> GGUF model files. See [`docs/benchmark_results.md`](docs/benchmark_results.md) for
> detailed methodology, analysis, and how to reproduce.

---

## Project Structure

```
bastion/
├── backend/
│   ├── config.py              # Centralized configuration
│   ├── ingestion/
│   │   ├── fetch_cve.py       # NVD API client
│   │   ├── chunk.py           # Text chunking utility
│   │   └── embed.py           # Embedding + Qdrant upsert
│   ├── rag/
│   │   ├── retriever.py       # Semantic search over Qdrant
│   │   └── synthesizer.py     # RAG + LLM answer synthesis
│   ├── llm/
│   │   ├── quantized_runner.py # llama.cpp GGUF wrapper
│   │   └── benchmark.py       # Quantization benchmark harness
│   ├── mcp_server/
│   │   └── server.py          # MCP server with 4 tools
│   └── tests/
│       └── test_ingestion.py  # Pipeline smoke tests
├── frontend/                  # React + Vite checkpoint UI
├── data/
│   └── cve_cache/             # Cached NVD JSON responses
├── docs/                      # Benchmark results, notes
├── models/                    # GGUF model files (not tracked)
├── docker-compose.yml         # Qdrant service
├── requirements.txt           # Python dependencies
└── DECISIONS.md               # Design decisions log
```

---

## Setup

```bash
# 1. Clone
git clone https://github.com/H8rsh100/Bastion.git
cd Bastion

# 2. Start Qdrant
docker compose up -d

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Download a GGUF model (place in models/)
# e.g. Mistral-7B-Instruct Q4_K_M from HuggingFace

# 5. Fetch CVE data
python -m backend.ingestion.fetch_cve

# 6. Build embeddings
python -m backend.ingestion.embed

# 7. Start the server
python -m backend.mcp_server.server

# 8. Start the frontend
cd frontend && npm install && npm run dev
```

---

## Extensibility

Designed to ingest output logs from complementary security tools (e.g., NetGuard, SentryMesh) as additional RAG sources — Bastion can then explain alerts those tools generate.

---

## License

MIT — see [LICENSE](LICENSE).
