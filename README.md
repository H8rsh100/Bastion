# Bastion

> Security intelligence that never leaves the building.

A locally-deployed, quantized-LLM security intelligence server exposed as an **MCP server** with a custom checkpoint-style React + Vite frontend. Bastion runs fully offline — a quantized language model grounded by a RAG pipeline over CVE feeds and logs, exposed as tools that any MCP client (Claude Desktop, Cursor, custom agents) can call.

**The pitch in one line:** *A self-hosted security co-pilot that never sends sensitive logs to the cloud, and plugs into your existing agent tooling instead of being yet another chat window.*

---

## Why This Architecture

This isn't four toy projects stapled together — each component exists because the use case demands it:

- **Quantization** — air-gapped/on-prem security environments can't call cloud APIs. Quantization is the only way this product could exist in a real SOC.
- **RAG** — grounds the model in live threat intel (NVD/CVE feed) instead of hallucinating CVE details. A concrete, checkable use case.
- **MCP** — the distribution mechanism. Instead of building yet another dashboard nobody opens, Bastion's capabilities become *tools* other agents can call via SSE or stdio transports.
- **Cybersecurity** — the domain that makes the other three non-arbitrary.

---

## Architecture & Pipeline

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
                     │  MCP Server (FastMCP)    │
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
| Backend | Python, FastAPI, Pydantic |
| Vector DB | Qdrant (Docker, local) |
| LLM Runtime | llama.cpp + GGUF quantized models (Mistral 7B) |
| Embeddings | all-MiniLM-L6-v2 via sentence-transformers |
| MCP Server | FastMCP SDK 1.x (SSE / stdio transports) |
| CVE Data | NVD API v2.0 + local JSON cache |
| Frontend | React + Vite, vanilla CSS, IBM Plex fonts |

---

## MCP Tools Exposed

| Tool | Input | What it does |
|------|-------|-------------|
| `search_cve` | query string | RAG search over CVE corpus, returns ranked matches with CVSS scores |
| `explain_vulnerability` | CVE ID | Retrieves + LLM-summarizes a specific CVE in developer-friendly plain language |
| `scan_log_for_iocs` | log text/file | LLM + regex hybrid pass to flag indicators of compromise (IOCs) and assess threat level |
| `check_dependency_risk` | package name + version | Cross-references CVE DB for known vulns in that software supply chain dependency |

---

## Frontend UI: Checkpoint Sector

The custom React frontend treats every request as an inspection passing through a physical security checkpoint at night. 

- **Signature Gate Schematic**: Visualizes real-time pipeline ingress progressing through three sequentially illuminated gates: `RETRIEVE` (RAG search) ➔ `GROUND` (LLM inference) ➔ `INSPECT` (IOC/risk assessment).
- **Three-Pane Layout**: Terminal-style command ingress on the left, telemetry status in the center, and monospace attributed intelligence readouts on the right.
- **Accessibility**: Includes seamless static highlighting fallbacks respecting `prefers-reduced-motion`.

---

## Quantization Benchmarks

*Results from running the same 20-question eval set across quantization levels:*

| Metric | Q4_K_M | Q8_0 | FP16 |
|--------|--------|------|------|
| Latency (avg) | ~380ms | ~620ms | ~1450ms |
| Memory (peak) | 4.2 GB | 7.8 GB | 14.2 GB |
| Tokens/sec | 34.2 | 21.0 | 9.4 |
| Quality score | 0.91 / 1.0 | 0.95 / 1.0 | 0.98 / 1.0 |

> See [`docs/benchmark_results.md`](docs/benchmark_results.md) for detailed methodology, analysis, and instructions to reproduce locally using `python -m backend.llm.benchmark`.

---

## Quickstart & Setup

```bash
# 1. Clone repository
git clone https://github.com/H8rsh100/Bastion.git
cd Bastion

# 2. Start local Qdrant vector database
docker compose up -d

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Download GGUF model file (place inside models/)
# e.g. Mistral-7B-Instruct-v0.2.Q4_K_M.gguf from Hugging Face

# 5. Fetch CVE data from NVD & build embeddings
python -m backend.ingestion.fetch_cve
python -m backend.ingestion.embed

# 6. Start the MCP server (SSE transport on port 8000)
python -m backend.mcp_server.server --transport sse

# 7. Start the Checkpoint Frontend UI
cd frontend && npm install && npm run dev
```

---

## Testing

```bash
# Run backend smoke and unit tests
python -m pytest backend/tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE).
