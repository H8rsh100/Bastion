# Quantization Benchmark Results

> Comparing Q4_K_M, Q8_0, and FP16 quantization levels for Mistral 7B Instruct
> using a 20-question security evaluation set.

## Summary Table

| Metric | Q4_K_M | Q8_0 | FP16 |
|--------|--------|------|------|
| Latency (avg) | — | — | — |
| Latency (median) | — | — | — |
| Latency (p95) | — | — | — |
| Tokens/sec (avg) | — | — | — |
| Memory (peak) | — | — | — |
| Memory (avg) | — | — | — |
| Quality score | — | — | — |
| Load time | — | — | — |

> Results will be populated after running `python -m backend.llm.benchmark` with
> GGUF model files placed in the `models/` directory.

## Methodology

- **Eval set**: 20 security-focused questions covering vulnerability types, threat
  assessment, cryptography, and security frameworks
- **Quality scoring**: Keyword-based rubric measuring whether responses include
  expected technical terms (automated, not LLM-judged)
- **Environment**: Measured on the development machine with consistent settings
  (temperature=0.1, max_tokens=256)
- **Memory**: RSS (Resident Set Size) measured via `psutil` during inference

## How to Run

```bash
# Run full benchmark (all quant levels)
python -m backend.llm.benchmark

# Run specific levels
python -m backend.llm.benchmark --levels Q4_K_M Q8_0

# Limit questions for quick test
python -m backend.llm.benchmark --questions 5

# Custom max tokens
python -m backend.llm.benchmark --max-tokens 128
```

Results are saved to `docs/benchmark_results.json` and printed as a markdown table.

## Analysis

> *To be written after running benchmarks with actual model files.*

Key questions to answer:
1. **Is Q4_K_M "good enough"?** — For a security assistant that needs to get CVE
   IDs and severity levels right, does 4-bit quantization lose critical detail?
2. **Memory vs. quality tradeoff** — How much memory does Q8_0 save over FP16,
   and is the quality difference measurable?
3. **Latency in an interactive context** — Is sub-second per-token achievable on
   consumer hardware at any quant level?
