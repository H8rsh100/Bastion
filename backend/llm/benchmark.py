"""
Quantization benchmark harness.

Runs the same eval set across Q4_K_M / Q8_0 / FP16, logging latency,
memory footprint, tokens/sec, and response quality. Outputs results
as a markdown table and a JSON file for later reference.

Gracefully skips any quant level whose GGUF model file is missing.
"""

import json
import time
import logging
import statistics
from pathlib import Path
from typing import Optional

import psutil

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.config import MODEL_PATHS, MODELS_DIR, PROJECT_ROOT
from backend.llm.quantized_runner import QuantizedRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── Eval Set ─────────────────────────────────────────────────────────────
# 20 security-focused questions spanning CVE analysis, threat assessment,
# and general security knowledge.

EVAL_QUESTIONS = [
    "What is a buffer overflow vulnerability and how can it be exploited?",
    "Explain the CVSS scoring system and what a score of 9.8 means.",
    "What are indicators of compromise (IOCs) and give three examples.",
    "Describe the difference between a CVE and a CWE.",
    "What is SQL injection and how do parameterized queries prevent it?",
    "Explain cross-site scripting (XSS) and its three main types.",
    "What is a zero-day vulnerability?",
    "Describe how a supply chain attack works in software dependencies.",
    "What is the MITRE ATT&CK framework and how is it used?",
    "Explain the principle of least privilege and why it matters.",
    "What is a race condition vulnerability? Give a real-world example.",
    "Describe how certificate pinning prevents man-in-the-middle attacks.",
    "What are the OWASP Top 10 and why do they matter?",
    "Explain the difference between symmetric and asymmetric encryption.",
    "What is a use-after-free vulnerability and which languages are affected?",
    "Describe how a DNS rebinding attack works.",
    "What is SSRF (Server-Side Request Forgery) and how can it be mitigated?",
    "Explain what a reverse shell is and how defenders detect one.",
    "What is privilege escalation and what are common techniques?",
    "Describe how Content Security Policy (CSP) headers protect web apps.",
]


# ── Quality rubric keywords ─────────────────────────────────────────────
# For each question, a set of keywords that a good answer should contain.
# Used for a rough automated quality score (% of keywords present).

QUALITY_KEYWORDS = {
    0: ["buffer", "memory", "overflow", "stack", "heap"],
    1: ["cvss", "score", "critical", "severity", "base"],
    2: ["indicator", "compromise", "ip", "hash", "domain"],
    3: ["cve", "cwe", "vulnerability", "weakness", "enumeration"],
    4: ["sql", "injection", "parameterized", "query", "input"],
    5: ["xss", "script", "reflected", "stored", "dom"],
    6: ["zero-day", "patch", "unknown", "exploit"],
    7: ["supply chain", "dependency", "package", "malicious"],
    8: ["mitre", "att&ck", "tactic", "technique", "procedure"],
    9: ["privilege", "least", "access", "permission"],
    10: ["race", "condition", "concurrent", "thread", "time"],
    11: ["certificate", "pinning", "mitm", "tls"],
    12: ["owasp", "top", "web", "application", "security"],
    13: ["symmetric", "asymmetric", "key", "encrypt"],
    14: ["use-after-free", "memory", "pointer", "c", "heap"],
    15: ["dns", "rebinding", "domain", "ip", "browser"],
    16: ["ssrf", "server", "request", "forgery", "internal"],
    17: ["reverse", "shell", "connection", "command", "detect"],
    18: ["privilege", "escalation", "root", "admin"],
    19: ["csp", "content", "security", "policy", "header"],
}


def score_quality(answer: str, question_index: int) -> float:
    """
    Rough quality score: fraction of expected keywords found in the answer.

    Returns a value between 0.0 and 1.0.
    """
    keywords = QUALITY_KEYWORDS.get(question_index, [])
    if not keywords:
        return 0.0

    answer_lower = answer.lower()
    hits = sum(1 for kw in keywords if kw.lower() in answer_lower)
    return round(hits / len(keywords), 2)


def run_benchmark(
    quant_levels: Optional[list[str]] = None,
    max_questions: int = 20,
    max_tokens: int = 256,
    output_dir: Optional[Path] = None,
) -> dict:
    """
    Run the full benchmark across quant levels.

    Args:
        quant_levels: List of quant levels to test (default: all three)
        max_questions: Cap on number of eval questions to run
        max_tokens: Max response tokens per question
        output_dir: Where to write results JSON (default: PROJECT_ROOT/docs)

    Returns:
        Dict with per-level aggregate metrics and per-question details.
    """
    if quant_levels is None:
        quant_levels = ["Q4_K_M", "Q8_0", "FP16"]

    if output_dir is None:
        output_dir = PROJECT_ROOT / "docs"
    output_dir.mkdir(parents=True, exist_ok=True)

    questions = EVAL_QUESTIONS[:max_questions]
    results = {"quant_levels": {}, "questions": len(questions), "max_tokens": max_tokens}

    for level in quant_levels:
        model_path = MODEL_PATHS.get(level)
        if model_path is None or not Path(model_path).exists():
            logger.warning(f"Skipping {level}: model file not found at {model_path}")
            results["quant_levels"][level] = {"skipped": True, "reason": "model file not found"}
            continue

        logger.info(f"\n{'='*60}")
        logger.info(f"BENCHMARKING: {level}")
        logger.info(f"{'='*60}")

        # Load model and measure load time
        load_start = time.time()
        runner = QuantizedRunner(quant_level=level, model_path=str(model_path))
        load_time = time.time() - load_start

        if not runner.is_loaded:
            logger.error(f"Failed to load model for {level}")
            results["quant_levels"][level] = {"skipped": True, "reason": "model failed to load"}
            continue

        level_results = {
            "model_path": str(model_path),
            "load_time_s": round(load_time, 1),
            "questions": [],
            "skipped": False,
        }

        latencies = []
        tokens_per_sec_list = []
        memory_values = []
        quality_scores = []

        for i, question in enumerate(questions):
            logger.info(f"  [{i+1}/{len(questions)}] {question[:60]}...")

            result = runner.generate(
                prompt=question,
                max_tokens=max_tokens,
                temperature=0.1,
            )

            quality = score_quality(result.get("text", ""), i)

            question_result = {
                "question_index": i,
                "question": question,
                "answer_preview": result.get("text", "")[:200],
                "tokens_generated": result.get("tokens_generated", 0),
                "latency_ms": result.get("latency_ms", 0),
                "tokens_per_sec": result.get("tokens_per_sec", 0),
                "memory_mb": result.get("memory_mb", 0),
                "quality_score": quality,
                "error": result.get("error", False),
            }

            level_results["questions"].append(question_result)

            if not result.get("error"):
                latencies.append(result.get("latency_ms", 0))
                tokens_per_sec_list.append(result.get("tokens_per_sec", 0))
                memory_values.append(result.get("memory_mb", 0))
                quality_scores.append(quality)

        # Aggregate metrics
        if latencies:
            level_results["aggregate"] = {
                "avg_latency_ms": round(statistics.mean(latencies), 1),
                "median_latency_ms": round(statistics.median(latencies), 1),
                "p95_latency_ms": round(sorted(latencies)[int(len(latencies) * 0.95)], 1),
                "avg_tokens_per_sec": round(statistics.mean(tokens_per_sec_list), 1),
                "peak_memory_mb": round(max(memory_values), 1),
                "avg_memory_mb": round(statistics.mean(memory_values), 1),
                "avg_quality_score": round(statistics.mean(quality_scores), 2),
                "questions_completed": len(latencies),
                "questions_errored": len(questions) - len(latencies),
            }

        results["quant_levels"][level] = level_results

        # Unload to free memory before next level
        runner.unload()

    # Write results JSON
    results_path = output_dir / "benchmark_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"\nResults written to: {results_path}")

    return results


def format_markdown_table(results: dict) -> str:
    """Format benchmark results as a markdown table."""
    levels = results.get("quant_levels", {})

    lines = [
        "# Quantization Benchmark Results",
        "",
        f"Eval set: {results.get('questions', 20)} security questions | Max tokens: {results.get('max_tokens', 256)}",
        "",
        "| Metric | Q4_K_M | Q8_0 | FP16 |",
        "|--------|--------|------|------|",
    ]

    metrics = [
        ("Latency (avg)", "avg_latency_ms", "ms"),
        ("Latency (median)", "median_latency_ms", "ms"),
        ("Latency (p95)", "p95_latency_ms", "ms"),
        ("Tokens/sec (avg)", "avg_tokens_per_sec", ""),
        ("Memory (peak)", "peak_memory_mb", "MB"),
        ("Memory (avg)", "avg_memory_mb", "MB"),
        ("Quality score", "avg_quality_score", "/1.0"),
        ("Load time", "load_time_s", "s"),
    ]

    for label, key, unit in metrics:
        row = f"| {label} |"
        for level in ["Q4_K_M", "Q8_0", "FP16"]:
            data = levels.get(level, {})
            if data.get("skipped"):
                row += " — |"
            else:
                agg = data.get("aggregate", {})
                val = agg.get(key, data.get(key))
                if val is not None:
                    row += f" {val}{unit} |"
                else:
                    row += " — |"
        lines.append(row)

    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run quantization benchmarks")
    parser.add_argument(
        "--levels",
        nargs="+",
        default=["Q4_K_M", "Q8_0", "FP16"],
        choices=["Q4_K_M", "Q8_0", "FP16"],
        help="Quant levels to benchmark",
    )
    parser.add_argument(
        "--questions",
        type=int,
        default=20,
        help="Number of eval questions (max 20)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=256,
        help="Max response tokens",
    )
    args = parser.parse_args()

    results = run_benchmark(
        quant_levels=args.levels,
        max_questions=args.questions,
        max_tokens=args.max_tokens,
    )

    # Print markdown table
    print("\n")
    print(format_markdown_table(results))
    print()

    # Summary
    for level, data in results["quant_levels"].items():
        if data.get("skipped"):
            print(f"  {level}: SKIPPED ({data.get('reason', 'unknown')})")
        else:
            agg = data.get("aggregate", {})
            print(
                f"  {level}: {agg.get('avg_latency_ms', '?')}ms avg | "
                f"{agg.get('avg_tokens_per_sec', '?')} tok/s | "
                f"{agg.get('peak_memory_mb', '?')}MB peak | "
                f"quality {agg.get('avg_quality_score', '?')}/1.0"
            )
