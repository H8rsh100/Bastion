"""
llama.cpp GGUF model wrapper.

Supports Q4_K_M / Q8_0 / FP16 configs per project plan.
Uses llama-cpp-python for inference with configurable parameters.
"""

import time
import logging
import psutil
from typing import Optional
from pathlib import Path

from llama_cpp import Llama

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from backend.config import (
    MODEL_PATHS,
    QUANT_LEVEL,
    LLM_CONTEXT_LENGTH,
    LLM_MAX_TOKENS,
    LLM_TEMPERATURE,
    LLM_GPU_LAYERS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# Default system prompt for security context
DEFAULT_SYSTEM_PROMPT = (
    "You are Bastion, a security intelligence assistant. You analyze CVE "
    "vulnerabilities, assess threat indicators, and provide clear, actionable "
    "security guidance. Base your answers on the provided context. If the "
    "context doesn't contain enough information, say so clearly. Do not "
    "hallucinate CVE details."
)


class QuantizedRunner:
    """
    Wrapper around llama-cpp-python for GGUF model inference.

    Supports loading different quantization levels and provides
    a simple generate() interface with timing/memory metrics.
    """

    def __init__(
        self,
        quant_level: str = QUANT_LEVEL,
        model_path: Optional[str] = None,
        n_ctx: int = LLM_CONTEXT_LENGTH,
        n_gpu_layers: int = LLM_GPU_LAYERS,
        verbose: bool = False,
    ):
        self.quant_level = quant_level
        self.n_ctx = n_ctx
        self.model: Optional[Llama] = None
        self._model_path = model_path or str(MODEL_PATHS.get(quant_level, ""))

        if not Path(self._model_path).exists():
            logger.warning(
                f"Model file not found: {self._model_path}. "
                f"Call load() after placing a GGUF file at that path."
            )
            return

        self.load(n_gpu_layers=n_gpu_layers, verbose=verbose)

    def load(
        self,
        model_path: Optional[str] = None,
        n_gpu_layers: int = LLM_GPU_LAYERS,
        verbose: bool = False,
    ):
        """Load the GGUF model into memory."""
        path = model_path or self._model_path

        if not Path(path).exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        logger.info(f"Loading model: {path} (quant={self.quant_level}, ctx={self.n_ctx})")
        start = time.time()

        self.model = Llama(
            model_path=str(path),
            n_ctx=self.n_ctx,
            n_gpu_layers=n_gpu_layers,
            verbose=verbose,
        )

        elapsed = time.time() - start
        logger.info(f"Model loaded in {elapsed:.1f}s")
        self._model_path = path

    def generate(
        self,
        prompt: str,
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        max_tokens: int = LLM_MAX_TOKENS,
        temperature: float = LLM_TEMPERATURE,
        top_p: float = 0.9,
        stop: Optional[list[str]] = None,
    ) -> dict:
        """
        Generate a response from the LLM.

        Args:
            prompt: The user/context prompt
            system_prompt: System instruction for the model
            max_tokens: Maximum tokens in the response
            temperature: Sampling temperature (lower = more deterministic)
            top_p: Nucleus sampling threshold
            stop: Stop sequences

        Returns:
            Dict with: text, tokens_generated, latency_ms, tokens_per_sec, memory_mb
        """
        if self.model is None:
            return {
                "text": "Model not loaded. Please load a GGUF model first.",
                "tokens_generated": 0,
                "latency_ms": 0,
                "tokens_per_sec": 0,
                "memory_mb": 0,
                "error": True,
            }

        # Build chat messages for instruct-style models
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]

        # Measure memory before
        process = psutil.Process()
        mem_before = process.memory_info().rss / (1024 * 1024)

        start = time.time()

        response = self.model.create_chat_completion(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            stop=stop or [],
        )

        elapsed_ms = (time.time() - start) * 1000

        # Extract response text
        text = response["choices"][0]["message"]["content"]
        usage = response.get("usage", {})
        tokens_generated = usage.get("completion_tokens", 0)

        # Memory after
        mem_after = process.memory_info().rss / (1024 * 1024)

        tokens_per_sec = (tokens_generated / (elapsed_ms / 1000)) if elapsed_ms > 0 else 0

        result = {
            "text": text,
            "tokens_generated": tokens_generated,
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "latency_ms": round(elapsed_ms, 1),
            "tokens_per_sec": round(tokens_per_sec, 1),
            "memory_mb": round(mem_after, 1),
            "memory_delta_mb": round(mem_after - mem_before, 1),
            "quant_level": self.quant_level,
            "error": False,
        }

        logger.info(
            f"Generated {tokens_generated} tokens in {elapsed_ms:.0f}ms "
            f"({tokens_per_sec:.1f} tok/s) | Memory: {mem_after:.0f}MB"
        )

        return result

    def generate_raw(
        self,
        prompt: str,
        max_tokens: int = LLM_MAX_TOKENS,
        temperature: float = LLM_TEMPERATURE,
        stop: Optional[list[str]] = None,
    ) -> str:
        """Simple text completion (no chat format). Returns just the text."""
        if self.model is None:
            return "Model not loaded."

        response = self.model(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=stop or [],
        )

        return response["choices"][0]["text"]

    @property
    def is_loaded(self) -> bool:
        """Check if a model is currently loaded."""
        return self.model is not None

    @property
    def model_info(self) -> dict:
        """Get info about the loaded model."""
        return {
            "loaded": self.is_loaded,
            "quant_level": self.quant_level,
            "model_path": self._model_path,
            "context_length": self.n_ctx,
        }

    def unload(self):
        """Unload the model to free memory."""
        if self.model:
            del self.model
            self.model = None
            logger.info("Model unloaded")


# ── CLI ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test the quantized LLM runner")
    parser.add_argument("--quant", type=str, default="Q4_K_M", choices=["Q4_K_M", "Q8_0", "FP16"])
    parser.add_argument("--model", type=str, default=None, help="Path to GGUF model file")
    parser.add_argument("--prompt", type=str, default="Explain CVE-2024-1234 in simple terms.")
    parser.add_argument("--max-tokens", type=int, default=256)
    args = parser.parse_args()

    runner = QuantizedRunner(quant_level=args.quant, model_path=args.model)

    if runner.is_loaded:
        result = runner.generate(args.prompt, max_tokens=args.max_tokens)
        print(f"\n{'='*60}")
        print(f"Response ({result['quant_level']}):")
        print(f"{'='*60}")
        print(result["text"])
        print(f"\n--- Metrics ---")
        print(f"Tokens: {result['tokens_generated']} | Latency: {result['latency_ms']}ms")
        print(f"Speed: {result['tokens_per_sec']} tok/s | Memory: {result['memory_mb']}MB")
    else:
        print(f"Model not found at: {runner._model_path}")
        print(f"Download a GGUF model and place it there, or pass --model <path>")
