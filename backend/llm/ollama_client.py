"""
SOCentinel — Ollama LLM Client.
Simple wrapper for local Ollama instance (phi4-mini for log structuring).
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def call_ollama(prompt: str, model: str = "phi4-mini") -> str | None:
    """
    Call local Ollama instance for inference.

    Args:
        prompt: The prompt to send.
        model: Ollama model name.

    Returns:
        Response text string, or None on failure.
    """
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("response", None)
    except Exception as e:
        print(f"[ollama_client] Error: {e}")
        return None
