"""
SOCentinel — Ollama LLM Client.
Wrapper around local Ollama instance for offline/local inference.
Used as secondary model for Dual-LLM Shield validation.
"""

import os
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


class OllamaClient:
    """Ollama local LLM client."""

    def __init__(self, model: str = "llama3", base_url: str = None):
        self.model = model
        self.base_url = base_url or OLLAMA_BASE_URL

    async def chat(self, messages: list, temperature: float = 0.1) -> str:
        """
        Send a chat request to local Ollama instance.

        Args:
            messages: List of message dicts (role, content).
            temperature: Sampling temperature.

        Returns:
            Response text string.
        """
        pass

    async def is_available(self) -> bool:
        """Check if the Ollama instance is running."""
        pass
