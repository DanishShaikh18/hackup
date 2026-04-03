"""
SOCentinel — Groq LLM Client.
Wrapper around the Groq API for fast LLM inference (Llama 3).
Primary model for triage, investigation, and response generation.
"""

import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")


class GroqClient:
    """Groq API client for Llama 3 inference."""

    def __init__(self, model: str = "llama3-70b-8192"):
        self.model = model
        self.api_key = GROQ_API_KEY

    async def chat(self, messages: list, temperature: float = 0.1, max_tokens: int = 2048) -> str:
        """
        Send a chat completion request to Groq.

        Args:
            messages: List of message dicts (role, content).
            temperature: Sampling temperature.
            max_tokens: Max response tokens.

        Returns:
            Response text string.
        """
        pass

    async def structured_output(self, messages: list, schema: dict) -> dict:
        """
        Get structured JSON output from Groq.

        Args:
            messages: Chat messages.
            schema: Expected output JSON schema.

        Returns:
            Parsed response dict.
        """
        pass
