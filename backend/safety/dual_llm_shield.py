"""
SOCentinel — Dual-LLM Shield.
LLM-1 (Ollama/phi4-mini) structures raw logs into JSON.
LLM-2 (Groq) never sees raw log text — only structured data.
"""

import json
from safety.input_sanitizer import InputSanitizer
from llm.ollama_client import call_ollama


class DualLLMShield:
    """Two-model pipeline: sanitize → structure via LLM-1 → feed to LLM-2."""

    def __init__(self):
        self.sanitizer = InputSanitizer()

    def process(self, raw_log: str) -> dict:
        """
        Sanitize raw log, then structure via Ollama (LLM-1).

        Returns structured dict. Falls back to sanitized text
        as details field if Ollama is unavailable or fails.
        """
        sanitized = self.sanitizer.sanitize(raw_log)

        if sanitized == "[REDACTED-INJECTION]":
            return {"details": sanitized, "event_type": "injection_attempt"}

        prompt = (
            "You are a log parser. Convert this log line to JSON with these fields: "
            "event_type, user_id, src_ip, dst_ip, hostname, timestamp, details. "
            "Return ONLY valid JSON, no explanation.\n\n"
            f"Log: {sanitized}"
        )

        response = call_ollama(prompt, model="phi4-mini")

        if not response:
            print("[dual_llm_shield] Ollama unavailable, using fallback")
            return {"details": sanitized}

        try:
            # Strip any markdown fences
            cleaned = response.strip().strip("`").strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            print("[dual_llm_shield] JSON parse failed, using fallback")
            return {"details": sanitized}
