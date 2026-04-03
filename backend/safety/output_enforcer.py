"""
SOCentinel — Output Enforcer.
Parses LLM output as JSON, returns safe fallback on failure.
"""

import json
import re


class OutputEnforcer:
    """Enforce structured JSON output from LLM responses."""

    SAFE_FALLBACK = {
        "error": "AI analysis unavailable",
        "severity": "UNKNOWN",
        "confidence": 0,
        "narrative": "Manual investigation required",
        "evidence_for_threat": [],
        "evidence_against_threat": [],
        "recommended_actions": [],
    }

    def enforce(self, raw_llm_text: str) -> dict:
        """
        Parse LLM text as JSON. Returns safe fallback on failure.
        Strips markdown code fences before parsing.
        """
        if not raw_llm_text:
            return dict(self.SAFE_FALLBACK)

        # Strip markdown code fences
        cleaned = re.sub(r"```(?:json)?\s*", "", raw_llm_text)
        cleaned = re.sub(r"```\s*$", "", cleaned).strip()

        try:
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[output_enforcer] JSON parse failed: {e}")
            return dict(self.SAFE_FALLBACK)
