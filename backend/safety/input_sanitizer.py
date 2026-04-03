"""
SOCentinel — Input Sanitizer.
Checks for prompt injection patterns and truncates input.
"""

import re


class InputSanitizer:
    """Sanitize raw log text before it reaches any LLM."""

    INJECTION_PATTERNS = [
        r"ignore.*instructions",
        r"you are now",
        r"act as",
        r"system prompt",
        r"forget everything",
        r"jailbreak",
    ]
    MAX_LENGTH = 1000

    def sanitize(self, raw_log: str) -> str:
        """
        Check for injection patterns and truncate.

        Returns '[REDACTED-INJECTION]' if injection detected,
        otherwise returns truncated string.
        """
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, raw_log, re.IGNORECASE):
                print(f"[input_sanitizer] Injection detected: {pattern}")
                return "[REDACTED-INJECTION]"
        return raw_log[:self.MAX_LENGTH]
