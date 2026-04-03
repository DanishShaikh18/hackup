"""
SOCentinel — Input Sanitizer.
Validates and sanitizes all user inputs before they reach the LLM.
Strips injection attempts, enforces length limits, validates format.
"""


class InputSanitizer:
    """Sanitize user inputs to prevent prompt injection and malformed data."""

    def sanitize(self, user_input: str) -> str:
        """
        Clean and validate user input.

        Args:
            user_input: Raw input string from user.

        Returns:
            Sanitized input string.
        """
        pass

    def detect_injection(self, text: str) -> bool:
        """
        Check if input contains prompt injection patterns.

        Args:
            text: Input text to check.

        Returns:
            True if injection detected, False otherwise.
        """
        pass
