"""
SOCentinel — Grounding Validator.
Ensures every AI-generated finding has a citation to raw log evidence.
No citation = no display. Mandatory grounding for trust.
"""


class GroundingValidator:
    """Validate that AI findings are grounded in actual evidence."""

    def validate(self, finding: str, evidence_refs: list, available_logs: list) -> dict:
        """
        Check that a finding is supported by cited evidence.

        Args:
            finding: AI-generated finding text.
            evidence_refs: List of log_event IDs cited.
            available_logs: List of actual log events for this alert.

        Returns:
            dict with 'grounded' (bool), 'coverage' (float), 'missing_refs' (list).
        """
        pass

    def extract_citations(self, text: str) -> list:
        """
        Extract log_event ID citations from AI-generated text.

        Args:
            text: AI response text.

        Returns:
            List of cited log_event IDs.
        """
        pass
