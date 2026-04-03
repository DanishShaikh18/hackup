"""
SOCentinel — Threat DNA.
Generates a unique 'threat fingerprint' for each alert based on event patterns.
Used for similarity matching against past investigations.
"""


class ThreatDNA:
    """Generate threat fingerprints for similarity matching."""

    def generate(self, alert_id: str, events: list) -> dict:
        """
        Create a threat DNA fingerprint from alert events.

        Args:
            alert_id: Alert to fingerprint.
            events: Associated log events.

        Returns:
            Threat DNA dict with pattern vector and metadata.
        """
        pass

    def compare(self, dna_a: dict, dna_b: dict) -> float:
        """
        Compare two threat DNA fingerprints.

        Args:
            dna_a: First threat DNA.
            dna_b: Second threat DNA.

        Returns:
            Similarity score (0.0 to 1.0).
        """
        pass
