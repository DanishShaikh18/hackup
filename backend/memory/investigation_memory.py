"""
SOCentinel — Investigation Memory.
Stores and retrieves past investigation findings for similarity search.
Uses Qdrant for vector similarity when available, falls back to SQLite.
"""


class InvestigationMemory:
    """Store and retrieve investigation findings with similarity search."""

    def __init__(self):
        self.qdrant_available = False

    async def store(self, case_id: str, finding: str, evidence_refs: list) -> str:
        """
        Store an investigation finding.

        Args:
            case_id: Associated case.
            finding: Finding text.
            evidence_refs: List of log_event IDs.

        Returns:
            Memory entry ID.
        """
        pass

    async def search_similar(self, alert_id: str, top_k: int = 5) -> list:
        """
        Find past investigations similar to the current alert.

        Args:
            alert_id: Current alert to match against.
            top_k: Number of similar cases to return.

        Returns:
            List of similar case dicts with similarity scores.
        """
        pass
