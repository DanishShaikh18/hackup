"""
SOCentinel — Triage Agent.
Performs initial alert triage: severity assessment, context enrichment,
true/false positive classification, and MITRE ATT&CK mapping.
"""


class TriageAgent:
    """AI agent for initial alert triage and classification."""

    async def triage(self, alert_id: str) -> dict:
        """
        Perform initial triage on an alert.

        Args:
            alert_id: Alert to triage.

        Returns:
            TriageResult dict with verdict, confidence, and initial MITRE mapping.
        """
        pass

    async def enrich_context(self, alert_id: str) -> dict:
        """
        Gather contextual data: user profile, asset info, recent activity.

        Args:
            alert_id: Alert to enrich.

        Returns:
            Context dict with user, asset, and behavioral data.
        """
        pass
