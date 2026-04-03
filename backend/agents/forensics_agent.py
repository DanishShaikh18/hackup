"""
SOCentinel — Forensics Agent.
Deep-dive investigation: timeline reconstruction, lateral movement detection,
data exfiltration analysis, and IOC extraction.
"""


class ForensicsAgent:
    """AI agent for deep forensic investigation."""

    async def investigate(self, alert_id: str, triage_result: dict) -> dict:
        """
        Perform deep forensic analysis based on triage results.

        Args:
            alert_id: Alert to investigate.
            triage_result: Output from triage agent.

        Returns:
            dict with timeline, attack_map, iocs, and forensic findings.
        """
        pass

    async def extract_iocs(self, log_events: list) -> list:
        """
        Extract Indicators of Compromise from log events.

        Args:
            log_events: List of log event dicts.

        Returns:
            List of IOC dicts (type, value, confidence).
        """
        pass
