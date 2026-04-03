"""
SOCentinel — Orchestrator Agent.
LangGraph state machine that coordinates triage → forensics → response flow.
Routes alerts through the agent pipeline based on severity and context.
"""


class OrchestratorAgent:
    """Main agent that coordinates the triage-forensics-response pipeline."""

    def __init__(self):
        self.graph = None  # LangGraph StateGraph, built in Phase 2

    async def build_graph(self):
        """Build the LangGraph state machine for alert processing."""
        pass

    async def process_alert(self, alert_id: str) -> dict:
        """
        Run full agent pipeline on an alert.

        Args:
            alert_id: The alert to process.

        Returns:
            dict with triage result, timeline, attack map, and action suggestions.
        """
        pass
