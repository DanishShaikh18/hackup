"""
SOCentinel — Responder Agent.
Generates response actions, enforces bounded autonomy tiers,
and manages action execution with human oversight.
"""


class ResponderAgent:
    """AI agent for generating and managing response actions."""

    async def suggest_actions(self, alert_id: str, investigation: dict) -> list:
        """
        Generate response action suggestions based on investigation findings.

        Args:
            alert_id: Alert being responded to.
            investigation: Output from forensics agent.

        Returns:
            List of ActionSuggestion dicts with autonomy tiers.
        """
        pass

    async def execute_action(self, action_id: str, approval: dict) -> dict:
        """
        Execute an approved action.

        Args:
            action_id: Action to execute.
            approval: Approval details (tier confirmation, MFA if needed).

        Returns:
            Execution result dict.
        """
        pass
