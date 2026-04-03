"""
SOCentinel — SOAR Suggester.
Generates response action suggestions based on alert context and playbooks.
Loads actions from playbook_actions.json and assigns autonomy tiers.
"""

import json
import os

PLAYBOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "playbook_actions.json")


class SOARSuggester:
    """Suggest SOAR response actions from playbooks."""

    def __init__(self):
        self.playbooks = {}

    def load_playbooks(self):
        """Load playbook action definitions from JSON."""
        pass

    def suggest(self, alert_id: str, attack_type: str, context: dict) -> list:
        """
        Suggest response actions for an alert.

        Args:
            alert_id: Alert being responded to.
            attack_type: Detected attack type (e.g. 'brute_force').
            context: Investigation context.

        Returns:
            List of ActionSuggestion dicts.
        """
        pass
