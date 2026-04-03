"""
SOCentinel — SOAR Suggester.
Loads playbook_actions.json, suggests actions based on alert category.
Forces tier 2 for CRITICAL assets.
"""

import json
import os


class SOARSuggester:
    """Suggest SOAR response actions from playbooks."""

    def __init__(self):
        path = os.path.join(os.path.dirname(__file__), "..", "data", "playbook_actions.json")
        with open(path, "r") as f:
            self.playbooks = json.load(f)

    def suggest(self, alert_category: str, asset_criticality: str) -> list:
        """
        Return action list for the category.
        If asset is CRITICAL, force all tiers to max(existing, 2).
        """
        playbook = self.playbooks.get(alert_category, {})
        actions = playbook.get("actions", [])

        result = []
        for action in actions:
            entry = dict(action)
            if asset_criticality == "CRITICAL":
                entry["tier"] = max(entry.get("tier", 0), 2)
            tier_labels = {0: "auto", 1: "one-click", 2: "mfa-required"}
            entry["tier_label"] = tier_labels.get(entry["tier"], "unknown")
            result.append(entry)

        return result
