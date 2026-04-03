"""
SOCentinel — Attack Mapper.
Maps event types to MITRE ATT&CK techniques using event_to_technique.json.
"""

import json
import os


class AttackMapper:
    """Map log event types to MITRE ATT&CK techniques."""

    def __init__(self):
        path = os.path.join(os.path.dirname(__file__), "..", "data", "event_to_technique.json")
        with open(path, "r") as f:
            self.technique_map = json.load(f)

    def map_event(self, event_type: str) -> dict:
        """
        Map a single event type to its ATT&CK technique.

        Returns technique dict or empty dict if no mapping.
        """
        return self.technique_map.get(event_type, {})
