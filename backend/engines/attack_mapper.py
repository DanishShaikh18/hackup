"""
SOCentinel — Attack Mapper.
Maps log events to MITRE ATT&CK techniques and builds kill chain visualization data.
Uses event_to_technique.json for deterministic mapping.
"""

import json
import os

TECHNIQUE_MAP_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "event_to_technique.json")


class AttackMapper:
    """Map events to MITRE ATT&CK techniques."""

    def __init__(self):
        self.technique_map = {}

    def load_mappings(self):
        """Load event-to-technique mappings from JSON."""
        pass

    def map_events(self, events: list) -> list:
        """
        Map a list of events to MITRE ATT&CK techniques.

        Args:
            events: List of log event dicts.

        Returns:
            List of dicts with event_id, technique_id, technique_name, tactic, kill_chain_stage.
        """
        pass

    def get_kill_chain(self, mappings: list) -> dict:
        """
        Build kill chain visualization data from technique mappings.

        Args:
            mappings: Output from map_events().

        Returns:
            Kill chain dict grouped by stage.
        """
        pass
