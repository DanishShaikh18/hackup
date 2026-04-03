"""
SOCentinel — Timeline Builder.
Builds ordered attack timelines from log events with ATT&CK annotations.
Detects gaps > 5 minutes between events.
"""

from datetime import datetime
from engines.attack_mapper import AttackMapper


class TimelineBuilder:
    """Build attack timelines from log events."""

    def __init__(self):
        self.mapper = AttackMapper()

    def build(self, log_events: list) -> list:
        """
        Build a chronological timeline with ATT&CK mapping and gap detection.

        Args:
            log_events: List of log event dicts from DB.

        Returns:
            Sorted list of timeline entry dicts.
        """
        # Sort by timestamp
        sorted_events = sorted(log_events, key=lambda e: e.get("timestamp", ""))

        timeline = []
        for event in sorted_events:
            technique = self.mapper.map_event(event.get("event_type", ""))
            timeline.append({
                "timestamp": event.get("timestamp", ""),
                "event_type": event.get("event_type", ""),
                "log_line_id": event.get("id", ""),
                "description": event.get("log_line", ""),
                "kill_chain_stage": technique.get("kill_chain_stage", "UNKNOWN"),
                "technique_id": technique.get("technique_id", ""),
                "technique_name": technique.get("technique_name", ""),
            })

        # Detect gaps > 5 minutes
        enriched = []
        for i, entry in enumerate(timeline):
            enriched.append(entry)
            if i < len(timeline) - 1:
                gap = self._gap_seconds(entry["timestamp"], timeline[i + 1]["timestamp"])
                if gap and gap > 300:
                    enriched.append({
                        "timestamp": entry["timestamp"],
                        "event_type": "gap",
                        "log_line_id": None,
                        "description": f"Gap detected ({gap // 60:.0f}m {gap % 60:.0f}s) — possible unlogged activity",
                        "kill_chain_stage": "UNKNOWN",
                        "technique_id": "",
                        "technique_name": "",
                    })

        return enriched

    def _gap_seconds(self, ts1: str, ts2: str) -> float | None:
        """Calculate seconds between two ISO timestamps."""
        try:
            t1 = datetime.fromisoformat(ts1.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(ts2.replace("Z", "+00:00"))
            return (t2 - t1).total_seconds()
        except (ValueError, TypeError):
            return None
