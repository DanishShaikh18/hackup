"""
SOCentinel — Timeline Builder.
Reconstructs attack timelines from log events with causal linking.
Produces ordered, annotated event sequences for visualization.
"""


class TimelineBuilder:
    """Build attack timelines from log events."""

    def build(self, alert_id: str, events: list) -> list:
        """
        Construct an ordered attack timeline.

        Args:
            alert_id: Alert to build timeline for.
            events: Associated log events.

        Returns:
            List of TimelineEvent dicts in chronological order.
        """
        pass

    def annotate(self, timeline: list) -> list:
        """
        Add MITRE ATT&CK annotations and anomaly flags to timeline events.

        Args:
            timeline: Raw timeline events.

        Returns:
            Annotated timeline events.
        """
        pass
