"""
SOCentinel — Session Detector.
Detects anomalous sessions by comparing current behavior to user baselines.
Flags: unusual hours, unusual IPs, unusual access patterns.
"""


class SessionDetector:
    """Detect anomalous user sessions based on behavioral baselines."""

    def detect_anomalies(self, user_id: str, events: list) -> list:
        """
        Compare session events against user's typical behavior.

        Args:
            user_id: User to check.
            events: List of session events.

        Returns:
            List of anomaly dicts (type, severity, description).
        """
        pass

    def get_baseline(self, user_id: str) -> dict:
        """
        Get the behavioral baseline for a user.

        Args:
            user_id: User to look up.

        Returns:
            Baseline dict with typical hours, IPs, access patterns.
        """
        pass
