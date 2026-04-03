"""
SOCentinel — Log Parser.
Ingests multi-source JSON logs and converts them to OCSF-standard objects.
"""

import json
from pathlib import Path
from datetime import datetime


# OCSF Category / Class UIDs
OCSF_CATEGORY = {
    "network_activity": 4,     # Network Activity
    "iam": 3,                  # Identity & Access Management
}

OCSF_CLASS = {
    "firewall": 4001,          # Firewall Activity
    "authentication": 3002,    # Authentication
}

OCSF_ACTIVITY = {
    "allow": 1,
    "deny": 2,
    "login_success": 1,
    "login_failed": 2,
}

OCSF_SEVERITY = {
    "allow": 1,        # Informational
    "deny": 3,         # Medium
    "login_success": 1,  # Informational
    "login_failed": 3, # Medium
}


class LogParser:
    """Ingest JSON log files and produce OCSF-normalized events."""

    def ingest(self, filepath: str) -> list[dict]:
        """Read a JSON log file and return raw event dicts."""
        path = Path(filepath)
        if not path.exists():
            return []
        with open(path, "r") as f:
            return json.load(f)

    def to_ocsf(self, raw_event: dict, source_type: str) -> dict:
        """
        Convert a raw log event to an OCSF-standard object.

        Args:
            raw_event: The raw dict from the JSON file.
            source_type: Either 'firewall' or 'auth'.

        Returns:
            OCSF-normalized dict.
        """
        action = raw_event.get("action", "unknown")

        if source_type == "firewall":
            return {
                "class_uid": OCSF_CLASS["firewall"],
                "class_name": "Firewall Activity",
                "category_uid": OCSF_CATEGORY["network_activity"],
                "category_name": "Network Activity",
                "severity_id": OCSF_SEVERITY.get(action, 1),
                "activity_id": OCSF_ACTIVITY.get(action, 0),
                "activity_name": action.upper(),
                "time": raw_event.get("timestamp", ""),
                "src_endpoint": {
                    "ip": raw_event.get("src_ip", ""),
                    "port": raw_event.get("src_port", 0),
                },
                "dst_endpoint": {
                    "ip": raw_event.get("dst_ip", ""),
                    "port": raw_event.get("dst_port", 0),
                },
                "metadata": {
                    "original_id": raw_event.get("id", ""),
                    "source": "firewall",
                    "protocol": raw_event.get("protocol", ""),
                    "bytes_sent": raw_event.get("bytes_sent", 0),
                    "rule_id": raw_event.get("rule_id", ""),
                },
            }

        elif source_type == "auth":
            return {
                "class_uid": OCSF_CLASS["authentication"],
                "class_name": "Authentication",
                "category_uid": OCSF_CATEGORY["iam"],
                "category_name": "Identity & Access Management",
                "severity_id": OCSF_SEVERITY.get(action, 1),
                "activity_id": OCSF_ACTIVITY.get(action, 0),
                "activity_name": action.upper().replace("_", " "),
                "time": raw_event.get("timestamp", ""),
                "src_endpoint": {
                    "ip": raw_event.get("src_ip", ""),
                },
                "metadata": {
                    "original_id": raw_event.get("id", ""),
                    "source": "auth",
                    "user_id": raw_event.get("user_id", ""),
                    "method": raw_event.get("method", ""),
                    "user_agent": raw_event.get("user_agent", ""),
                    "geo_location": raw_event.get("geo_location", ""),
                },
            }

        return raw_event

    def ingest_and_normalize(self, filepath: str, source_type: str) -> list[dict]:
        """Ingest + normalize in one call."""
        raw_events = self.ingest(filepath)
        return [self.to_ocsf(e, source_type) for e in raw_events]

    def search(self, events: list[dict], **filters) -> list[dict]:
        """
        Filter events by field values.
        Supports top-level and nested 'metadata' fields.

        Example: search(events, action="login_failed", src_ip="203.0.113.45")
        """
        results = []
        for event in events:
            match = True
            for key, value in filters.items():
                # Check top-level fields
                event_val = event.get(key)
                # Check in src_endpoint
                if event_val is None and "src_endpoint" in event:
                    event_val = event["src_endpoint"].get(key)
                # Check in metadata
                if event_val is None and "metadata" in event:
                    event_val = event["metadata"].get(key)
                # Check activity_name (case-insensitive partial match)
                if event_val is None and key == "action":
                    event_val = event.get("activity_name", "").lower().replace(" ", "_")

                if event_val is None or str(event_val).lower() != str(value).lower():
                    match = False
                    break
            if match:
                results.append(event)
        return results
