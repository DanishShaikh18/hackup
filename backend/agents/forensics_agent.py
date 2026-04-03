"""
SOCentinel — Forensics Agent.
Deep investigation: timeline, ATT&CK mapping, hash checking.
"""

import json
from db import get_connection
from engines.timeline_builder import TimelineBuilder
from engines.attack_mapper import AttackMapper


class ForensicsAgent:
    """AI agent for deep forensic investigation."""

    def __init__(self):
        self.timeline_builder = TimelineBuilder()
        self.mapper = AttackMapper()

    def run(self, alert_id: str, triage_result: dict) -> dict:
        """
        Build timeline, map ATT&CK, check for file hashes.
        """
        conn = get_connection()
        events = conn.execute(
            "SELECT * FROM log_events WHERE alert_id = ? ORDER BY timestamp",
            (alert_id,),
        ).fetchall()
        events = [dict(e) for e in events]
        conn.close()

        # Build timeline
        timeline = self.timeline_builder.build(events)

        # Map ATT&CK techniques
        techniques = []
        kill_chain_stages = set()
        for event in events:
            mapping = self.mapper.map_event(event.get("event_type", ""))
            if mapping:
                techniques.append(mapping)
                kill_chain_stages.add(mapping.get("kill_chain_stage", ""))

        # Check for file hashes in metadata
        recursive_findings = []
        for event in events:
            meta = event.get("metadata")
            if meta:
                try:
                    meta_dict = json.loads(meta) if isinstance(meta, str) else meta
                    if meta_dict.get("file_hash"):
                        recursive_findings.append({
                            "log_id": event["id"],
                            "hash": meta_dict["file_hash"],
                            "recursive_check": "hash found — would scan all hosts in production",
                        })
                except (json.JSONDecodeError, TypeError):
                    pass

        return {
            "timeline": timeline,
            "kill_chain_stages": list(kill_chain_stages),
            "mitre_techniques": techniques,
            "recursive_findings": recursive_findings,
        }
