"""
SOCentinel — Responder Agent.
Generates response actions with autonomy tiers and CISO report.
"""

import json
from db import get_connection
from engines.soar_suggester import SOARSuggester
from autonomy.bounded_autonomy import BoundedAutonomy
from llm.groq_client import call_groq


class ResponderAgent:
    """AI agent for generating response actions."""

    def __init__(self):
        self.soar = SOARSuggester()
        self.autonomy = BoundedAutonomy()

    def run(self, alert_id: str, triage_result: dict, forensics_result: dict) -> dict:
        """
        Get SOAR suggestions, classify tiers, generate CISO report.
        """
        conn = get_connection()

        # Fetch asset
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        asset = None
        if alert and alert["asset_id"]:
            asset = conn.execute(
                "SELECT * FROM assets WHERE id = ?", (alert["asset_id"],)
            ).fetchone()
        conn.close()

        asset_dict = dict(asset) if asset else {}
        criticality = asset_dict.get("criticality", "MEDIUM")
        asset_type = asset_dict.get("asset_type", "unknown")

        # Get SOAR suggestions
        actions = self.soar.suggest("brute_force", criticality)

        # Classify each action via bounded autonomy
        confidence = triage_result.get("confidence", 0)
        for action in actions:
            tier = self.autonomy.classify(action["id"], asset_type, confidence)
            action["tier"] = tier
            tier_labels = {0: "auto", 1: "one-click", 2: "mfa-required"}
            action["tier_label"] = tier_labels.get(tier, "unknown")

        # Generate CISO report
        narrative = triage_result.get("narrative", "No narrative available")
        timeline_summary = json.dumps(
            forensics_result.get("timeline", [])[:5], default=str
        )
        ciso_prompt = (
            "You are a SOC analyst. Write a 150-word executive incident summary. "
            "Plain English. No markdown. No bullet points."
        )
        ciso_context = f"Narrative: {narrative}\nTimeline: {timeline_summary}"
        ciso_report = call_groq(ciso_prompt, ciso_context)

        return {
            "actions": actions,
            "ciso_report": ciso_report or "Report unavailable — Groq offline.",
            "confidence": confidence,
        }
