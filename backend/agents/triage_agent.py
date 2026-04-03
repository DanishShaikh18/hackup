"""
SOCentinel — Triage Agent.
Main agent that fetches context, calls Groq, validates output.
"""

import json
from db import get_connection
from llm.groq_client import call_groq
from safety.output_enforcer import OutputEnforcer
from safety.grounding_validator import GroundingValidator
from memory.investigation_memory import InvestigationMemory

TRIAGE_SYSTEM_PROMPT = """You are a senior SOC analyst. Analyze the security alert context and return ONLY valid JSON matching this schema exactly:
{
  "narrative": "2-3 sentence plain English explanation of what happened",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": <integer 0-100>,
  "evidence_for_threat": [{"text": "...", "citation_log_id": "LOG-XXXX-X"}],
  "evidence_against_threat": [{"text": "...", "citation_log_id": null}],
  "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "stage": "Initial Access"}],
  "recommended_actions": [{"action": "...", "tier": 0, "priority": 1, "reason": "...", "risk": "..."}],
  "analyst_note": "single most important thing for analyst to know"
}
Rules: Only reference log_line_ids from the context. If evidence is ambiguous say so. Return ONLY JSON, no markdown, no preamble."""


class TriageAgent:
    """AI agent for initial alert triage and classification."""

    def __init__(self):
        self.enforcer = OutputEnforcer()
        self.grounding = GroundingValidator()
        self.memory = InvestigationMemory()

    def run(self, alert_id: str) -> dict:
        """Run full triage: fetch context → call Groq → validate → return."""
        conn = get_connection()

        # Fetch alert
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not alert:
            conn.close()
            return {"error": f"Alert {alert_id} not found"}
        alert = dict(alert)

        # Fetch user profile
        user = None
        if alert.get("username"):
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (alert["username"],)
            ).fetchone()
            user = dict(row) if row else None

        # Fetch asset
        asset = None
        if alert.get("asset_id"):
            row = conn.execute(
                "SELECT * FROM assets WHERE id = ?", (alert["asset_id"],)
            ).fetchone()
            asset = dict(row) if row else None

        # Fetch log events
        events = conn.execute(
            "SELECT * FROM log_events WHERE alert_id = ? ORDER BY timestamp",
            (alert_id,),
        ).fetchall()
        events = [dict(e) for e in events]
        conn.close()

        # Get known log IDs for grounding
        known_log_ids = [e["id"] for e in events]

        # Search similar past cases
        techniques = []
        if alert.get("rule_name"):
            techniques = [alert["rule_name"]]
        similar = self.memory.search_similar(
            alert_category=alert.get("rule_name", "unknown"),
            mitre_techniques=techniques,
        )

        # Build context for LLM
        context = {
            "alert": alert,
            "user_profile": user,
            "asset": asset,
            "log_events": events,
            "known_log_ids": known_log_ids,
            "similar_past_cases": similar,
        }

        # Call Groq
        raw_response = call_groq(TRIAGE_SYSTEM_PROMPT, json.dumps(context, default=str))

        # Parse and validate
        result = self.enforcer.enforce(raw_response)
        result = self.grounding.validate(result, known_log_ids)
        result["alert_id"] = alert_id

        return result
