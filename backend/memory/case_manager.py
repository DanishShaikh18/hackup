"""
SOCentinel — Case Manager.
CRUD for investigation cases. Generates CISO reports via Groq.
"""

import json
import uuid
from datetime import datetime
from db import get_connection
from memory.investigation_memory import InvestigationMemory
from llm.groq_client import call_groq


class CaseManager:
    """Manage investigation case lifecycle."""

    def __init__(self):
        self.memory = InvestigationMemory()

    def create_case(self, title: str, linked_alert_ids: list = None) -> str:
        """Create a new case, optionally link alerts. Returns case ID."""
        case_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO cases (id, title, status, severity, created_at) VALUES (?, ?, ?, ?, ?)",
            (case_id, title, "open", "HIGH", datetime.utcnow().isoformat() + "Z"),
        )
        if linked_alert_ids:
            meta = json.dumps({"linked_alerts": linked_alert_ids})
            cursor.execute("UPDATE cases SET metadata = ? WHERE id = ?", (meta, case_id))
        conn.commit()
        conn.close()
        return case_id

    def get_case(self, case_id: str) -> dict:
        """Get case by ID."""
        conn = get_connection()
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        conn.close()
        return dict(row) if row else {}

    def list_cases(self) -> list:
        """List all cases."""
        conn = get_connection()
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def add_note(self, case_id: str, note: str):
        """Append analyst note to case."""
        conn = get_connection()
        existing = conn.execute(
            "SELECT analyst_notes FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if existing:
            current = existing["analyst_notes"] or ""
            ts = datetime.utcnow().strftime("%H:%M:%S")
            updated = f"{current}\n[{ts}] {note}" if current else f"[{ts}] {note}"
            conn.execute(
                "UPDATE cases SET analyst_notes = ? WHERE id = ?", (updated, case_id)
            )
            conn.commit()
        conn.close()

    def link_alert(self, case_id: str, alert_id: str):
        """Link an alert to a case via metadata."""
        conn = get_connection()
        row = conn.execute("SELECT metadata FROM cases WHERE id = ?", (case_id,)).fetchone()
        meta = json.loads(row["metadata"]) if row and row["metadata"] else {}
        alerts = meta.get("linked_alerts", [])
        if alert_id not in alerts:
            alerts.append(alert_id)
        meta["linked_alerts"] = alerts
        conn.execute("UPDATE cases SET metadata = ? WHERE id = ?", (json.dumps(meta), case_id))
        conn.commit()
        conn.close()

    def close_case(self, case_id: str, outcome: str, resolution: str):
        """Close case and store to investigation memory."""
        conn = get_connection()
        now = datetime.utcnow().isoformat() + "Z"
        case = dict(conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone())
        created = case.get("created_at", now)
        try:
            t1 = datetime.fromisoformat(created.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(now.replace("Z", "+00:00"))
            minutes = int((t2 - t1).total_seconds() / 60)
        except Exception:
            minutes = 0

        is_tp = 1 if outcome == "true_positive" else 0
        conn.execute(
            """UPDATE cases SET status = 'closed', closed_at = ?, resolution = ?,
               resolution_time_minutes = ?, is_true_positive = ? WHERE id = ?""",
            (now, resolution, minutes, is_tp, case_id),
        )
        conn.commit()
        conn.close()

        # Store to vector memory
        techniques = json.loads(case.get("mitre_techniques", "[]") or "[]")
        self.memory.store(
            case_id=case_id,
            alert_category=case.get("attack_type", "unknown"),
            mitre_techniques=techniques,
            outcome=outcome,
            resolution=resolution,
            lessons=resolution,
        )

    def generate_ciso_report(self, case_id: str) -> str:
        """Generate executive incident report via Groq."""
        case = self.get_case(case_id)
        if not case:
            return "Case not found."
        prompt = (
            "You are a SOC analyst. Write a 200-word executive incident report "
            "for this case data. Plain English. No markdown."
        )
        result = call_groq(prompt, json.dumps(case, default=str))
        return result or "Report generation failed — Groq unavailable."
