"""
SOCentinel — NL2Query.
Converts natural language questions to sqlite3 queries using keyword matching.
No LLM needed — simple intent classification.
"""

import re
import sqlite3
from db import get_connection


class NL2Query:
    """Convert natural language to structured DB queries."""

    def query(self, nl_text: str) -> dict:
        """
        Parse natural language, build SQL, execute, return results + interpretation.
        """
        text = nl_text.lower().strip()
        conn = get_connection()
        cursor = conn.cursor()

        try:
            if "failed login" in text or "login fail" in text:
                cursor.execute(
                    "SELECT * FROM log_events WHERE event_type = ? ORDER BY timestamp DESC",
                    ("login_fail",),
                )
                rows = [dict(r) for r in cursor.fetchall()]
                interp = f"Found {len(rows)} failed login events"

            elif "activity for" in text:
                match = re.search(r"activity for\s+(\S+)", text)
                username = match.group(1) if match else ""
                cursor.execute(
                    "SELECT * FROM log_events WHERE username = ? ORDER BY timestamp DESC",
                    (username,),
                )
                rows = [dict(r) for r in cursor.fetchall()]
                interp = f"Found {len(rows)} events for user {username}"

            elif "alerts" in text and ("today" in text or "this week" in text):
                cursor.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50"
                )
                rows = [dict(r) for r in cursor.fetchall()]
                interp = f"Found {len(rows)} recent alerts"

            elif "ip" in text:
                cursor.execute(
                    "SELECT src_ip, COUNT(*) as count FROM alerts GROUP BY src_ip ORDER BY count DESC"
                )
                rows = [dict(r) for r in cursor.fetchall()]
                interp = f"Found {len(rows)} unique source IPs in alerts"

            else:
                cursor.execute(
                    "SELECT * FROM log_events ORDER BY timestamp DESC LIMIT 20"
                )
                rows = [dict(r) for r in cursor.fetchall()]
                interp = f"Showing {len(rows)} most recent log events"

            return {"results": rows, "interpretation": interp}

        finally:
            conn.close()
