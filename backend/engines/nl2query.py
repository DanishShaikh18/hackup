"""
SOCentinel — Hybrid NL2Query.
Rule-based first, LLM fallback using Groq.
Safe SQL validation included.
"""

import re
import json
import sqlite3
from db import get_connection
from llm.groq_client import call_groq


# Allowed tables for security
ALLOWED_TABLES = {
    "alerts",
    "log_events",
    "users",
    "assets"
}


class NL2Query:
    """Convert natural language to SQL queries."""

    def query(self, nl_text: str) -> dict:

        text = nl_text.lower().strip()
        conn = get_connection()
        cursor = conn.cursor()

        try:

            # -----------------------------
            # 1) RULE-BASED QUICK MATCHES
            # -----------------------------

            if "failed login" in text or "login fail" in text:

                sql = """
                SELECT *
                FROM log_events
                WHERE event_type = ?
                ORDER BY timestamp DESC
                """

                params = ("login_fail",)

                cursor.execute(sql, params)

                rows = [dict(r) for r in cursor.fetchall()]

                return {
                    "source": "rule",
                    "query": sql,
                    "results": rows,
                    "interpretation": f"Found {len(rows)} failed login events"
                }

            elif "activity for" in text:

                match = re.search(r"activity for\s+(\S+)", text)

                username = match.group(1) if match else ""

                sql = """
                SELECT *
                FROM log_events
                WHERE username = ?
                ORDER BY timestamp DESC
                """

                cursor.execute(sql, (username,))

                rows = [dict(r) for r in cursor.fetchall()]

                return {
                    "source": "rule",
                    "query": sql,
                    "results": rows,
                    "interpretation": f"Found {len(rows)} events for user {username}"
                }

            # -----------------------------
            # 2) LLM FALLBACK
            # -----------------------------

            sql = self.generate_sql_with_groq(text)

            if not self.is_safe_sql(sql):

                return {
                    "error": "Unsafe query blocked",
                    "generated_sql": sql
                }

            cursor.execute(sql)

            rows = [dict(r) for r in cursor.fetchall()]

            return {
                "source": "llm",
                "query": sql,
                "results": rows,
                "interpretation": f"Found {len(rows)} records"
            }

        finally:
            conn.close()

    # -----------------------------
    # LLM SQL GENERATION
    # -----------------------------

    def generate_sql_with_groq(self, text: str) -> str:

        schema = """
Tables:

alerts(
    id,
    timestamp,
    severity,
    src_ip,
    user_id,
    hostname,
    status
)

log_events(
    id,
    timestamp,
    username,
    event_type,
    src_ip,
    hostname
)

users(
    username,
    role,
    department
)

assets(
    id,
    hostname,
    criticality
)
"""

        prompt = f"""
You are a SQL generator.

Convert the user request into a SQLite SELECT query.

Rules:

- Only generate SELECT statements
- Use only provided tables
- Never use DELETE, UPDATE, INSERT, DROP
- Limit results to 50 rows
- Return SQL only

Schema:

{schema}

User request:

{text}
"""

        sql = call_groq(prompt)

        return sql.strip()

    # -----------------------------
    # SQL SAFETY CHECK
    # -----------------------------

    def is_safe_sql(self, sql: str) -> bool:

        sql_upper = sql.upper()

        if not sql_upper.startswith("SELECT"):
            return False

        dangerous = [
            "DROP",
            "DELETE",
            "UPDATE",
            "INSERT",
            "ALTER",
            "TRUNCATE"
        ]

        for word in dangerous:
            if word in sql_upper:
                return False

        for table in ALLOWED_TABLES:
            if table in sql:
                return True

        return False