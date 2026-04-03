"""
SOCentinel — NL2Query (Natural Language to Query).
Converts analyst natural language questions into structured DB queries.
Example: "Show me all failed logins from Tor IPs" → SQL query.
"""


class NL2Query:
    """Convert natural language to structured queries."""

    async def translate(self, question: str) -> dict:
        """
        Convert a natural language question to a SQL query.

        Args:
            question: Analyst's natural language question.

        Returns:
            dict with 'sql' (str), 'explanation' (str), 'params' (list).
        """
        pass

    def execute_safe(self, sql: str, params: list = None) -> list:
        """
        Execute a read-only SQL query safely.

        Args:
            sql: SQL query (must be SELECT only).
            params: Query parameters.

        Returns:
            List of result dicts.
        """
        pass
