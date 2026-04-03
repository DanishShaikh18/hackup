"""
SOCentinel — Case Manager.
CRUD operations for investigation cases.
Manages case lifecycle: create → investigate → resolve → close.
"""


class CaseManager:
    """Manage investigation case lifecycle."""

    def create_case(self, title: str, severity: str, alert_ids: list = None) -> dict:
        """
        Create a new investigation case.

        Args:
            title: Case title.
            severity: Case severity.
            alert_ids: Initial alert IDs to attach.

        Returns:
            Created case dict.
        """
        pass

    def get_case(self, case_id: str) -> dict:
        """Get case by ID."""
        pass

    def list_cases(self, status: str = None) -> list:
        """List all cases, optionally filtered by status."""
        pass

    def add_alert(self, case_id: str, alert_id: str) -> dict:
        """Attach an alert to a case."""
        pass

    def add_note(self, case_id: str, note: str) -> dict:
        """Add analyst notes to a case."""
        pass

    def close_case(self, case_id: str, resolution: str, is_true_positive: bool) -> dict:
        """Close a case with resolution details."""
        pass

    def generate_ciso_report(self, case_id: str) -> dict:
        """Generate executive summary report for CISO."""
        pass
