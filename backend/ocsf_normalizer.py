"""
SOCentinel — OCSF Normalizer.
Converts raw log lines/dicts into OCSF-compliant normalized event dicts.
Phase 2 will implement full normalization logic.
"""


def normalize_to_ocsf(raw_event: dict) -> dict:
    """
    Convert a raw log event dict into an OCSF-normalized dict.

    Args:
        raw_event: Raw event dict with at minimum 'event_type' and 'timestamp'.

    Returns:
        OCSF-normalized event dict.
    """
    pass


def detect_ocsf_category(event_type: str) -> str:
    """
    Map an event type string to its OCSF category.

    Args:
        event_type: e.g. 'login_fail', 'file_access', 'process_exec'

    Returns:
        OCSF category string (e.g. 'authentication', 'file_activity')
    """
    pass
