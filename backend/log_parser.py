"""
SOCentinel — Log Parser.
Ingests multi-source logs:
  - Structured JSON logs (existing)
  - Unstructured raw syslog/firewall text (NEW)
Converts everything to OCSF-standard objects.
"""

import json
import re
import uuid
from pathlib import Path
from datetime import datetime


# ── OCSF Constants (unchanged) ───────────────────────────────

OCSF_CATEGORY = {
    "network_activity": 4,
    "iam": 3,
}

OCSF_CLASS = {
    "firewall": 4001,
    "authentication": 3002,
}

OCSF_ACTIVITY = {
    "allow": 1,
    "deny": 2,
    "login_success": 1,
    "login_failed": 2,
}

OCSF_SEVERITY = {
    "allow": 1,
    "deny": 3,
    "login_success": 1,
    "login_failed": 3,
}


# ── Regex Patterns for Unstructured Logs ─────────────────────

# UFW/iptables firewall block/allow lines
# Example: Apr 03 02:14:33 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=1234 DPT=22 BYTES=60
FIREWALL_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"   # timestamp
    r"\S+\s+kernel:.*?\[UFW\s+(?P<action>BLOCK|ALLOW)\].*?"        # action
    r"SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+"                       # source IP
    r"DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+"                       # dest IP
    r"PROTO=(?P<protocol>\w+)\s+"                                   # protocol
    r"SPT=(?P<src_port>\d+)\s+"                                     # source port
    r"DPT=(?P<dst_port>\d+)"                                        # dest port
    r"(?:.*?BYTES?=(?P<bytes>\d+))?",                               # bytes (optional)
    re.IGNORECASE
)

# SSH auth lines — failed and accepted
# Example: Apr 03 02:15:10 sshd[1234]: Failed password for admin from 1.2.3.4 port 22 ssh2
# Example: Apr 03 02:17:20 sshd[1238]: Accepted password for admin from 1.2.3.4 port 22 ssh2
AUTH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"   # timestamp
    r"sshd\[\d+\]:\s+"                                              # process
    r"(?P<result>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+"       # result + method
    r"(?P<user>\S+)\s+from\s+"                                      # username
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+"                           # source IP
    r"port\s+(?P<port>\d+)",                                        # port
    re.IGNORECASE
)

# Month name → number mapping for timestamp parsing
MONTH_MAP = {
    "jan": "01", "feb": "02", "mar": "03", "apr": "04",
    "may": "05", "jun": "06", "jul": "07", "aug": "08",
    "sep": "09", "oct": "10", "nov": "11", "dec": "12",
}


class LogParser:
    """
    Ingest JSON or raw text log files and produce OCSF-normalized events.
    Auto-detects file type by extension.
    """

    # ── Public API ────────────────────────────────────────────

    def ingest(self, filepath: str) -> list[dict]:
        """
        Read a log file and return raw event dicts.
        Auto-detects JSON (.json) vs raw text (.log / .txt).
        """
        path = Path(filepath)
        if not path.exists():
            return []

        if path.suffix.lower() == ".json":
            return self._ingest_json(path)
        else:
            # Treat as raw unstructured text
            return self._ingest_raw(path)

    def to_ocsf(self, raw_event: dict, source_type: str) -> dict:
        """
        Convert a raw log event to an OCSF-standard object.
        Unchanged from original — works for both JSON-sourced and
        regex-parsed events since both produce the same dict shape.
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
                    "raw_source": raw_event.get("_raw_source", "json"),
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
                    "raw_source": raw_event.get("_raw_source", "json"),
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
        Supports top-level and nested metadata fields.
        Unchanged from original.
        """
        results = []
        for event in events:
            match = True
            for key, value in filters.items():
                event_val = event.get(key)
                if event_val is None and "src_endpoint" in event:
                    event_val = event["src_endpoint"].get(key)
                if event_val is None and "metadata" in event:
                    event_val = event["metadata"].get(key)
                if event_val is None and key == "action":
                    event_val = event.get("activity_name", "").lower().replace(" ", "_")
                if event_val is None or str(event_val).lower() != str(value).lower():
                    match = False
                    break
            if match:
                results.append(event)
        return results

    # ── Private: JSON ingestion (original logic) ──────────────

    def _ingest_json(self, path: Path) -> list[dict]:
        """Read a structured JSON log file."""
        with open(path, "r") as f:
            return json.load(f)

    # ── Private: Raw text ingestion (NEW) ─────────────────────

    def _ingest_raw(self, path: Path) -> list[dict]:
        """
        Parse an unstructured syslog/mixed text file.
        Each line is tested against firewall and auth regex patterns.
        Lines that match neither are recorded as unparsed (for auditability).
        Returns a flat list of normalized event dicts — same shape as JSON events.
        """
        events = []
        unparsed_count = 0

        with open(path, "r", errors="replace") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue

            # Try firewall pattern first
            fw_match = FIREWALL_PATTERN.search(line)
            if fw_match:
                event = self._parse_firewall_line(fw_match, line)
                events.append(event)
                continue

            # Try auth pattern
            auth_match = AUTH_PATTERN.search(line)
            if auth_match:
                event = self._parse_auth_line(auth_match, line)
                events.append(event)
                continue

            # Neither matched — log it for auditability
            unparsed_count += 1

        if unparsed_count:
            print(f"[LogParser] {unparsed_count} lines did not match any pattern in {path.name}")

        return events

    # ── Private: Line parsers ─────────────────────────────────

    def _parse_firewall_line(self, match: re.Match, raw_line: str) -> dict:
        """Convert a regex firewall match → structured event dict."""
        action_raw = match.group("action").upper()
        action = "allow" if action_raw == "ALLOW" else "deny"

        timestamp = self._build_timestamp(
            match.group("month"),
            match.group("day"),
            match.group("time"),
        )

        return {
            "id": f"raw-fw-{uuid.uuid4().hex[:8]}",
            "timestamp": timestamp,
            "src_ip": match.group("src_ip"),
            "dst_ip": match.group("dst_ip"),
            "src_port": int(match.group("src_port")),
            "dst_port": int(match.group("dst_port")),
            "protocol": match.group("protocol").upper(),
            "action": action,
            "bytes_sent": int(match.group("bytes") or 0),
            "rule_id": "RAW-SYSLOG",
            "_raw_source": "syslog",
            "_raw_line": raw_line,
            "_log_type": "firewall",
        }

    def _parse_auth_line(self, match: re.Match, raw_line: str) -> dict:
        """Convert a regex auth match → structured event dict."""
        result = match.group("result").lower()
        action = "login_success" if result == "accepted" else "login_failed"

        timestamp = self._build_timestamp(
            match.group("month"),
            match.group("day"),
            match.group("time"),
        )

        return {
            "id": f"raw-auth-{uuid.uuid4().hex[:8]}",
            "timestamp": timestamp,
            "src_ip": match.group("src_ip"),
            "user_id": match.group("user"),
            "action": action,
            "method": match.group("method"),
            "user_agent": "syslog",
            "geo_location": "",
            "_raw_source": "syslog",
            "_raw_line": raw_line,
            "_log_type": "auth",
        }

    def _build_timestamp(self, month: str, day: str, time_str: str) -> str:
        """
        Build ISO 8601 timestamp from syslog components.
        Syslog has no year — we assume current year.
        Example: 'Apr', '3', '02:14:33' → '2026-04-03T02:14:33Z'
        """
        year = datetime.now().year
        month_num = MONTH_MAP.get(month.lower()[:3], "01")
        day_padded = day.zfill(2)
        return f"{year}-{month_num}-{day_padded}T{time_str}Z"