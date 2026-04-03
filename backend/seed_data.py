"""
SOCentinel — Seed data for demo scenarios.
Seeds Scenario A (credential stuffing) fully into the SQLite DB.
Run: python seed_data.py
"""

import json
from db import init_db, get_connection


def seed_scenario_a():
    """Seed the primary credential stuffing demo scenario."""
    conn = get_connection()
    cursor = conn.cursor()

    # --- User: j.morrison ---
    cursor.execute("""
        INSERT OR REPLACE INTO users (id, username, full_name, department, role, is_privileged, typical_hours, typical_ips, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "USR-001",
        "j.morrison",
        "James Morrison",
        "Finance",
        "Finance Director",
        1,
        "08:00-18:00",
        json.dumps(["10.0.1.45"]),
        0.0
    ))

    # --- Asset: FS-FINANCE-01 ---
    cursor.execute("""
        INSERT OR REPLACE INTO assets (id, hostname, asset_type, criticality, owner, ip_address, autonomy_tier)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        "FS-FINANCE-01",
        "FS-FINANCE-01",
        "file_server",
        "CRITICAL",
        "j.morrison",
        "10.0.1.100",
        2
    ))

    # --- Alert: ALERT-2024-0094 ---
    cursor.execute("""
        INSERT OR REPLACE INTO alerts (id, title, severity, status, rule_name, src_ip, dst_ip, username, asset_id, timestamp, raw_log, ocsf_category)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "ALERT-2024-0094",
        "Brute Force Authentication Attempt Detected",
        "HIGH",
        "open",
        "brute_force_login",
        "185.220.101.47",
        "10.0.1.100",
        "j.morrison",
        "FS-FINANCE-01",
        "2024-11-15T02:28:31Z",
        "Multiple failed login attempts from 185.220.101.47 targeting j.morrison",
        "authentication"
    ))

    # --- Log Events ---
    log_events = [
        (
            "LOG-0091-A",
            "ALERT-2024-0094",
            "2024-11-15T02:28:31Z",
            "login_fail",
            "185.220.101.47",
            "10.0.1.100",
            "j.morrison",
            "FS-FINANCE-01",
            "47 failed login attempts for user j.morrison from 185.220.101.47 within 3 minutes",
            json.dumps({"ocsf_class": "authentication", "activity_id": 1, "status": "failure", "count": 47}),
            json.dumps({"attempt_count": 47, "time_window_sec": 180, "geo": "Tor Exit Node"})
        ),
        (
            "LOG-0094-B",
            "ALERT-2024-0094",
            "2024-11-15T02:31:47Z",
            "login_success",
            "185.220.101.47",
            "10.0.1.100",
            "j.morrison",
            "FS-FINANCE-01",
            "Successful login for j.morrison from 185.220.101.47 after 47 failed attempts",
            json.dumps({"ocsf_class": "authentication", "activity_id": 1, "status": "success"}),
            json.dumps({"after_failures": 47, "geo": "Tor Exit Node", "time_since_last_fail_sec": 196})
        ),
        (
            "LOG-0094-C",
            "ALERT-2024-0094",
            "2024-11-15T02:33:12Z",
            "file_access",
            "185.220.101.47",
            "10.0.1.100",
            "j.morrison",
            "FS-FINANCE-01",
            "File access by j.morrison to /finance/payroll/ from 185.220.101.47",
            json.dumps({"ocsf_class": "file_activity", "activity_id": 1, "path": "/finance/payroll/"}),
            json.dumps({"path": "/finance/payroll/", "action": "list_directory"})
        ),
        (
            "LOG-0094-D",
            "ALERT-2024-0094",
            "2024-11-15T02:35:03Z",
            "file_download",
            "185.220.101.47",
            "10.0.1.100",
            "j.morrison",
            "FS-FINANCE-01",
            "File download: Q3_payroll_export.xlsx (4.2 MB) by j.morrison from 185.220.101.47",
            json.dumps({"ocsf_class": "file_activity", "activity_id": 2, "file_name": "Q3_payroll_export.xlsx", "size_mb": 4.2}),
            json.dumps({"filename": "Q3_payroll_export.xlsx", "size_mb": 4.2, "path": "/finance/payroll/Q3_payroll_export.xlsx"})
        ),
        (
            "LOG-0094-E",
            "ALERT-2024-0094",
            "2024-11-15T02:38:41Z",
            "access_denied",
            "185.220.101.47",
            "10.0.1.100",
            "j.morrison",
            "FS-FINANCE-01",
            "Access denied for j.morrison to /exec/board-reports/ from 185.220.101.47",
            json.dumps({"ocsf_class": "file_activity", "activity_id": 1, "status": "denied", "path": "/exec/board-reports/"}),
            json.dumps({"path": "/exec/board-reports/", "action": "list_directory", "result": "access_denied"})
        ),
    ]

    cursor.executemany("""
        INSERT OR REPLACE INTO log_events (id, alert_id, timestamp, event_type, src_ip, dst_ip, username, asset_id, log_line, ocsf_json, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, log_events)

    # --- Closed past case for investigation memory demo ---
    cursor.execute("""
        INSERT OR REPLACE INTO cases (id, title, status, severity, analyst_notes, created_at, closed_at, resolution, resolution_time_minutes, is_true_positive, attack_type, mitre_techniques)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "INC-0047",
        "Credential Stuffing — Finance Portal",
        "closed",
        "HIGH",
        "Confirmed credential stuffing from Tor exit node. Attacker used breached credentials to access finance share. Account locked, IP blocked, password reset enforced.",
        "2024-10-02T14:22:00Z",
        "2024-10-02T16:36:00Z",
        "True positive. Attacker accessed finance fileshare using breached credentials from Tor exit node. Contained within 2h 14min. No data exfiltration confirmed.",
        134,
        1,
        "credential_stuffing",
        json.dumps(["T1110.004", "T1078", "T1083"])
    ))

    # --- Investigation memory for the closed case ---
    cursor.execute("""
        INSERT OR REPLACE INTO investigation_memory (case_id, alert_id, finding, evidence_refs, confidence)
        VALUES (?, ?, ?, ?, ?)
    """, (
        "INC-0047",
        None,
        "Credential stuffing attack from Tor exit node targeting finance accounts. Pattern: brute force → successful auth → lateral file access. Resolved by account lock + IP block.",
        json.dumps(["LOG-0047-A", "LOG-0047-B", "LOG-0047-C"]),
        0.95
    ))

    conn.commit()
    conn.close()
    print("[seed] Scenario A (credential stuffing) seeded successfully.")
    print("[seed] Closed case INC-0047 seeded for investigation memory demo.")


if __name__ == "__main__":
    init_db()
    seed_scenario_a()
    print("[seed] All seed data loaded. Database ready for Phase 2.")
