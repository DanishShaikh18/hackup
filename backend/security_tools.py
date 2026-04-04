"""
SOCentinel — Deterministic Security Tools.
Pure Python logic: no guessing, no AI percentages.
Every score is a calculation. Every mapping is a dictionary lookup.
"""

from datetime import datetime
# Add this import at the top of security_tools.py
from thresholds import check_threshold, classify_alerts, get_threshold, ALERT_CATEGORIES

# ──────────────────────────────────────────────────────────────
# MITRE ATT&CK Mapping
# Pattern → (Technique ID, Technique Name, Kill Chain Stage, Weight)
# ──────────────────────────────────────────────────────────────

KILL_CHAIN_WEIGHTS = {
    "Reconnaissance": 1,
    "Weaponization": 2,
    "Delivery": 3,
    "Exploitation": 4,
    "Installation": 5,
    "Command & Control": 6,
    "Actions on Objectives": 7,
}

MITRE_MAPPING = {
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery",
        "kill_chain_stage": "Reconnaissance",
        "weight": KILL_CHAIN_WEIGHTS["Reconnaissance"],
    },
    "login_failed": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "kill_chain_stage": "Delivery",
        "weight": KILL_CHAIN_WEIGHTS["Delivery"],
    },
    "firewall_deny": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "kill_chain_stage": "Delivery",
        "weight": KILL_CHAIN_WEIGHTS["Delivery"],
    },
    "login_success_after_failures": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Persistence",
        "kill_chain_stage": "Exploitation",
        "weight": KILL_CHAIN_WEIGHTS["Exploitation"],
    },
    "data_exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "kill_chain_stage": "Actions on Objectives",
        "weight": KILL_CHAIN_WEIGHTS["Actions on Objectives"],
    },
}

# ──────────────────────────────────────────────────────────────
# Known Good Baselines (for False Positive Reduction)
# ──────────────────────────────────────────────────────────────

KNOWN_GOOD_IPS = ["10.0.0.50", "192.168.1.100", "10.0.0.1", "192.168.1.1"]
STANDARD_HOURS = (9, 18)  # 09:00 - 18:00


# ──────────────────────────────────────────────────────────────
# Core Functions
# ──────────────────────────────────────────────────────────────

def get_mitre_mapping(event_type: str) -> dict | None:
    """Lookup MITRE technique mapping for an event type."""
    return MITRE_MAPPING.get(event_type)


def calculate_risk_score(kill_chain_weight: int, confidence: float, asset_value: int) -> dict:
    """
    Deterministic risk scoring.

    Formula: score = (kill_chain_weight × confidence) + asset_value
    Normalized to 1–10 scale.

    Args:
        kill_chain_weight: Weight from Kill Chain stage (1-7).
        confidence: Confidence level (0.0 - 1.0).
        asset_value: Value of the target asset (1-5).

    Returns:
        Dict with score, formula_display, and breakdown.
    """
    raw_score = (kill_chain_weight * confidence) + asset_value
    # Normalize: max possible raw = (7 * 1.0) + 5 = 12, min = (1 * 0.1) + 1 = 1.1
    normalized = min(10, max(1, round(raw_score * 10 / 12, 1)))

    return {
        "score": normalized,
        "raw_score": round(raw_score, 2),
        "formula_display": f"({kill_chain_weight} × {confidence}) + {asset_value} = {round(raw_score, 2)}",
        "formula_normalized": f"Normalized {round(raw_score, 2)} → {normalized}/10",
        "breakdown": {
            "kill_chain_weight": kill_chain_weight,
            "confidence": confidence,
            "asset_value": asset_value,
        },
        "severity": _severity_label(normalized),
    }


def _severity_label(score: float) -> str:
    """Map score to severity label."""
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 4:
        return "Medium"
    elif score >= 2:
        return "Low"
    return "Informational"


def baseline_check(event: dict) -> dict:
    """
    Check if an event is a Likely False Positive.

    Rules:
    - If src_ip is in KNOWN_GOOD_IPS → likely FP.
    - If activity occurred during STANDARD_HOURS → less suspicious.
    - Combines both signals.

    Returns:
        { is_false_positive: bool, reason: str }
    """
    ip = ""
    if "src_endpoint" in event:
        ip = event["src_endpoint"].get("ip", "")
    elif "src_ip" in event:
        ip = event["src_ip"]

    timestamp_str = event.get("time", event.get("timestamp", ""))
    is_known_good_ip = ip in KNOWN_GOOD_IPS
    is_standard_hours = False

    if timestamp_str:
        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            is_standard_hours = STANDARD_HOURS[0] <= ts.hour < STANDARD_HOURS[1]
        except (ValueError, TypeError):
            pass

    reasons = []
    if is_known_good_ip:
        reasons.append(f"IP {ip} is in Known Good list")
    if is_standard_hours:
        reasons.append("Activity occurred during standard business hours (09:00–18:00)")

    is_fp = is_known_good_ip  # Known good IP is the strongest signal

    return {
        "is_false_positive": is_fp,
        "reason": "; ".join(reasons) if reasons else "No baseline match — activity is suspicious",
        "ip": ip,
        "is_known_good_ip": is_known_good_ip,
        "is_standard_hours": is_standard_hours,
    }


def correlate_logs(firewall_events: list[dict], auth_events: list[dict]) -> list[dict]:
    """
    Cross-source correlation: find IPs that appear in BOTH firewall and auth logs.

    Returns:
        List of { ip, firewall_evidence[], auth_evidence[], event_types[] }
    """
    # Collect IPs from firewall logs
    fw_by_ip: dict[str, list] = {}
    for event in firewall_events:
        ip = event.get("src_ip", "")
        if not ip:
            continue
        fw_by_ip.setdefault(ip, []).append(event)

    # Collect IPs from auth logs
    auth_by_ip: dict[str, list] = {}
    for event in auth_events:
        ip = event.get("src_ip", "")
        if not ip:
            continue
        auth_by_ip.setdefault(ip, []).append(event)

    # Find intersection
    correlated = []
    common_ips = set(fw_by_ip.keys()) & set(auth_by_ip.keys())

    for ip in common_ips:
        fw_events = fw_by_ip[ip]
        a_events = auth_by_ip[ip]

        # ── Observed measurements ────────────────────────────
        deny_count = sum(1 for e in fw_events if e.get("action") == "deny")
        fail_count = sum(1 for e in a_events if e.get("action") == "login_failed")
        success_count = sum(1 for e in a_events if e.get("action") == "login_success")
        total_bytes = sum(e.get("bytes_sent", 0) for e in fw_events)
        distinct_ports = len(set(e.get("dst_port", 0) for e in fw_events
                                  if e.get("action") == "deny"))

        # ── Threshold-based detection ────────────────────────
        # All thresholds sourced from thresholds.py with full derivation
        event_types = set()

        fw_deny_check = check_threshold("firewall_deny_count", deny_count)
        if fw_deny_check["exceeded"]:
            event_types.add("firewall_deny")

        port_scan_check = check_threshold("port_scan_distinct_ports", distinct_ports)
        if port_scan_check["exceeded"]:
            event_types.add("port_scan")

        brute_check = check_threshold("brute_force_login_failures", fail_count)
        if brute_check["exceeded"]:
            event_types.add("login_failed")

        # Exfil only fires when access was gained (success > 0) AND bytes exceed threshold
        exfil_check = check_threshold("exfiltration_bytes", total_bytes)
        if success_count > 0 and exfil_check["exceeded"]:
            event_types.add("data_exfiltration")

        # Compromise: success AFTER enough failures
        compromise_check = check_threshold(
            "success_after_failures_min_failures",
            fail_count if success_count > 0 else 0
        )
        if compromise_check["exceeded"]:
            event_types.add("login_success_after_failures")

        # ── Full alert classification ────────────────────────
        triggered_alerts = classify_alerts(
            deny_count=deny_count,
            fail_count=fail_count,
            success_count=success_count,
            bytes_transferred=total_bytes,
            distinct_ports=distinct_ports,
        )

        correlated.append({
            "ip": ip,
            "firewall_evidence": fw_events,
            "auth_evidence": a_events,
            "event_types": list(event_types),
            "firewall_deny_count": deny_count,
            "auth_fail_count": fail_count,
            "auth_success_count": success_count,
            "distinct_ports_scanned": distinct_ports,
            "total_bytes_transferred": total_bytes,
            "triggered_alerts": triggered_alerts,  # full classified alert list
        })

    return correlated


def analyze_threat(correlated_ip: dict, asset_value: int = 3) -> dict:
    """
    Full deterministic threat analysis for a single correlated IP.

    Returns:
        Complete analysis with risk score, MITRE mappings, kill chain,
        false positive check, and evidence.
    """
    event_types = correlated_ip.get("event_types", [])
    ip = correlated_ip["ip"]

    # Map all detected event types to MITRE
    mitre_techniques = []
    kill_chain_stages = []
    max_weight = 0

    for et in event_types:
        mapping = get_mitre_mapping(et)
        if mapping:
            mitre_techniques.append(mapping)
            stage = mapping["kill_chain_stage"]
            if stage not in kill_chain_stages:
                kill_chain_stages.append(stage)
            max_weight = max(max_weight, mapping["weight"])

    # Calculate confidence based on evidence volume
    fail_count = correlated_ip.get("auth_fail_count", 0)
    deny_count = correlated_ip.get("firewall_deny_count", 0)
    total_evidence = fail_count + deny_count
    confidence = min(1.0, round(total_evidence / 10, 2))  # 10 events = 100% confidence

    # Calculate risk score
    risk = calculate_risk_score(max_weight, confidence, asset_value)

    # Run false positive check on the IP
    fp_check = baseline_check({"src_ip": ip, "time": correlated_ip["firewall_evidence"][0].get("timestamp", "")})

    # Build ordered kill chain
    ordered_chain = []
    for stage_name in KILL_CHAIN_WEIGHTS:
        is_active = stage_name in kill_chain_stages
        techniques_in_stage = [
            m for m in mitre_techniques if m["kill_chain_stage"] == stage_name
        ]
        ordered_chain.append({
            "stage": stage_name,
            "weight": KILL_CHAIN_WEIGHTS[stage_name],
            "active": is_active,
            "techniques": techniques_in_stage,
        })

    return {
        "ip": ip,
        "risk_score": risk,
        "mitre_techniques": mitre_techniques,
        "kill_chain": ordered_chain,
        "false_positive_analysis": fp_check,
        "evidence_summary": {
            "firewall_deny_count": deny_count,
            "auth_fail_count": fail_count,
            "auth_success_count": correlated_ip.get("auth_success_count", 0),
            "total_evidence_points": total_evidence,
            "confidence": confidence,
            # NEW
            "distinct_ports_scanned": correlated_ip.get("distinct_ports_scanned", 0),
            "total_bytes_transferred": correlated_ip.get("total_bytes_transferred", 0),
        },
        # NEW: full threshold-based alert classification
        "triggered_alerts": correlated_ip.get("triggered_alerts", []),
    }