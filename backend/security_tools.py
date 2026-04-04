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
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "kill_chain_stage": "Reconnaissance",
        "weight": KILL_CHAIN_WEIGHTS["Reconnaissance"],
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
    "password_spraying": {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "kill_chain_stage": "Delivery",
        "weight": KILL_CHAIN_WEIGHTS["Delivery"],
    },
    "unknown_heuristic": {
        "technique_id": "T1unknown",
        "technique_name": "Heuristic/Unknown Behavior",
        "tactic": "Unknown",
        "kill_chain_stage": "Reconnaissance",
        "weight": KILL_CHAIN_WEIGHTS["Reconnaissance"],
    },
}

# ──────────────────────────────────────────────────────────────
# Known Good Baselines (for False Positive Reduction)
# ──────────────────────────────────────────────────────────────

KNOWN_GOOD_IPS = ["10.0.0.50", "192.168.1.100", "10.0.0.1", "192.168.1.1"]
STANDARD_HOURS = (9, 18)  # 09:00 - 18:00
TOR_GEOLOCATIONS = ["Tor Exit Node", "Unknown", "Anonymous Proxy"]
OFFICE_GEOLOCATIONS = ["Office", "HQ", "Corporate", "Internal"]


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


def baseline_check(event: dict, correlated_ip: dict | None = None) -> dict:
    """
    Three-Gate False Positive Triage.

    Gate 1 — IP Reputation (Known-Good Whitelist)
    Gate 2 — User & Time Baseline
    Gate 3 — Cross-Telemetry Validation

    Decision: Only FP if known-good IP AND no threat signals AND single telemetry source.
    Any strong threat signal (Tor, multi-user targeting, off-hours + cross-telemetry) → NOT FP.

    Returns:
        Dict with is_false_positive, reason, gate_results, fp_signals, threat_signals, confidence.
    """
    ip = ""
    if "src_endpoint" in event:
        ip = event["src_endpoint"].get("ip", "")
    elif "src_ip" in event:
        ip = event["src_ip"]

    fp_signals = []
    threat_signals = []

    # ── Gate 1: IP Reputation ─────────────────────────────────
    is_known_good = ip in KNOWN_GOOD_IPS
    gate1 = {"ip": ip, "is_known_good": is_known_good}
    if is_known_good:
        fp_signals.append(f"IP {ip} is in Known Good list")

    # ── Gate 2: User & Time Baseline ──────────────────────────
    timestamp_str = event.get("time", event.get("timestamp", ""))
    is_standard_hours = False
    is_off_hours = False

    if timestamp_str:
        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            is_standard_hours = STANDARD_HOURS[0] <= ts.hour < STANDARD_HOURS[1]
            is_off_hours = not is_standard_hours
        except (ValueError, TypeError):
            pass

    if is_standard_hours:
        fp_signals.append("Activity during standard business hours (09:00–18:00)")
    if is_off_hours:
        threat_signals.append("Activity outside business hours")

    # Geo-location check from correlated auth evidence
    geo_locations = set()
    if correlated_ip:
        for e in correlated_ip.get("auth_evidence", []):
            geo = e.get("geo_location", "")
            if geo:
                geo_locations.add(geo)

    is_tor = any(g in TOR_GEOLOCATIONS for g in geo_locations)
    is_office = any(g in OFFICE_GEOLOCATIONS for g in geo_locations)

    if is_tor:
        threat_signals.append(f"Geo-location from Tor/Unknown: {geo_locations}")
    if is_office:
        fp_signals.append(f"Geo-location from Office/Corporate: {geo_locations}")

    gate2 = {
        "is_standard_hours": is_standard_hours,
        "is_off_hours": is_off_hours,
        "geo_locations": list(geo_locations),
        "is_tor": is_tor,
        "is_office": is_office,
    }

    # ── Gate 3: Cross-Telemetry Validation ────────────────────
    in_firewall = False
    in_auth = False
    multi_user_targeted = False
    unique_users_attacked = 0

    if correlated_ip:
        in_firewall = len(correlated_ip.get("firewall_evidence", [])) > 0
        in_auth = len(correlated_ip.get("auth_evidence", [])) > 0

        unique_users_attacked = len(set(
            e.get("user_id") for e in correlated_ip.get("auth_evidence", [])
            if e.get("action") == "login_failed" and e.get("user_id")
        ))
        multi_user_targeted = unique_users_attacked >= 2

    cross_telemetry = in_firewall and in_auth
    single_source = not cross_telemetry

    if cross_telemetry:
        threat_signals.append("IP appears in BOTH firewall AND auth logs — confirmed cross-telemetry")
    else:
        fp_signals.append("IP appears in only one log source — weak signal")

    if multi_user_targeted:
        threat_signals.append(f"Multiple users targeted ({unique_users_attacked}) — spray attack pattern")

    gate3 = {
        "in_firewall": in_firewall,
        "in_auth": in_auth,
        "cross_telemetry": cross_telemetry,
        "unique_users_attacked": unique_users_attacked,
        "multi_user_targeted": multi_user_targeted,
    }

    # ── Decision Logic ────────────────────────────────────────
    # Strong threat signals override everything
    has_strong_threat = is_tor or multi_user_targeted or (is_off_hours and cross_telemetry)

    if has_strong_threat:
        is_fp = False
        confidence = "High"
    elif is_known_good and not threat_signals and single_source:
        is_fp = True
        confidence = "High"
    elif is_known_good and not threat_signals:
        is_fp = True
        confidence = "Medium"
    elif threat_signals:
        is_fp = False
        confidence = "Medium"
    else:
        is_fp = False
        confidence = "Low"

    if is_fp:
        reason = "False Positive: " + "; ".join(fp_signals)
    elif threat_signals:
        reason = "Confirmed Threat: " + "; ".join(threat_signals)
    else:
        reason = "No baseline match — activity is suspicious"

    return {
        "is_false_positive": is_fp,
        "reason": reason,
        "gate_results": {
            "gate1_ip_reputation": gate1,
            "gate2_user_baseline": gate2,
            "gate3_cross_telemetry": gate3,
        },
        "fp_signals": fp_signals,
        "threat_signals": threat_signals,
        "confidence": confidence,
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

        # Password spraying: multiple different users targeted from same IP
        unique_users_attacked = len(set(
            e.get("user_id") for e in a_events
            if e.get("action") == "login_failed"
        ))
        if unique_users_attacked >= 2:
            event_types.add("password_spraying")

        # Zero-day fallback: suspicious activity but no rule matched
        if not event_types and (deny_count > 0 or fail_count > 0):
            event_types.add("unknown_heuristic")

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


def build_attack_timeline(correlated_ip: dict, mitre_techniques: list) -> list[dict]:
    """
    Reconstruct the attack timeline for a correlated IP.

    Collects ALL events from both firewall and auth evidence,
    sorts by timestamp, and annotates each with MITRE context,
    kill chain stage, significance, and pivot point detection.

    Returns:
        Sorted list of timeline entries — the attack story.
    """
    timeline = []
    ip = correlated_ip.get("ip", "")

    # Build a quick lookup: event action → MITRE mapping
    action_to_mitre = {
        "deny": MITRE_MAPPING.get("firewall_deny"),
        "allow": None,  # allow is not a threat indicator by itself
        "login_failed": MITRE_MAPPING.get("login_failed"),
        "login_success": MITRE_MAPPING.get("login_success_after_failures"),
    }

    # Track state for pivot detection
    failure_seen = False
    first_success_after_fail = False
    large_transfer_seen = False

    # Collect firewall events
    for e in correlated_ip.get("firewall_evidence", []):
        action = e.get("action", "")
        mitre = action_to_mitre.get(action)
        bytes_sent = e.get("bytes_sent", 0)

        # Determine significance
        if action == "deny":
            significance = f"Blocked connection to port {e.get('dst_port')} — attacker probing network"
            failure_seen = True
        elif action == "allow" and bytes_sent > 50000:
            significance = f"Large outbound transfer ({bytes_sent} bytes) — potential data exfiltration"
            mitre = MITRE_MAPPING.get("data_exfiltration")
        elif action == "allow":
            significance = f"Allowed connection to port {e.get('dst_port')}"
        else:
            significance = f"Firewall event: {action}"

        # Pivot point: first large transfer
        is_pivot = False
        if action == "allow" and bytes_sent > 50000 and not large_transfer_seen:
            is_pivot = True
            large_transfer_seen = True

        timeline.append({
            "timestamp": e.get("timestamp", ""),
            "event_type": action,
            "source": "Firewall",
            "mitre_technique": {
                "id": mitre["technique_id"],
                "name": mitre["technique_name"],
            } if mitre else None,
            "kill_chain_stage": mitre["kill_chain_stage"] if mitre else None,
            "significance": significance,
            "is_pivot_point": is_pivot,
            "raw_details": {
                "dst_port": e.get("dst_port"),
                "protocol": e.get("protocol"),
                "bytes_sent": bytes_sent,
            },
        })

    # Collect auth events
    for e in correlated_ip.get("auth_evidence", []):
        action = e.get("action", "")
        mitre = action_to_mitre.get(action)
        user = e.get("user_id", "unknown")

        if action == "login_failed":
            significance = f"Failed login attempt as '{user}' — credential attack in progress"
            failure_seen = True
        elif action == "login_success" and failure_seen:
            significance = f"Successful login as '{user}' AFTER previous failures — account compromised"
            mitre = MITRE_MAPPING.get("login_success_after_failures")
        elif action == "login_success":
            significance = f"Successful login as '{user}'"
        else:
            significance = f"Auth event: {action} for user '{user}'"

        # Pivot point: first success after failures
        is_pivot = False
        if action == "login_success" and failure_seen and not first_success_after_fail:
            is_pivot = True
            first_success_after_fail = True

        timeline.append({
            "timestamp": e.get("timestamp", ""),
            "event_type": action,
            "source": "Auth",
            "mitre_technique": {
                "id": mitre["technique_id"],
                "name": mitre["technique_name"],
            } if mitre else None,
            "kill_chain_stage": mitre["kill_chain_stage"] if mitre else None,
            "significance": significance,
            "is_pivot_point": is_pivot,
            "raw_details": {
                "user_id": user,
                "method": e.get("method"),
                "geo_location": e.get("geo_location"),
            },
        })

    # Sort by timestamp ascending — this IS the attack story
    timeline.sort(key=lambda x: x.get("timestamp", ""))

    return timeline


def analyze_threat(correlated_ip: dict, asset_value: int = 3) -> dict:
    """
    Full deterministic threat analysis for a single correlated IP.

    Returns:
        Complete analysis with risk score, MITRE mappings, kill chain,
        false positive check, attack timeline, and evidence.
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

    # Run Three-Gate false positive check with cross-telemetry context
    fp_check = baseline_check(
        {"src_ip": ip, "time": correlated_ip["firewall_evidence"][0].get("timestamp", "")},
        correlated_ip=correlated_ip,
    )

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

    # Build attack timeline
    attack_timeline = build_attack_timeline(correlated_ip, mitre_techniques)

    return {
        "ip": ip,
        "risk_score": risk,
        "mitre_techniques": mitre_techniques,
        "kill_chain": ordered_chain,
        "false_positive_analysis": fp_check,
        "attack_timeline": attack_timeline,
        "evidence_summary": {
            "firewall_deny_count": deny_count,
            "auth_fail_count": fail_count,
            "auth_success_count": correlated_ip.get("auth_success_count", 0),
            "total_evidence_points": total_evidence,
            "confidence": confidence,
            "distinct_ports_scanned": correlated_ip.get("distinct_ports_scanned", 0),
            "total_bytes_transferred": correlated_ip.get("total_bytes_transferred", 0),
        },
        # Full threshold-based alert classification
        "triggered_alerts": correlated_ip.get("triggered_alerts", []),
    }