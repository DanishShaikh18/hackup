"""
SOCentinel — FastAPI Backend.
Hybrid Security Reasoning Engine: Deterministic Math + Grounded AI.

Endpoints:
    POST /analyze    — Run full investigation on log data
    POST /chat       — SOC Co-Pilot chat interface
    POST /remediate  — SOAR simulation (block IP)
    GET  /           — Health check
    GET  /cases      — List past investigations
    GET  /cases/{id} — Retrieve past investigation
    POST /multi-agent/{case_id}/{ip} — Multi-agent analysis
"""

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from log_parser import LogParser
from security_tools import correlate_logs, analyze_threat, build_attack_timeline
from copilot import narrate_investigation, chat as copilot_chat, nl_search, multi_agent_analyze
from thresholds import get_all_thresholds, SENSITIVITY_PROFILES, ACTIVE_PROFILE

# ── Data paths ───────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
FIREWALL_LOG = DATA_DIR / "firewall_logs.json"
AUTH_LOG = DATA_DIR / "auth_logs.json"
RAW_LOG = DATA_DIR / "raw_mixed.log"

# ── App setup ────────────────────────────────────────────────
app = FastAPI(
    title="SOCentinel",
    description="Hybrid Security Reasoning Engine — Deterministic Math + Grounded AI",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared parser instance ───────────────────────────────────
parser = LogParser()

# ── In-memory state ──────────────────────────────────────────
blocked_ips: list[dict] = []
last_analysis: dict | None = None
case_store: dict[str, dict] = {}  # case_id → full analysis result
case_history: list[dict] = []     # lightweight index for listing


def _store_case(case: dict):
    """Persist case to in-memory store and history index."""
    global last_analysis
    case_store[case["case_id"]] = case
    case_history.append({
        "case_id": case["case_id"],
        "timestamp": case["timestamp"],
        "threat_count": len(case["threats"]),
        "top_severity": max(
            (t["risk_score"]["severity"] for t in case["threats"]),
            key=lambda s: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}.get(s, 0),
            default="Unknown"
        ) if case["threats"] else "Unknown",
        "correlated_ips": case["correlation_summary"]["ips"],
        "source_type": case.get("source_type", "structured_json"),
    })
    last_analysis = case


# ── Health Check ─────────────────────────────────────────────

@app.get("/")
async def health():
    return {
        "service": "SOCentinel",
        "version": "2.0.0",
        "status": "operational",
        "engine": "Hybrid — Deterministic + Grounded AI",
    }


# ── POST /analyze ────────────────────────────────────────────

@app.post("/analyze")
async def analyze(request: Request):
    """
    Run full investigation:
    1. Ingest both JSON log files
    2. Correlate by IP across sources
    3. Run deterministic analysis (MITRE mapping, risk score, baseline check)
    4. Generate AI narration (grounded by the deterministic results)
    """
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    asset_value = body.get("asset_value", 3)

    # 1. Ingest raw logs
    fw_raw = parser.ingest(str(FIREWALL_LOG))
    auth_raw = parser.ingest(str(AUTH_LOG))

    # 2. Also produce OCSF-normalized versions
    fw_ocsf = [parser.to_ocsf(e, "firewall") for e in fw_raw]
    auth_ocsf = [parser.to_ocsf(e, "auth") for e in auth_raw]

    # 3. Correlate across sources using raw data (has src_ip at top level)
    correlated = correlate_logs(fw_raw, auth_raw)

    # 4. Analyze each correlated IP
    threat_analyses = []
    for ip_data in correlated:
        analysis = analyze_threat(ip_data, asset_value)
        threat_analyses.append(analysis)

    # 5. Build evidence table (flat list of all raw events with source labels)
    evidence_table = []
    for e in fw_raw:
        evidence_table.append({
            "source": "Firewall",
            "id": e.get("id"),
            "timestamp": e.get("timestamp"),
            "src_ip": e.get("src_ip"),
            "event": e.get("action"),
            "details": f"Port {e.get('dst_port')} ({e.get('protocol')}) → {e.get('dst_ip')} | {e.get('bytes_sent', 0)} bytes",
        })
    for e in auth_raw:
        evidence_table.append({
            "source": "Auth",
            "id": e.get("id"),
            "timestamp": e.get("timestamp"),
            "src_ip": e.get("src_ip"),
            "event": e.get("action"),
            "details": f"User: {e.get('user_id')} | Method: {e.get('method')} | Geo: {e.get('geo_location')}",
        })

    # Sort evidence by timestamp
    evidence_table.sort(key=lambda x: x.get("timestamp", ""))

    # 6. Generate AI narration for top threat
    ai_summary = ""
    if threat_analyses:
        top_threat = max(threat_analyses, key=lambda t: t["risk_score"]["score"])
        ai_summary = narrate_investigation(top_threat)

    # 7. Build the Investigation Case
    case = {
        "case_id": f"CASE-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threats": threat_analyses,
        "evidence_table": evidence_table,
        "ocsf_events": {
            "firewall": fw_ocsf,
            "auth": auth_ocsf,
        },
        "correlation_summary": {
            "total_firewall_events": len(fw_raw),
            "total_auth_events": len(auth_raw),
            "correlated_ips": len(correlated),
            "ips": [c["ip"] for c in correlated],
        },
        "ai_summary": ai_summary,
    }

    _store_case(case)
    return case


# ── POST /chat ───────────────────────────────────────────────

@app.post("/chat")
async def chat_endpoint(request: Request):
    """
    SOC Co-Pilot chat.
    If analysis has been run, provides grounded context.
    Also supports natural-language log search.
    """
    body = await request.json()
    message = body.get("message", "")

    if not message:
        return {"error": "Missing 'message' field"}

    # Check if the user is asking to search logs
    search_keywords = ["show me", "find", "search", "list", "who is", "is anyone", "any", "how many"]
    is_search = any(kw in message.lower() for kw in search_keywords)

    if is_search:
        fw_raw = parser.ingest(str(FIREWALL_LOG))
        auth_raw = parser.ingest(str(AUTH_LOG))
        result = nl_search(message, fw_raw, auth_raw)
        return {
            "type": "search",
            "reply": result.get("summary", ""),
            "results": result.get("results", []),
            "intent": result.get("intent", ""),
            "filters": result.get("filters_applied", {}),
        }

    # Regular chat with investigation context
    context = None
    if last_analysis:
        context = {
            "threats": last_analysis.get("threats", []),
            "correlation_summary": last_analysis.get("correlation_summary", {}),
            "total_cases_investigated": len(case_history),
            "current_case_id": last_analysis.get("case_id", ""),
        }

    result = copilot_chat(message, context)
    return {
        "type": "chat",
        "reply": result["reply"],
        "grounded": result["grounded"],
    }


# ── POST /remediate ──────────────────────────────────────────

@app.post("/remediate")
async def remediate(request: Request):
    """
    SOAR simulation: Block an IP address.
    In production this would call a firewall API — here it's a mock.
    """
    body = await request.json()
    ip = body.get("ip", "")

    if not ip:
        return {"error": "Missing 'ip' field"}

    entry = {
        "ip": ip,
        "action": "BLOCKED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_added": f"FW-BLOCK-{uuid.uuid4().hex[:6].upper()}",
        "status": "success",
    }
    blocked_ips.append(entry)

    return {
        "status": "success",
        "message": f"IP {ip} has been blocked on the firewall.",
        "details": entry,
        "total_blocked": len(blocked_ips),
    }

@app.post("/analyze-raw")
async def analyze_raw(request: Request):
    """
    Analyze unstructured raw syslog/text logs.
    Demonstrates the parser can handle unstructured input,
    parse it to structured events, then run the full pipeline.
    """
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    asset_value = body.get("asset_value", 3)

    # Ingest raw unstructured log — auto-detected as .log file
    raw_events = parser.ingest(str(RAW_LOG))

    # Split parsed events by their detected log type
    fw_raw = [e for e in raw_events if e.get("_log_type") == "firewall"]
    auth_raw = [e for e in raw_events if e.get("_log_type") == "auth"]

    # From here the pipeline is IDENTICAL to /analyze
    fw_ocsf = [parser.to_ocsf(e, "firewall") for e in fw_raw]
    auth_ocsf = [parser.to_ocsf(e, "auth") for e in auth_raw]

    correlated = correlate_logs(fw_raw, auth_raw)

    threat_analyses = []
    for ip_data in correlated:
        analysis = analyze_threat(ip_data, asset_value)
        threat_analyses.append(analysis)

    evidence_table = []
    for e in fw_raw:
        evidence_table.append({
            "source": "Firewall (Raw Syslog)",
            "id": e.get("id"),
            "timestamp": e.get("timestamp"),
            "src_ip": e.get("src_ip"),
            "event": e.get("action"),
            "details": f"Port {e.get('dst_port')} ({e.get('protocol')}) → {e.get('dst_ip')} | {e.get('bytes_sent', 0)} bytes | RAW: {e.get('_raw_line', '')[:60]}",
        })
    for e in auth_raw:
        evidence_table.append({
            "source": "Auth (Raw Syslog)",
            "id": e.get("id"),
            "timestamp": e.get("timestamp"),
            "src_ip": e.get("src_ip"),
            "event": e.get("action"),
            "details": f"User: {e.get('user_id')} | Method: {e.get('method')} | RAW: {e.get('_raw_line', '')[:60]}",
        })

    evidence_table.sort(key=lambda x: x.get("timestamp", ""))

    ai_summary = ""
    if threat_analyses:
        top_threat = max(threat_analyses, key=lambda t: t["risk_score"]["score"])
        ai_summary = narrate_investigation(top_threat)

    case = {
        "case_id": f"CASE-RAW-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "unstructured_syslog",
        "parse_stats": {
            "total_raw_lines": len(raw_events),
            "firewall_parsed": len(fw_raw),
            "auth_parsed": len(auth_raw),
        },
        "threats": threat_analyses,
        "evidence_table": evidence_table,
        "ocsf_events": {"firewall": fw_ocsf, "auth": auth_ocsf},
        "correlation_summary": {
            "total_firewall_events": len(fw_raw),
            "total_auth_events": len(auth_raw),
            "correlated_ips": len(correlated),
            "ips": [c["ip"] for c in correlated],
        },
        "ai_summary": ai_summary,
    }

    _store_case(case)
    return case

@app.get("/thresholds")
async def thresholds_info():
    """
    Returns all threshold configurations with full derivation documentation.
    Judges can inspect exactly how every detection decision is made.
    """
    return {
        "active_profile": ACTIVE_PROFILE,
        "profiles": SENSITIVITY_PROFILES,
        "thresholds": get_all_thresholds(),
        "note": (
            "All thresholds are derived from NIST SP 800-61r2, SANS Institute benchmarks, "
            "Microsoft Security Baseline, and statistical mean+sigma analysis. "
            "Change ACTIVE_PROFILE in thresholds.py to tune sensitivity."
        ),
    }


# ── Case Persistence ────────────────────────────────────────

@app.get("/cases")
async def list_cases():
    """Return lightweight case history index."""
    return {
        "total": len(case_history),
        "cases": list(reversed(case_history))  # newest first
    }

@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    """Retrieve a full past investigation by case ID."""
    case = case_store.get(case_id)
    if not case:
        return {"error": f"Case {case_id} not found"}
    return case


# ── Multi-Agent SOC Collaboration ────────────────────────────

@app.post("/multi-agent/{case_id}/{ip}")
async def multi_agent_endpoint(case_id: str, ip: str):
    """
    Run multi-agent analysis on a specific threat from a specific case.
    Frontend calls this when analyst wants deeper collaborative analysis.
    """
    case = case_store.get(case_id)
    if not case:
        return {"error": "Case not found. Run analysis first."}

    threat = next((t for t in case.get("threats", []) if t["ip"] == ip), None)
    if not threat:
        return {"error": f"IP {ip} not found in case {case_id}"}

    result = multi_agent_analyze(threat)
    return {
        "case_id": case_id,
        "ip": ip,
        "multi_agent_report": result,
    }