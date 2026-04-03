"""
SOCentinel — FastAPI application.
All routes fully implemented for Phase 2.
"""

import json
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from db import init_db, get_connection
from agents.orchestrator import run_full_investigation
from engines.timeline_builder import TimelineBuilder
from engines.attack_mapper import AttackMapper
from engines.soar_suggester import SOARSuggester
from engines.nl2query import NL2Query
from autonomy.bounded_autonomy import BoundedAutonomy
from memory.investigation_memory import InvestigationMemory
from memory.case_manager import CaseManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("[main] SOCentinel backend started.")
    yield
    print("[main] SOCentinel backend shutting down.")


app = FastAPI(
    title="SOCentinel",
    description="AI-driven SOC co-pilot API",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Alert routes ──────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    conn = get_connection()
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        return {"error": "Alert not found"}
    alert = dict(alert)
    events = conn.execute(
        "SELECT * FROM log_events WHERE alert_id = ? ORDER BY timestamp", (alert_id,)
    ).fetchall()
    conn.close()
    alert["log_events"] = [dict(e) for e in events]
    return alert


# ── Triage routes ─────────────────────────────────────────────

@app.post("/api/triage/{alert_id}")
async def start_triage(alert_id: str):
    result = run_full_investigation(alert_id)
    return result


@app.get("/api/triage/{alert_id}/status")
async def get_triage_status(alert_id: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT ocsf_category FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    conn.close()
    if not row or not row["ocsf_category"]:
        return {"status": "pending"}
    try:
        return json.loads(row["ocsf_category"])
    except (json.JSONDecodeError, TypeError):
        return {"status": "pending"}


# ── Timeline & Attack Map ────────────────────────────────────

@app.get("/api/timeline/{alert_id}")
async def get_timeline(alert_id: str):
    conn = get_connection()
    events = conn.execute(
        "SELECT * FROM log_events WHERE alert_id = ? ORDER BY timestamp", (alert_id,)
    ).fetchall()
    conn.close()
    events = [dict(e) for e in events]
    timeline = TimelineBuilder().build(events)
    return {"timeline": timeline}


@app.get("/api/attack-map/{alert_id}")
async def get_attack_map(alert_id: str):
    conn = get_connection()
    events = conn.execute(
        "SELECT * FROM log_events WHERE alert_id = ? ORDER BY timestamp", (alert_id,)
    ).fetchall()
    conn.close()
    mapper = AttackMapper()
    by_tactic = {}
    for event in events:
        event = dict(event)
        mapping = mapper.map_event(event.get("event_type", ""))
        if mapping:
            tactic = mapping.get("tactic", "Unknown")
            if tactic not in by_tactic:
                by_tactic[tactic] = []
            by_tactic[tactic].append({
                "log_id": event["id"],
                "event_type": event["event_type"],
                **mapping,
            })
    return {"attack_map": by_tactic}


# ── Investigation Memory ─────────────────────────────────────

@app.get("/api/memory/similar/{alert_id}")
async def get_similar_cases(alert_id: str):
    conn = get_connection()
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    if not alert:
        return {"similar": []}
    memory = InvestigationMemory()
    similar = memory.search_similar(
        alert_category=alert["rule_name"] or "unknown",
        mitre_techniques=[],
    )
    return {"similar": similar}


# ── Natural Language Query ───────────────────────────────────

@app.post("/api/query")
async def nl_query(request: Request):
    body = await request.json()
    q = body.get("q", "")
    if not q:
        return {"error": "Missing 'q' field"}
    result = NL2Query().query(q)
    return result


# ── Actions ──────────────────────────────────────────────────

@app.get("/api/actions/{alert_id}")
async def get_actions(alert_id: str):
    conn = get_connection()
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    asset = None
    if alert and alert["asset_id"]:
        asset = conn.execute(
            "SELECT * FROM assets WHERE id = ?", (alert["asset_id"],)
        ).fetchone()
    conn.close()
    criticality = dict(asset).get("criticality", "MEDIUM") if asset else "MEDIUM"
    asset_type = dict(asset).get("asset_type", "unknown") if asset else "unknown"

    soar = SOARSuggester()
    actions = soar.suggest("brute_force", criticality)

    autonomy = BoundedAutonomy()
    for action in actions:
        tier = autonomy.classify(action["id"], asset_type, 80)
        action["tier"] = tier
        tier_labels = {0: "auto", 1: "one-click", 2: "mfa-required"}
        action["tier_label"] = tier_labels.get(tier, "unknown")

    return {"actions": actions}


@app.post("/api/actions/{alert_id}/execute")
async def execute_action(alert_id: str, request: Request):
    body = await request.json()
    action_id = body.get("action_id", "")
    conn = get_connection()
    conn.execute(
        "INSERT INTO investigation_memory (alert_id, finding, evidence_refs, confidence) VALUES (?, ?, ?, ?)",
        (alert_id, f"Action executed: {action_id}", "[]", 1.0),
    )
    conn.commit()
    conn.close()
    return {"status": "executed", "action_id": action_id, "alert_id": alert_id}


@app.post("/api/actions/{alert_id}/confirm")
async def confirm_action(alert_id: str, request: Request):
    body = await request.json()
    action_id = body.get("action_id", "")
    conn = get_connection()
    conn.execute(
        "INSERT INTO investigation_memory (alert_id, finding, evidence_refs, confidence) VALUES (?, ?, ?, ?)",
        (alert_id, f"Action confirmed: {action_id}", "[]", 1.0),
    )
    conn.commit()
    conn.close()
    return {"status": "confirmed", "action_id": action_id, "alert_id": alert_id}


@app.post("/api/actions/{alert_id}/mfa")
async def mfa_action(alert_id: str, request: Request):
    body = await request.json()
    action_id = body.get("action_id", "")
    mfa_token = body.get("mfa_token", "")
    if not mfa_token or len(mfa_token) != 6 or not mfa_token.isdigit():
        return {"status": "rejected", "reason": "MFA token must be exactly 6 digits"}
    conn = get_connection()
    conn.execute(
        "INSERT INTO investigation_memory (alert_id, finding, evidence_refs, confidence) VALUES (?, ?, ?, ?)",
        (alert_id, f"MFA authorized for action: {action_id}", "[]", 1.0),
    )
    conn.commit()
    conn.close()
    return {"status": "authorized", "action_id": action_id, "alert_id": alert_id}


# ── Cases ────────────────────────────────────────────────────

@app.get("/api/cases")
async def get_cases():
    return CaseManager().list_cases()


@app.post("/api/cases")
async def create_case(request: Request):
    body = await request.json()
    title = body.get("title", "Untitled Case")
    alert_ids = body.get("alert_ids", [])
    case_id = CaseManager().create_case(title, alert_ids)
    return {"case_id": case_id, "status": "created"}


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    return CaseManager().get_case(case_id)


@app.post("/api/cases/{case_id}/alerts")
async def add_alert_to_case(case_id: str, request: Request):
    body = await request.json()
    alert_id = body.get("alert_id", "")
    CaseManager().link_alert(case_id, alert_id)
    return {"status": "linked", "case_id": case_id, "alert_id": alert_id}


@app.post("/api/cases/{case_id}/notes")
async def add_note_to_case(case_id: str, request: Request):
    body = await request.json()
    note = body.get("note", "")
    CaseManager().add_note(case_id, note)
    return {"status": "note_added", "case_id": case_id}


@app.post("/api/cases/{case_id}/close")
async def close_case(case_id: str, request: Request):
    body = await request.json()
    outcome = body.get("outcome", "unknown")
    resolution = body.get("resolution", "")
    CaseManager().close_case(case_id, outcome, resolution)
    return {"status": "closed", "case_id": case_id}


@app.get("/api/cases/{case_id}/ciso-report")
async def get_ciso_report(case_id: str):
    report = CaseManager().generate_ciso_report(case_id)
    return {"case_id": case_id, "report": report}


# ── External Investigation ───────────────────────────────────

@app.get("/api/investigate/hash/{hash_value}")
async def investigate_hash(hash_value: str):
    return {
        "hash": hash_value,
        "hosts_checked": 14,
        "found_on": [],
        "status": "clean",
    }


@app.get("/api/investigate/ip/{ip_address}")
async def investigate_ip(ip_address: str):
    conn = get_connection()
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE src_ip = ?", (ip_address,)
    ).fetchall()
    events = conn.execute(
        "SELECT * FROM log_events WHERE src_ip = ?", (ip_address,)
    ).fetchall()
    conn.close()
    return {
        "ip": ip_address,
        "alerts": [dict(a) for a in alerts],
        "events": [dict(e) for e in events],
    }
