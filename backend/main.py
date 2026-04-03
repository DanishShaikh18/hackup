"""
SOCentinel — FastAPI application entry point.
All route stubs return {"status": "not implemented"} until Phase 2.
"""

import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialize DB. Shutdown: cleanup."""
    init_db()
    print("[main] SOCentinel backend started.")
    yield
    print("[main] SOCentinel backend shutting down.")


app = FastAPI(
    title="SOCentinel",
    description="AI-driven SOC co-pilot API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

NOT_IMPLEMENTED = {"status": "not implemented"}


# ── Alert routes ──────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts():
    return NOT_IMPLEMENTED


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    return NOT_IMPLEMENTED


# ── Triage routes ─────────────────────────────────────────────

@app.post("/api/triage/{alert_id}")
async def start_triage(alert_id: str):
    return NOT_IMPLEMENTED


@app.get("/api/triage/{alert_id}/status")
async def get_triage_status(alert_id: str):
    return NOT_IMPLEMENTED


# ── Timeline & Attack Map ────────────────────────────────────

@app.get("/api/timeline/{alert_id}")
async def get_timeline(alert_id: str):
    return NOT_IMPLEMENTED


@app.get("/api/attack-map/{alert_id}")
async def get_attack_map(alert_id: str):
    return NOT_IMPLEMENTED


# ── Investigation Memory ─────────────────────────────────────

@app.get("/api/memory/similar/{alert_id}")
async def get_similar_cases(alert_id: str):
    return NOT_IMPLEMENTED


# ── Natural Language Query ───────────────────────────────────

@app.post("/api/query")
async def nl_query():
    return NOT_IMPLEMENTED


# ── Actions ──────────────────────────────────────────────────

@app.get("/api/actions/{alert_id}")
async def get_actions(alert_id: str):
    return NOT_IMPLEMENTED


@app.post("/api/actions/{alert_id}/execute")
async def execute_action(alert_id: str):
    return NOT_IMPLEMENTED


@app.post("/api/actions/{alert_id}/confirm")
async def confirm_action(alert_id: str):
    return NOT_IMPLEMENTED


@app.post("/api/actions/{alert_id}/mfa")
async def mfa_action(alert_id: str):
    return NOT_IMPLEMENTED


# ── Cases ────────────────────────────────────────────────────

@app.get("/api/cases")
async def get_cases():
    return NOT_IMPLEMENTED


@app.post("/api/cases")
async def create_case():
    return NOT_IMPLEMENTED


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    return NOT_IMPLEMENTED


@app.post("/api/cases/{case_id}/alerts")
async def add_alert_to_case(case_id: str):
    return NOT_IMPLEMENTED


@app.post("/api/cases/{case_id}/notes")
async def add_note_to_case(case_id: str):
    return NOT_IMPLEMENTED


@app.post("/api/cases/{case_id}/close")
async def close_case(case_id: str):
    return NOT_IMPLEMENTED


@app.get("/api/cases/{case_id}/ciso-report")
async def get_ciso_report(case_id: str):
    return NOT_IMPLEMENTED


# ── External Investigation ───────────────────────────────────

@app.get("/api/investigate/hash/{hash_value}")
async def investigate_hash(hash_value: str):
    return NOT_IMPLEMENTED


@app.get("/api/investigate/ip/{ip_address}")
async def investigate_ip(ip_address: str):
    return NOT_IMPLEMENTED
