"""
SOCentinel — Orchestrator.
Sequential agent pipeline: triage → forensics → response.
No LangGraph — just simple function calls with timing.
"""

import json
import time
from db import get_connection
from agents.triage_agent import TriageAgent
from agents.forensics_agent import ForensicsAgent
from agents.responder_agent import ResponderAgent


def run_full_investigation(alert_id: str) -> dict:
    """
    Run the complete investigation pipeline on an alert.
    Returns combined result with timing data.
    """
    steps = []

    # Step 1: Triage
    t0 = time.time()
    triage = TriageAgent().run(alert_id)
    steps.append({"agent": "triage", "status": "done", "seconds": round(time.time() - t0, 2)})

    # Step 2: Forensics
    t0 = time.time()
    forensics = ForensicsAgent().run(alert_id, triage)
    steps.append({"agent": "forensics", "status": "done", "seconds": round(time.time() - t0, 2)})

    # Step 3: Response
    t0 = time.time()
    response = ResponderAgent().run(alert_id, triage, forensics)
    steps.append({"agent": "responder", "status": "done", "seconds": round(time.time() - t0, 2)})

    # Save result to alerts table
    try:
        conn = get_connection()
        combined = json.dumps({
            "triage": triage,
            "forensics": forensics,
            "response": response,
        }, default=str)
        conn.execute(
            "UPDATE alerts SET status = 'triaging' WHERE id = ?",
            (alert_id,),
        )
        # Store triage result in raw_log as JSON (reusing column for demo)
        conn.execute(
            "UPDATE alerts SET ocsf_category = ? WHERE id = ?",
            (combined, alert_id),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[orchestrator] Error saving result: {e}")

    return {
        "triage": triage,
        "forensics": forensics,
        "response": response,
        "steps": steps,
    }
