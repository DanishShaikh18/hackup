"""
SOCentinel — SOC Co-Pilot.
Grounded AI: the LLM narrates, explains, and searches — 
but always references the deterministic analysis, never guesses numbers.
"""

import json
from llm.groq_client import call_groq


SYSTEM_PROMPT = """You are SOCentinel, a SOC (Security Operations Center) Co-Pilot AI.

RULES:
1. You are GROUNDED. You must reference specific evidence: IPs, timestamps, log IDs, MITRE technique IDs.
2. You must NEVER invent numbers. The risk score and confidence come from the deterministic engine — quote them directly.
3. When explaining a threat, always mention: (a) what was detected, (b) which MITRE technique it maps to, (c) why it is or isn't a false positive.
4. Keep responses concise: 2–4 sentences for summaries, up to a paragraph for detailed explanations.
5. Use plain English a junior SOC analyst can understand.
6. Always include "Why this is NOT a False Positive" in threat summaries when the activity is suspicious."""


def narrate_investigation(analysis_result: dict) -> str:
    """
    Generate a human-readable investigation summary from deterministic analysis results.
    The LLM adds narrative context but is grounded by the actual data.
    """
    # Build a context payload the LLM can reference
    context = json.dumps(analysis_result, indent=2, default=str)

    user_msg = f"""Based on the following deterministic analysis, write a 3-4 sentence investigation summary.

You MUST include:
1. What was detected (IPs, event types, counts)
2. The risk score and how it was calculated
3. Which MITRE techniques were matched
4. Why this is NOT a false positive (reference the baseline check)

Analysis Results:
{context}"""

    result = call_groq(SYSTEM_PROMPT, user_msg)

    if not result:
        # Fallback: generate a non-LLM summary from the data
        return _fallback_summary(analysis_result)

    return result


def chat(user_message: str, analysis_context: dict | None = None) -> dict:
    """
    SOC Co-Pilot chat interface.

    If analysis_context is provided, the LLM answers questions about it.
    If not, it gives general SOC guidance.
    """
    context_str = ""
    if analysis_context:
        context_str = f"\n\nCurrent Investigation Context:\n{json.dumps(analysis_context, indent=2, default=str)}"

    user_msg = f"{user_message}{context_str}"

    reply = call_groq(SYSTEM_PROMPT, user_msg)

    if not reply:
        reply = "I'm unable to reach the AI model right now. Please check the analysis panels for deterministic results — those are always available."

    return {
        "reply": reply,
        "grounded": analysis_context is not None,
    }


def nl_search(user_query: str, firewall_events: list[dict], auth_events: list[dict]) -> dict:
    """
    Natural Language search across log data.
    The LLM interprets the intent, we filter data, LLM summarizes.
    """
    search_prompt = f"""The user asked: "{user_query}"

Available log data:
- Firewall logs ({len(firewall_events)} events): connection allow/deny with IPs, ports, protocols
- Auth logs ({len(auth_events)} events): login success/failure with user IDs, IPs, geolocations

Based on the user's question, identify which logs are relevant and what to look for.
Respond in JSON format:
{{
  "intent": "brief description of what user wants",
  "search_source": "firewall" or "auth" or "both",
  "search_fields": {{"field_name": "value_to_match"}},
  "explanation": "why these filters match the question"
}}

Return ONLY the JSON, no markdown."""

    llm_response = call_groq(SYSTEM_PROMPT, search_prompt)

    if not llm_response:
        return {"error": "LLM unavailable", "results": []}

    # Parse LLM's search instructions
    try:
        # Clean up potential markdown formatting
        clean = llm_response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1].rsplit("```", 1)[0]
        search_plan = json.loads(clean)
    except (json.JSONDecodeError, IndexError):
        return {
            "error": "Could not parse search intent",
            "raw_response": llm_response,
            "results": [],
        }

    # Execute the search
    results = []
    source = search_plan.get("search_source", "both")
    filters = search_plan.get("search_fields", {})

    if source in ("firewall", "both"):
        for event in firewall_events:
            if _matches_filters(event, filters):
                results.append({**event, "_source": "firewall"})

    if source in ("auth", "both"):
        for event in auth_events:
            if _matches_filters(event, filters):
                results.append({**event, "_source": "auth"})

    # Have the LLM summarize findings
    summary_msg = f"""The user asked: "{user_query}"
Search found {len(results)} matching events.
Results: {json.dumps(results[:10], default=str)}

Summarize the findings in 2-3 sentences. Reference specific IPs, counts, and patterns."""

    summary = call_groq(SYSTEM_PROMPT, summary_msg) or f"Found {len(results)} matching events."

    return {
        "intent": search_plan.get("intent", ""),
        "results": results,
        "summary": summary,
        "filters_applied": filters,
    }


def _matches_filters(event: dict, filters: dict) -> bool:
    """Check if an event matches the given filters (loose matching)."""
    if not filters:
        return True

    for key, value in filters.items():
        event_val = str(event.get(key, "")).lower()
        if event_val and str(value).lower() in event_val:
            continue
        # Also check nested if not found at top level
        found = False
        for sub_key in event:
            if isinstance(event[sub_key], dict):
                sub_val = str(event[sub_key].get(key, "")).lower()
                if sub_val and str(value).lower() in sub_val:
                    found = True
                    break
        if not found and event_val == "":
            # Key not found anywhere, skip this filter
            continue
        elif not found and str(value).lower() not in event_val:
            return False
    return True


def _fallback_summary(analysis: dict) -> str:
    """Non-LLM fallback summary when Groq is unavailable."""
    ip = analysis.get("ip", "Unknown")
    score = analysis.get("risk_score", {}).get("score", "?")
    severity = analysis.get("risk_score", {}).get("severity", "Unknown")
    formula = analysis.get("risk_score", {}).get("formula_display", "N/A")
    techniques = [t.get("technique_id", "") for t in analysis.get("mitre_techniques", [])]
    fp = analysis.get("false_positive_analysis", {})

    summary = (
        f"ALERT: IP {ip} flagged as {severity} (Risk Score: {score}/10). "
        f"Score calculated as: {formula}. "
        f"MITRE Techniques detected: {', '.join(techniques) or 'None'}. "
    )

    if fp.get("is_false_positive"):
        summary += f"Note: This may be a false positive — {fp.get('reason', '')}."
    else:
        summary += f"This is NOT a false positive: {fp.get('reason', '')}."

    return summary
