import httpx

r = httpx.post("http://localhost:8000/analyze", json={"asset_value": 3}, timeout=30)
data = r.json()

print(f"Case: {data['case_id']}")
print(f"Evidence Table: {len(data['evidence_table'])} events")
print(f"Correlated IPs: {data['correlation_summary']['ips']}")
print()

for t in data["threats"]:
    ip = t["ip"]
    score = t["risk_score"]["score"]
    sev = t["risk_score"]["severity"]
    formula = t["risk_score"]["formula_display"]
    fp = t["false_positive_analysis"]["is_false_positive"]
    reason = t["false_positive_analysis"]["reason"]
    techs = [m["technique_id"] for m in t["mitre_techniques"]]
    stages = [s["stage"] for s in t["kill_chain"] if s["active"]]
    
    print(f"--- IP: {ip} ---")
    print(f"  Score: {score}/10 ({sev})")
    print(f"  Formula: {formula}")
    print(f"  MITRE: {techs}")
    print(f"  Kill Chain: {stages}")
    print(f"  False Positive: {fp}")
    print(f"  Reason: {reason}")
    print()

print("AI Summary:")
print(data.get("ai_summary", "N/A")[:400])
