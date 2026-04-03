import httpx, json

r = httpx.post("http://localhost:8000/analyze", json={"asset_value": 3}, timeout=30)
data = r.json()

out = []
out.append(f"Case: {data['case_id']}")
out.append(f"Evidence: {len(data['evidence_table'])} events")
out.append(f"IPs: {data['correlation_summary']['ips']}")
out.append("")

for t in data["threats"]:
    out.append(f"IP: {t['ip']}")
    out.append(f"  Score: {t['risk_score']['score']}/10 ({t['risk_score']['severity']})")
    out.append(f"  Formula: {t['risk_score']['formula_display']}")
    out.append(f"  MITRE: {[m['technique_id'] for m in t['mitre_techniques']]}")
    out.append(f"  FP: {t['false_positive_analysis']['is_false_positive']}")
    out.append(f"  Reason: {t['false_positive_analysis']['reason']}")
    out.append("")

with open("d:/hackup/backend/result.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(out))

print("DONE")
