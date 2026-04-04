# 🛡️ SOCentinel — AI-Driven SOC Co-Pilot

> **The math decides. The AI explains. Every alert is traceable.**

SOCentinel is a hybrid Security Operations Center Co-Pilot built for the HackUp 2026 hackathon under **Topic 04: Security Operations Agent**. It combines a fully deterministic risk engine with grounded AI narration to help security analysts investigate threats faster, with full explainability and zero black boxes.

---

## 🏆 What Makes SOCentinel Different

Most AI security tools give you an answer. SOCentinel gives you an answer **and shows its work.**

| The Problem with Existing Tools | How SOCentinel Solves It |
|---|---|
| ML tools say "malicious" with no explanation | Every risk score has a visible formula |
| Firewall and auth logs analyzed in isolation | Cross-source correlation links both by IP |
| Thousands of alerts, no prioritization | Deterministic scoring ranks threats by severity |
| False positives waste analyst hours | 3-gate false positive triage system |
| No attack story — just scattered events | Full chronological attack timeline with pivot points |
| AI can be manipulated via prompt injection | Two-layer injection defense built in |
| One AI giving one opinion | 3 specialist agents + coordinator synthesis |

---

## ✅ Hackathon Requirements — Fully Addressed

| Requirement | Implementation |
|---|---|
| Natural language querying over security data | `/chat` endpoint with NL search and co-pilot chat |
| Correlate multi-source logs and events | Firewall + auth logs correlated by IP in real time |
| Explainability with evidence-backed insights | Risk formula shown on UI, every threshold cited to NIST/MITRE |
| Handle AI hallucination | AI is grounded by deterministic data — it narrates, never calculates |
| Handle prompt injection | Pattern blocking + XML boundary delimiters on all LLM inputs |
| Suggest response actions (SOAR) | One-click IP blocking with rule ID and audit trail |
| **Brownie Point:** Investigation memory | Full case persistence — reload and compare past investigations |
| **Brownie Point:** Multi-agent collaboration | 3 specialist AI agents (Network, Identity, Threat Intel) + Coordinator |

---

## 💡 Core Principle

```
Risk Score = (Kill Chain Weight × Confidence) + Asset Value
```

The LLM never touches this formula. It receives the **result** and writes a plain-English explanation. If the LLM goes offline, the deterministic engine keeps working. The AI is additive — not a dependency.

---

## 🔍 Key Capabilities

### 1. Deterministic Risk Scoring
Every threat gets a score derived from a transparent formula. Kill chain stage weight (1–7), confidence from evidence count, and asset criticality combine into a normalised 1–10 score. Severity maps to Critical / High / Medium / Low / Informational. No guessing, no black box.

### 2. Cross-Source Log Correlation
Firewall and authentication logs are indexed by source IP and intersected. An attacker who scans ports on the firewall and then brute-forces SSH gets caught because both are linked to the same IP. Single-source tools miss this entirely.

### 3. Three-Gate False Positive Triage
Three independent gates run on every threat:
- **Gate 1 — IP Reputation:** Is this a known-good internal IP?
- **Gate 2 — Time and Geo:** Business hours? Office location? Tor exit node?
- **Gate 3 — Cross-Telemetry:** Does the IP appear in both log sources? Are multiple users targeted?

A single strong threat signal (Tor exit node, multi-user spray attack) overrides all other gates. The system never suppresses a real threat because one gate voted clean.

### 4. MITRE ATT&CK Mapping
Every detected event pattern maps to a specific MITRE technique with kill chain stage and weight. Password spraying (T1110.003) is detected automatically when two or more unique users are targeted from the same IP. A zero-day fallback catches unknown patterns via heuristic mapping so nothing slips through.

### 5. Attack Timeline Reconstruction
All events for a threat IP are sorted chronologically, annotated with MITRE technique and kill chain stage, and surfaced as a swimlane timeline. Pivot points — the moment an attacker gains access or starts exfiltrating — are flagged visually. Analysts see the full attack story in one view.

### 6. Grounded AI Co-Pilot
Groq (Llama 3.3 70B) operates under strict grounding rules: it must reference specific evidence, quote deterministic scores directly, and never invent numbers. The LLM runs at temperature 0.2 for maximum accuracy. A deterministic fallback summary activates automatically if Groq is unavailable.

### 7. Multi-Agent SOC Collaboration
Three specialist AI agents analyse each threat independently:
- **Agent 1 — Network Analyst:** Firewall and port-scan patterns
- **Agent 2 — Identity Analyst:** Credential and brute-force patterns
- **Agent 3 — Threat Intel:** MITRE mapping and campaign context

A Coordinator agent synthesises all three findings into one prioritised action recommendation.

### 8. Prompt Injection Defense
Two layers of protection on every LLM input:
- **Layer 1:** Pattern scanner blocks 12 known injection phrases and enforces a 500-character limit
- **Layer 2:** XML boundary tags wrap all user input so the model cannot be instructed from within user content

### 9. SOAR-Style Remediation
Analysts can block a threat IP in one click. The system generates a firewall rule ID, timestamps the action, and maintains a blocked-IP audit log. Inline confirmation prevents accidental blocks — no browser popups.

### 10. Investigation Memory
Every completed investigation is stored as a named case (e.g., `CASE-A1B2C3D4`). Analysts can list all past cases, reload any previous investigation in full, and compare cases side by side. Chat context carries the current case ID so the AI always knows what investigation is active.

---

## 🏗️ Architecture Overview

```
Data Sources
  Firewall Logs (JSON / UFW)
  Auth Logs (SSH / SSO)          ──► OCSF Parser ──► Normalised Events
  Raw Syslog (unstructured)

FastAPI Backend (localhost:8000)
  ├── Deterministic Engine (security_tools.py, thresholds.py)
  │     Risk Scorer · Log Correlator · FP Triage · MITRE Mapper
  │     Timeline Builder · Threshold Alert Generator
  │
  ├── AI Layer (copilot.py, groq_client.py)
  │     Grounded Narration · NL Search · Chat · Multi-Agent
  │     Prompt Injection Defense · Fallback Summary
  │
  └── Case Store (main.py)
        In-memory case persistence · History index · Session memory

React Frontend (localhost:5173)
  Intel Feed · Threat Workspace · Evidence Panel · AI Chat Drawer
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, Uvicorn |
| AI / LLM | Groq Cloud — Llama 3.3 70B Versatile |
| Frontend | React 18, Vite 5 |
| Log Standard | OCSF (Open Cybersecurity Schema Framework) |
| Detection Standards | NIST SP 800-63B, NIST SP 800-61r2, MITRE ATT&CK, SANS, Verizon DBIR 2023 |
| Dependencies | 4 pip packages — fastapi, uvicorn, python-dotenv, groq |

No database. No Docker. No cloud infrastructure required.

---

## 🧮 Detection Thresholds

All thresholds are derived from published industry standards, not arbitrary numbers.

| Detection | Threshold | Standard |
|---|---|---|
| Brute force login failures | 5 attempts | NIST SP 800-63B + Microsoft Account Lockout Policy |
| Port scan | 5 distinct ports | SANS Brute Force Detection Benchmark |
| Firewall denies | 3 blocks | NIST SP 800-61r2 + 3-sigma statistical baseline |
| Data exfiltration | 50,000 bytes | MITRE T1041 + Verizon DBIR 2023 |
| Success after failures | 3 failures then success | NIST SP 800-63B behavioral logic |
| Request velocity | 30 requests per minute | Human behavior baseline |

Three sensitivity profiles (Low / Medium / High) multiply all thresholds at runtime — no code changes needed to adjust for different environments.

---

## 🚀 Running SOCentinel

### Requirements
- Python 3.11+
- Node.js 18+
- Free Groq API key from [console.groq.com](https://console.groq.com)

### Backend
```bash
cd backend
pip install -r ../requirements.txt
echo "GROQ_API_KEY=your_key_here" > .env
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Hit **Analyze** to run the full investigation pipeline.

### API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/analyze` | Full investigation on structured JSON logs |
| POST | `/analyze-raw` | Investigation on unstructured syslog |
| POST | `/chat` | NL search and AI co-pilot chat |
| POST | `/remediate` | SOAR — block an IP |
| POST | `/multi-agent/{case_id}/{ip}` | Run multi-agent analysis on a threat |
| GET | `/thresholds` | View all thresholds with derivations |
| GET | `/cases` | List all past investigation cases |
| GET | `/cases/{id}` | Retrieve a full past case |

---

## 📁 Project Structure

```
hackup/
├── backend/
│   ├── main.py                 FastAPI app — all endpoints
│   ├── security_tools.py       Deterministic engine — scoring, correlation, FP triage, timeline
│   ├── log_parser.py           OCSF parser — JSON and raw syslog
│   ├── thresholds.py           NIST-derived thresholds with full derivation docs
│   ├── copilot.py              AI co-pilot — narration, chat, multi-agent, injection defense
│   └── llm/groq_client.py      Groq SDK wrapper
│
└── frontend/src/components/
    ├── Header.jsx              Logo, case pills, animated FW/AUTH counters, timezone
    ├── IntelFeed.jsx           Left panel — case history timeline
    ├── ThreatWorkspace.jsx     Center panel — arc gauge, kill chain, timeline, MITRE grid, agents
    ├── EvidencePanel.jsx       Right panel — evidence cards, alerts, SOAR actions
    └── ChatDrawer.jsx          Slide-out AI co-pilot drawer
```

---

## 🔬 Sample Attack Scenario

The included log data simulates a complete multi-stage intrusion from IP `203.0.113.45`:

1. **Reconnaissance** — Port scans on 22, 3389, 8080, 1433, 5432 (all denied by firewall)
2. **Credential Attack** — 5 failed SSH logins targeting `admin` and `root` from a Tor exit node
3. **Account Compromise** — Successful login after repeated failures (T1078 — Valid Accounts)
4. **Exfiltration** — 85KB transferred outbound, exceeding the 50KB threshold by 1.73x

SOCentinel detects all four stages, maps each to the correct MITRE technique, flags the pivot point at step 3, triggers a Critical alert at step 4, and generates a multi-agent report — all from a single click.

---

*Built for HackUp 2026 · Topic 04: Security Operations Agent*
*Team SOCentinel*