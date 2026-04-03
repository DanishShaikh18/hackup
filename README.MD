# SOCentinel 🛡️

**AI-driven SOC co-pilot that triages, investigates, and responds to security alerts with bounded autonomy and mandatory human oversight.**

---

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Project Foundation | ✅ |
| 2 | Backend Logic & Agents | ⬜ |
| 3 | Frontend Dashboard | ⬜ |
| 4 | Polish & Demo | ⬜ |

---

## Quick Start

```bash
# 1. Clone and enter project
cd hackup

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set up environment
cp .env.example .env
# Edit .env with your GROQ_API_KEY

# 4. Start Qdrant (optional, for vector search)
docker-compose up -d

# 5. Seed database with demo scenario
cd backend
python seed_data.py

# 6. Start backend
uvicorn main:app --reload --port 8000

# 7. Start frontend (separate terminal)
cd frontend
npm install
npm run dev
```

---

## Key Differentiators

### 1. 🎛️ Bounded Autonomy
Every action has an autonomy tier (0–2). Tier 0 actions execute automatically. Tier 1 actions require one-click approval. Tier 2 actions demand MFA confirmation. The AI never acts beyond its allowed scope.

### 2. 🛡️ Dual-LLM Shield
All LLM inputs pass through a secondary model that checks for prompt injection, hallucination, and unsafe content before the primary model processes them. Defense in depth for AI safety.

### 3. 📎 Mandatory Citations
Every AI-generated finding includes a `grounded_by` field linking back to raw log evidence. No citation = no display. Analysts can always verify the AI's reasoning against source data.

---

## Tech Stack

- **Backend**: FastAPI + LangGraph + Groq (Llama 3)
- **Frontend**: React + Vite + Tailwind CSS
- **Vector DB**: Qdrant
- **Database**: SQLite (local demo)
- **AI Safety**: Dual-LLM shield + grounding validator

---

## Demo Scenario

**Credential Stuffing Attack** — 47 failed logins from a Tor exit node at 2:28 AM, followed by a successful login to a Finance Director's account, file access to payroll data, and a 4.2 MB data exfiltration. SOCentinel triages, investigates, and recommends response actions with full evidence chains.
