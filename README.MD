# SOCentinel — Hybrid Security Reasoning Engine

A SOC (Security Operations Center) co-pilot that combines **deterministic risk scoring** with **grounded AI narration** to investigate security threats across multi-source log data.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Frontend (React)                  │
│  ┌──────────────┐  ┌─────────────────────────────┐  │
│  │  Chat Panel   │  │   Evidence Workspace        │  │
│  │  (NL queries) │  │  ┌─────────┐ ┌──────────┐  │  │
│  │               │  │  │ MathBox │ │ KillChain│  │  │
│  │               │  │  └─────────┘ └──────────┘  │  │
│  │               │  │  ┌──────────────────────┐  │  │
│  │               │  │  │   Evidence Table     │  │  │
│  │               │  │  └──────────────────────┘  │  │
│  │               │  │  ┌──────────────────────┐  │  │
│  │               │  │  │   SOAR Button        │  │  │
│  └──────────────┘  │  └──────────────────────┘  │  │
│                     └─────────────────────────────┘  │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP
┌──────────────────────┴──────────────────────────────┐
│                 FastAPI Backend                       │
│  POST /analyze  — Full investigation pipeline        │
│  POST /chat     — SOC Co-Pilot (NL search + chat)   │
│  POST /remediate — SOAR IP blocking simulation      │
├──────────────────────────────────────────────────────┤
│  security_tools.py │ log_parser.py │ copilot.py      │
│  (Deterministic)   │ (OCSF Parser) │ (Grounded AI)  │
└──────────────────────────────────────────────────────┘
```

## Key Features

- **Multi-Source Correlation**: Links `firewall_logs.json` and `auth_logs.json` by IP
- **OCSF Normalization**: Raw logs → OCSF-standard JSON objects
- **Deterministic Risk Scoring**: `Score = (KillChainWeight × Confidence) + AssetValue`
- **MITRE ATT&CK Mapping**: Event patterns → Technique IDs (T1110, T1046, etc.)
- **Cyber Kill Chain Timeline**: Visual 7-stage attack progression
- **False Positive Reduction**: Baseline check against known-good IPs + business hours
- **Grounded AI Narration**: Groq LLM explains findings using the deterministic data
- **NL Chat Interface**: "Is anyone brute-forcing our firewall?" 
- **SOAR Simulation**: One-click IP blocking

## Setup

### Backend

```bash
cd backend
pip install -r ../requirements.txt
# Add your Groq API key to .env
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Health check |
| `POST` | `/analyze` | Run full investigation (deterministic + AI) |
| `POST` | `/chat` | Co-pilot chat / NL log search |
| `POST` | `/remediate` | Block IP (SOAR simulation) |

## Tech Stack

- **Backend**: Python, FastAPI, Groq (Llama 3.3)
- **Frontend**: React, Vite, Vanilla CSS
- **Data**: JSON log files (no database)
- **AI**: Grounded — LLM references deterministic calculations, never guesses
