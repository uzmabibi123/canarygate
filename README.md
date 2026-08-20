# 🛡️ CanaryGate

**A Zero-Trust reverse proxy with active canary-token deception, contextual risk scoring, and AI-assisted SOC monitoring — built for machine and AI-agent identities.**

> Instead of trusting a static API key indefinitely, CanaryGate evaluates every request against context — time, IP trust, request rate, geographic consistency, and behavior — and scores it for risk in real time. Leaked credentials are caught the moment they're used, not after the damage is done.

---

## 🎯 Why This Exists

Machine identities now outnumber human identities in most enterprise environments, yet most access control still relies on static API keys that are trusted forever once issued. CanaryGate demonstrates a working alternative: continuous, context-aware verification combined with active deception.

## ⚙️ How It Works

![CanaryGate architecture](images/architecture.png)

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 Zero-Trust Access Control | Every request validated — no implicit trust |
| 🍯 Canary Token Deception | Decoy credentials trigger instant lockdown when misused |
| 📊 Contextual Risk Engine | Weighted scoring across 7 real-time signals |
| 🎫 Short-Lived JWTs | 15-minute tokens, tagged by identity type |
| 🤖 AI-Agent Aware | Elevated caution automatically applied to AI-agent identities |
| 🌍 Geo-Velocity Detection | Flags "impossible travel" for a single credential |
| 🧭 Behavioral Anomaly Detection | Flags access patterns that deviate from the norm |
| 🗺️ MITRE ATT&CK Mapping | Every incident linked to a real technique ID |
| 🚦 Severity Classification | Low / Medium / High / Critical, auto-assigned |
| 🧠 AI-Generated Explanations | Local LLM (phi3:mini via Ollama) explains each alert in plain language |
| 🔗 Alert Correlation | Groups related alerts into one high-priority signal |
| 📤 Log Export | One-click CSV / JSON export |
| ✅ False-Positive Review | Analyst can mark and track false positives |
| 🌐 Live 3D Dashboard | Streamlit + Plotly, dark-themed, auto-refreshing |

## 🖥️ Tech Stack

- **Backend:** Python, FastAPI
- **Database:** SQLite
- **Auth:** Static API keys + short-lived JWT (python-jose)
- **AI:** Ollama (phi3:mini) — fully local, no external API calls
- **Dashboard:** Streamlit, Plotly
- **Infra:** AWS EC2 (Ubuntu), Docker

100% free and open-source tooling (excluding AWS compute).

## 🚀 Running It Locally

```bash
# 1. Clone the repo
git clone https://github.com/uzmabibi123/canarygate.git
cd canarygate

# 2. Set up environment
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn httpx python-jose[cryptography] streamlit plotly pandas requests

# 3. Initialize the database
python3 setup_db.py

# 4. Run each service in its own terminal
uvicorn mock_backend:app --host 0.0.0.0 --port 8001
uvicorn proxy:app --host 0.0.0.0 --port 8000
streamlit run dashboard.py --server.port 8501
```

## 🧪 Security Testing

The proxy was tested against 18+ attack scenarios including SQL injection, path traversal, JWT tampering, header injection, oversized payloads, and concurrent-load race conditions. One genuine bug was found — a crash under concurrent requests — and fixed. Full details are in the project report.

## ⚠️ Honest Scope Note

This is a working prototype demonstrating real Zero-Trust and deception patterns, not a production-ready commercial product. Concepts used are established industry patterns (used commercially by CyberArk, Okta, Thinkst Canary); the original contribution here is the integration of all of them, plus AI-agent-aware policy, into a single self-built system.

## 📄 License

Built as an academic/internship project.
