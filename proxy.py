import time
import sqlite3
import httpx
import requests
from datetime import datetime
from fastapi import FastAPI, Request, Response
from jose import jwt, JWTError

app = FastAPI()

MOCK_BACKEND_URL = "http://127.0.0.1:8001"
JWT_SECRET = "canarygate-secret-key-2026"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

HONEY_PAYLOAD = {
    "status": "success",
    "aws_access_key_id": "AKIAFAKE123EXAMPLE",
    "internal_note": "fake data shown to unauthorized user"
}

ALLOWED_HOURS = range(6, 22)
TRUSTED_IPS = ["127.0.0.1"]
RATE_LIMIT = 5
RATE_WINDOW_SECONDS = 60
REQUEST_TIMESTAMPS = {}

IP_COUNTRY_MAP = {
    "127.0.0.1": "Pakistan",
    "172.34.54.67": "USA",
    "45.10.20.30": "Germany",
    "99.99.99.99": "Russia"
}

LAST_SEEN = {}
ENDPOINT_HISTORY = {}

MITRE_MAP = {
    "off_hours_access": "T1078 - Valid Accounts",
    "suspicious_user_agent": "T1583 - Acquire Infrastructure",
    "untrusted_ip": "T1078.004 - Cloud Accounts",
    "rate_limit_exceeded": "T1499 - Endpoint Denial of Service",
    "ai_agent_default_caution": "T1204 - User Execution (Agent)",
    "impossible_travel": "T1078.004 - Cloud Accounts (Impossible Travel)",
    "unusual_endpoint": "T1touchpoint - Discovery / Lateral Movement",
    "canary_token_used": "T1552 - Unsecured Credentials"
}

def get_country(ip):
    return IP_COUNTRY_MAP.get(ip, "Unknown")

def get_severity(score):
    if score >= 70:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 40:
        return "Medium"
    return "Low"

def map_mitre(reasons):
    techniques = set()
    for r in reasons:
        for key, technique in MITRE_MAP.items():
            if r.startswith(key):
                techniques.add(technique)
    return ", ".join(techniques) if techniques else "N/A"

def generate_ai_explanation(incident_type, reasons, risk_score):
    try:
        reasons_text = ", ".join(reasons) if reasons else "canary token misuse"
        prompt = f"In one short sentence, explain to a security analyst why this event is risky: incident={incident_type}, risk_score={risk_score}, triggered_reasons={reasons_text}. Be concise, plain language, no jargon."
        response = requests.post(
            OLLAMA_URL,
            json={"model": "phi3:mini", "prompt": prompt, "stream": False, "options": {"num_predict": 60}},
            timeout=90
        )
        if response.status_code == 200:
            return response.json().get("response", "").strip()
        return "AI explanation unavailable."
    except Exception:
        return "AI explanation unavailable (timeout or error)."

def check_rate_limit(client_ip: str) -> bool:
    """Returns True if this request EXCEEDS the rate limit."""
    now = time.time()
    if client_ip not in REQUEST_TIMESTAMPS:
        REQUEST_TIMESTAMPS[client_ip] = []
    REQUEST_TIMESTAMPS[client_ip] = [
        t for t in REQUEST_TIMESTAMPS[client_ip] if now - t <= RATE_WINDOW_SECONDS
    ]
    REQUEST_TIMESTAMPS[client_ip].append(now)
    count = len(REQUEST_TIMESTAMPS[client_ip])
    print(f"RATE-CHECK ip={client_ip} count={count} full_list={REQUEST_TIMESTAMPS[client_ip]}", flush=True)
    return count > RATE_LIMIT

def check_token(token: str):
    conn = sqlite3.connect("security.db", timeout=10)
    cursor = conn.cursor()
    cursor.execute("SELECT token_type, is_active FROM tokens WHERE token_value = ?", (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return {"exists": True, "type": result[0], "active": bool(result[1])}
    return {"exists": False, "type": None, "active": False}

def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"valid": True, "identity_type": payload.get("identity_type", "unknown")}
    except JWTError:
        return {"valid": False, "identity_type": None}

def lock_down_real_tokens():
    conn = sqlite3.connect("security.db", timeout=10)
    cursor = conn.cursor()
    cursor.execute("UPDATE tokens SET is_active = 0 WHERE token_type = 'REAL'")
    conn.commit()
    conn.close()

def log_incident(token, ip, incident_type, risk_score=0, reason="", severity="Low", mitre="N/A", ai_explanation="N/A"):
    conn = sqlite3.connect("security.db", timeout=10)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO incidents 
        (timestamp, source_ip, used_token, incident_type, details, severity, mitre_technique, review_status, ai_explanation) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.time(), ip, token, incident_type, f"risk_score={risk_score}; reason={reason}", severity, mitre, "unreviewed", ai_explanation)
    )
    conn.commit()
    conn.close()

def calculate_risk(request: Request, client_ip: str, identity_type: str = "human", credential_id: str = "unknown"):
    score = 0
    reasons = []

    current_hour = datetime.now().hour
    if current_hour not in ALLOWED_HOURS:
        score += 30
        reasons.append("off_hours_access")

    ua = request.headers.get("user-agent", "")
    if ua == "" or "curl" in ua.lower():
        score += 10
        reasons.append("suspicious_user_agent")

    if client_ip not in TRUSTED_IPS:
        score += 20
        reasons.append("untrusted_ip")

    if check_rate_limit(client_ip):
        score += 25
        reasons.append("rate_limit_exceeded")

    if identity_type == "ai-agent":
        score += 15
        reasons.append("ai_agent_default_caution")

    current_country = get_country(client_ip)
    now = time.time()
    if credential_id in LAST_SEEN:
        last_country, last_time = LAST_SEEN[credential_id]
        if last_country != current_country and (now - last_time) < 300:
            score += 35
            reasons.append(f"impossible_travel_{last_country}_to_{current_country}")
    LAST_SEEN[credential_id] = (current_country, now)

    current_path = request.url.path
    if credential_id in ENDPOINT_HISTORY:
        usual_path = ENDPOINT_HISTORY[credential_id]
        if usual_path != current_path:
            score += 15
            reasons.append(f"unusual_endpoint_{usual_path}_to_{current_path}")
    ENDPOINT_HISTORY[credential_id] = current_path

    return score, reasons

@app.post("/login")
async def login(identity_type: str = "service"):
    payload = {"sub": "test-user", "identity_type": identity_type, "exp": time.time() + 900}
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"access_token": token, "identity_type": identity_type, "expires_in_seconds": 900}

@app.middleware("http")
async def zero_trust_check(request: Request, call_next):
    if request.url.path == "/login":
        return await call_next(request)

    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    api_key = request.headers.get("X-API-Key")
    auth_header = request.headers.get("Authorization")

    identity_type = "human"
    used_credential = None

    if auth_header and auth_header.startswith("Bearer "):
        jwt_token = auth_header.replace("Bearer ", "")
        jwt_result = verify_jwt(jwt_token)
        if not jwt_result["valid"]:
            return Response(content="Invalid or Expired JWT Token", status_code=403)
        identity_type = jwt_result["identity_type"]
        used_credential = jwt_token

    elif api_key:
        token_info = check_token(api_key)
        if token_info["exists"] and token_info["type"] == "CANARY":
            ai_text = generate_ai_explanation("CANARY_TRIGGERED", ["canary_token_used"], 100)
            log_incident(api_key, client_ip, "CANARY_TRIGGERED", 100, "canary_token_used", "Critical", MITRE_MAP["canary_token_used"], ai_text)
            lock_down_real_tokens()
            return Response(content=str(HONEY_PAYLOAD), status_code=200, media_type="application/json")
        if not token_info["exists"] or not token_info["active"]:
            return Response(content="Invalid or Suspended API Key", status_code=403)
        used_credential = api_key
    else:
        return Response(content="Missing API Key or JWT Token", status_code=401)

    risk_score, reasons = calculate_risk(request, client_ip, identity_type, used_credential)
    severity = get_severity(risk_score)
    mitre = map_mitre(reasons)

    if risk_score >= 70:
        ai_text = generate_ai_explanation("BLOCKED_HIGH_RISK", reasons, risk_score)
        log_incident(used_credential, client_ip, "BLOCKED_HIGH_RISK", risk_score, ",".join(reasons), severity, mitre, ai_text)
        return Response(content=f"Access Denied - Risk Score: {risk_score}", status_code=403)

    if risk_score >= 40:
        ai_text = generate_ai_explanation("ALLOWED_WITH_WARNING", reasons, risk_score)
        log_incident(used_credential, client_ip, "ALLOWED_WITH_WARNING", risk_score, ",".join(reasons), severity, mitre, ai_text)

    response = await call_next(request)
    return response

@app.get("/{path:path}")
async def proxy_request(path: str, request: Request):
    target_url = f"{MOCK_BACKEND_URL}/{path}"
    async with httpx.AsyncClient() as client:
        try:
            backend_response = await client.get(target_url, timeout=10)
        except httpx.ConnectTimeout:
            return Response(content="Backend service temporarily unavailable", status_code=503)
    return Response(content=backend_response.content, status_code=backend_response.status_code, media_type="application/json")
