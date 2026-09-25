import json
import math
import random
import sqlite3
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="CanaryGate SOC Dashboard", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
.stApp { background: radial-gradient(circle at 80% -10%, rgba(54,95,128,.24), transparent 38%), #0b101b; color: #e8eef7; }
[data-testid="stSidebar"] { background: #0a101b; border-right: 1px solid #1d2a3e; }
[data-testid="stMetric"] { background: linear-gradient(145deg,#121d2c,#0f1725); border: 1px solid #233249; border-radius: 11px; padding: 15px; }
[data-testid="stMetricLabel"] { color: #8b99ad; }
[data-testid="stMetricValue"] { color: #ecf4fb; font-family: 'DM Mono', monospace; }
h1 { color: #ecf4fb !important; letter-spacing: -.04em; }
h2, h3 { color: #dce7f3 !important; }
.stButton>button, .stDownloadButton>button { border: 1px solid #30435d; border-radius: 7px; background: #142235; color: #d5e2ef; }
.stButton>button:hover, .stDownloadButton>button:hover { border-color: #58aaa7; color: #e8fffc; }
div[data-testid="stDataFrame"] { border: 1px solid #26364d; border-radius: 9px; overflow: hidden; }
section[data-testid="stExpander"] { border: 1px solid #25354b; border-radius: 9px; background: #111b2a; }
.small-mono { color:#7890a6; font-family:'DM Mono',monospace; font-size:11px; letter-spacing:.08em; }
.role-badge { display:inline-block; padding:6px 12px; border:1px solid #3b506a; border-radius:20px; color:#89dcd6; font-family:'DM Mono',monospace; font-size:11px; }
.readonly { padding:10px 13px; border:1px solid #6a5630; border-radius:8px; color:#e6c779; background:rgba(230,199,121,.06); }
</style>
""", unsafe_allow_html=True)

DB_PATH = "security.db"
COUNTRIES = {"127.0.0.1": "Pakistan", "172.34.54.67": "USA", "45.10.20.30": "Germany", "99.99.99.99": "Russia"}
COORDS = {"Pakistan": (30.3753, 69.3451), "USA": (37.0902, -95.7129), "Germany": (51.1657, 10.4515), "Russia": (61.5240, 105.3188), "Unknown": (0, 0)}


def db_connect():
    return sqlite3.connect(DB_PATH, timeout=10)


def init_db():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL)""")
    cur.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", ("admin", "admin123", "Admin"))
    cur.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", ("viewer", "viewer123", "Viewer"))
    conn.commit()
    conn.close()


def get_user(username, password):
    conn = db_connect()
    row = conn.execute("SELECT username, role FROM users WHERE lower(username)=lower(?) AND password=?", (username.strip(), password)).fetchone()
    conn.close()
    return {"username": row[0], "role": row[1]} if row else None


def create_user(username, password, role):
    conn = db_connect()
    try:
        conn.execute("INSERT INTO users VALUES (?, ?, ?)", (username.strip(), password, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


@st.cache_data(ttl=8)
def load_incidents():
    conn = db_connect()
    try:
        df = pd.read_sql_query("SELECT * FROM incidents ORDER BY id DESC", conn)
    finally:
        conn.close()
    if not df.empty:
        df["country"] = df["source_ip"].map(COUNTRIES).fillna("Unknown")
    return df


def update_review_status(incident_id, status):
    conn = db_connect()
    conn.execute("UPDATE incidents SET review_status=? WHERE id=?", (status, int(incident_id)))
    conn.commit()
    conn.close()
    load_incidents.clear()


def correlated_alerts(df, window_seconds=300, minimum=3):
    if df.empty:
        return []
    results = []
    for ip, group in df.groupby("source_ip"):
        stamps = sorted(group["timestamp"].tolist())
        for start in stamps:
            window = [item for item in stamps if start <= item <= start + window_seconds]
            if len(window) >= minimum:
                results.append({"ip": ip, "country": COUNTRIES.get(ip, "Unknown"), "count": len(window), "start": datetime.fromtimestamp(start)})
                break
    return results


def auth_screen():
    st.markdown("<div style='max-width:530px;margin:5vh auto 0;text-align:center'>", unsafe_allow_html=True)
    st.markdown("<div class='small-mono'>CANARYGATE / SECURE CONSOLE</div>", unsafe_allow_html=True)
    st.title("Machine identity defense, without the noise.")
    st.caption("Context-aware access control, canary deception, and analyst review in one calm operational view.")
    login_tab, signup_tab = st.tabs(["Log in", "Sign up"])
    with login_tab:
        with st.form("login"):
            username = st.text_input("Username", placeholder="e.g. analyst")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Enter console", use_container_width=True)
            if submitted:
                account = get_user(username, password)
                if account:
                    st.session_state.account = account
                    st.rerun()
                st.error("Invalid credentials. Try admin / admin123 or viewer / viewer123.")
    with signup_tab:
        with st.form("signup"):
            username = st.text_input("Choose a username")
            password = st.text_input("Choose a password", type="password")
            admin_code = st.text_input("Admin code (optional)", type="password")
            submitted = st.form_submit_button("Create account", use_container_width=True)
            if submitted:
                if not username.strip() or not password:
                    st.error("Username and password are required.")
                elif admin_code and admin_code != "CGATE-ADMIN-2026":
                    st.error("Incorrect admin code.")
                else:
                    role = "Admin" if admin_code else "Viewer"
                    if create_user(username, password, role):
                        st.session_state.account = {"username": username.strip(), "role": role}
                        st.rerun()
                    st.error("That username already exists.")
    st.info("Demo access — Admin: admin / admin123 · Viewer: viewer / viewer123")
    st.markdown("</div>", unsafe_allow_html=True)


init_db()
if "account" not in st.session_state:
    st.session_state.account = None
if not st.session_state.account:
    auth_screen()
    st.stop()

account = st.session_state.account
is_admin = account["role"] == "Admin"
with st.sidebar:
    st.markdown("## 🛡️ CanaryGate")
    st.caption("SOC CONSOLE · v2.4")
    st.markdown(f"<span class='role-badge'>👤 {account['username']} · {account['role']}</span>", unsafe_allow_html=True)
    st.divider()
    st.success("Systems nominal")
    st.caption("Proxy and deception engine are reporting normally.")
    if st.button("Log out / switch account", use_container_width=True):
        st.session_state.account = None
        st.rerun()

st.markdown("<div class='small-mono'>FRIDAY, 25 SEPTEMBER 2026 / ZERO-TRUST MONITORING</div>", unsafe_allow_html=True)
st.title(f"Good morning, {account['username']}.")
st.caption("Here’s the current posture across your machine-identity perimeter.")
if not is_admin:
    st.markdown("<div class='readonly'>🔒 <b>Read-only mode.</b> You can inspect incidents and analytics. Admin accounts can update reviews and export reports.</div>", unsafe_allow_html=True)

if st.button("↻ Refresh data"):
    load_incidents.clear()
    st.rerun()

df = load_incidents()
metrics = [
    ("Total incidents", len(df)),
    ("🔴 Canary triggers", int((df["incident_type"] == "CANARY_TRIGGERED").sum()) if not df.empty else 0),
    ("🚫 Blocked high risk", int((df["incident_type"] == "BLOCKED_HIGH_RISK").sum()) if not df.empty else 0),
    ("⚠️ Allowed + warning", int((df["incident_type"] == "ALLOWED_WITH_WARNING").sum()) if not df.empty else 0),
    ("✅ False positives", int((df["review_status"] == "false_positive").sum()) if not df.empty else 0),
]
cols = st.columns(5)
for col, (label, value) in zip(cols, metrics):
    col.metric(label, value)

st.divider()
st.subheader("🔗 Correlated high-priority incidents")
alerts = correlated_alerts(df)
if alerts:
    for alert in alerts:
        st.error(f"**HIGH PRIORITY:** {alert['count']} alerts from `{alert['ip']}` ({alert['country']}) within 5 minutes, starting {alert['start']}")
else:
    st.success("No correlated multi-alert patterns detected.")

st.divider()
st.subheader("Live incident log")
search_col, type_col, severity_col = st.columns([2, 1, 1])
query = search_col.text_input("Search", placeholder="IP, technique, or event", label_visibility="collapsed")
type_filter = type_col.selectbox("Event type", ["All events", "CANARY_TRIGGERED", "BLOCKED_HIGH_RISK", "ALLOWED_WITH_WARNING"], label_visibility="collapsed")
severity_filter = severity_col.selectbox("Severity", ["All severities", "Critical", "High", "Medium", "Low"], label_visibility="collapsed")
view = df.copy()
if not view.empty:
    haystack = view.astype(str).apply(" ".join, axis=1).str.lower()
    if query:
        view = view[haystack.str.contains(query.lower(), na=False)]
    if type_filter != "All events":
        view = view[view["incident_type"] == type_filter]
    if severity_filter != "All severities":
        view = view[view["severity"] == severity_filter]

if not df.empty:
    export_cols = ["id", "timestamp", "source_ip", "country", "incident_type", "severity", "mitre_technique", "review_status", "details"]
    exp1, exp2 = st.columns(2)
    if is_admin:
        exp1.download_button("📥 Export CSV", df[export_cols].to_csv(index=False), "canarygate_incidents.csv", "text/csv", use_container_width=True)
        exp2.download_button("📥 Export JSON", df[export_cols].to_json(orient="records", indent=2), "canarygate_incidents.json", "application/json", use_container_width=True)
    else:
        st.caption("🔒 Exports are available to Admin accounts only.")
    display = view.copy()
    display["time"] = pd.to_datetime(display["timestamp"], unit="s")
    columns = ["id", "time", "source_ip", "country", "incident_type", "severity", "mitre_technique", "review_status", "ai_explanation"]
    st.dataframe(display[[column for column in columns if column in display.columns]], use_container_width=True, hide_index=True, height=340)
else:
    st.info("No incidents logged yet.")

st.divider()
st.subheader("🔍 Review incidents")
if is_admin and not df.empty:
    for _, row in df.head(10).iterrows():
        c1, c2, c3, c4 = st.columns([2.2, 1, 1, 1])
        c1.write(f"**#{row['id']}** · {row['incident_type']}")
        c2.write(str(row.get("severity", "N/A")))
        current = row.get("review_status", "unreviewed")
        choice = c3.selectbox("Status", ["unreviewed", "confirmed", "false_positive"], index=["unreviewed", "confirmed", "false_positive"].index(current), key=f"review_{row['id']}", label_visibility="collapsed")
        if choice != current and c4.button("Save", key=f"save_{row['id']}"):
            update_review_status(row["id"], choice)
            st.rerun()
elif not df.empty:
    st.caption("🔒 Marking incidents as confirmed or false-positive is available to Admin accounts only.")

st.divider()
st.subheader("🌍 Request origin map")
if not df.empty:
    counts = df["country"].value_counts().reset_index()
    counts.columns = ["country", "count"]
    counts["lat"] = counts["country"].map(lambda item: COORDS.get(item, (0, 0))[0])
    counts["lon"] = counts["country"].map(lambda item: COORDS.get(item, (0, 0))[1])
    fig = go.Figure(go.Scattergeo(lat=counts["lat"], lon=counts["lon"], text=counts["country"] + ": " + counts["count"].astype(str), mode="markers+text", textposition="top center", marker={"size": counts["count"] * 7 + 8, "color": "#55d9d3", "line": {"width": 1, "color": "#ffffff"}}))
    fig.update_geos(projection_type="orthographic", showland=True, landcolor="#1c2a3b", showocean=True, oceancolor="#0b101b", showcountries=True, countrycolor="#36455a", bgcolor="#0b101b")
    fig.update_layout(paper_bgcolor="#0b101b", font={"color": "#e8eef7"}, height=470, margin={"l": 0, "r": 0, "t": 0, "b": 0})
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No location data yet.")

st.caption("CanaryGate prototype · Data source: security.db · Use server-side authentication before production")
