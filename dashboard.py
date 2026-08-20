import streamlit as st
import sqlite3
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import time
import math
import random

st.set_page_config(page_title="CanaryGate SOC Dashboard", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
[data-testid="stMetric"] {
    background-color: #161A25;
    border: 1px solid #262B3D;
    border-radius: 10px;
    padding: 15px;
}
h1 {
    background: linear-gradient(90deg, #00D4FF, #0077FF);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ CanaryGate — Security Operations Dashboard")
st.caption("Live Zero-Trust proxy monitoring")

COUNTRY_COORDS = {
    "Pakistan": (30.3753, 69.3451),
    "USA": (37.0902, -95.7129),
    "Germany": (51.1657, 10.4515),
    "Russia": (61.5240, 105.3188),
    "Unknown": (0, 0)
}

def load_incidents():
    conn = sqlite3.connect("security.db")
    df = pd.read_sql_query("SELECT * FROM incidents ORDER BY id DESC", conn)
    conn.close()
    return df

def update_review_status(incident_id, status):
    conn = sqlite3.connect("security.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE incidents SET review_status = ? WHERE id = ?", (status, incident_id))
    conn.commit()
    conn.close()

def find_correlated_alerts(df, window_seconds=300, min_alerts=3):
    if df.empty:
        return []
    correlated = []
    grouped = df.groupby("source_ip")
    for ip, group in grouped:
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()
        for i in range(len(timestamps)):
            window = [t for t in timestamps if timestamps[i] <= t <= timestamps[i] + window_seconds]
            if len(window) >= min_alerts:
                correlated.append({
                    "source_ip": ip,
                    "alert_count": len(window),
                    "window_start": pd.to_datetime(timestamps[i], unit="s")
                })
                break
    return correlated

df = load_incidents()

col1, col2, col3, col4, col5 = st.columns(5)

total_incidents = len(df)
canary_hits = len(df[df["incident_type"] == "CANARY_TRIGGERED"])
blocked = len(df[df["incident_type"] == "BLOCKED_HIGH_RISK"])
warnings = len(df[df["incident_type"] == "ALLOWED_WITH_WARNING"])
false_positives = len(df[df["review_status"] == "false_positive"]) if "review_status" in df.columns else 0

col1.metric("Total Incidents", total_incidents)
col2.metric("🔴 Canary Triggers", canary_hits)
col3.metric("🚫 Blocked (High Risk)", blocked)
col4.metric("⚠️ Warnings", warnings)
col5.metric("✅ False Positives", false_positives)

st.divider()

st.subheader("🔗 Correlated High-Priority Incidents")
correlated_alerts = find_correlated_alerts(df)
if correlated_alerts:
    for alert in correlated_alerts:
        st.error(f"**HIGH PRIORITY:** {alert['alert_count']} alerts from IP `{alert['source_ip']}` within 5 minutes (starting {alert['window_start']})")
else:
    st.success("No correlated multi-alert patterns detected.")

st.divider()

st.subheader("Live Incident Log")

exp1, exp2 = st.columns(2)
if not df.empty:
    csv_data = df.to_csv(index=False)
    exp1.download_button("📥 Export as CSV", csv_data, "canarygate_incidents.csv", "text/csv")
    json_data = df.to_json(orient="records", indent=2)
    exp2.download_button("📥 Export as JSON", json_data, "canarygate_incidents.json", "application/json")

if not df.empty:
    display_df = df.copy()
    display_df["time"] = pd.to_datetime(display_df["timestamp"], unit="s")
    st.dataframe(
        display_df[["time", "source_ip", "incident_type", "severity", "mitre_technique", "ai_explanation", "details"]],
        use_container_width=True,
        height=300
    )
else:
    st.info("No incidents logged yet.")

st.divider()

st.subheader("⏱️ Incident Timeline (Latest Canary/Block Event)")

critical_events = df[df["incident_type"].isin(["CANARY_TRIGGERED", "BLOCKED_HIGH_RISK"])]
if not critical_events.empty:
    latest = critical_events.iloc[0]
    event_time = pd.to_datetime(latest["timestamp"], unit="s")
    timeline_steps = [
        (event_time, f"Credential used: {str(latest['used_token'])[:20]}..."),
        (event_time, f"Detection: {latest['incident_type']}"),
        (event_time, f"Severity assigned: {latest.get('severity', 'N/A')}"),
        (event_time, "Response: Real tokens locked down" if latest["incident_type"] == "CANARY_TRIGGERED" else "Response: Request blocked")
    ]
    for i, (t, desc) in enumerate(timeline_steps):
        st.write(f"`{t}` → **Step {i+1}:** {desc}")
else:
    st.info("No critical events yet to show timeline.")

st.divider()

st.subheader("🔍 Review Incidents (Mark as Confirmed / False Positive)")

if not df.empty:
    recent = df.head(10)
    for _, row in recent.iterrows():
        c1, c2, c3, c4 = st.columns([2, 2, 2, 2])
        c1.write(f"**ID {row['id']}** — {row['incident_type']}")
        c2.write(f"Severity: {row.get('severity', 'N/A')}")
        c3.write(f"Status: {row.get('review_status', 'unreviewed')}")
        new_status = c4.selectbox(
            "Mark as",
            ["unreviewed", "confirmed", "false_positive"],
            index=["unreviewed", "confirmed", "false_positive"].index(row.get('review_status', 'unreviewed')),
            key=f"status_{row['id']}",
            label_visibility="collapsed"
        )
        if new_status != row.get('review_status', 'unreviewed'):
            update_review_status(row['id'], new_status)
            st.rerun()
else:
    st.info("No incidents to review.")

st.divider()

st.subheader("🌍 Request Origin Map (3D Globe)")

ip_country_map = {
    "127.0.0.1": "Pakistan",
    "172.34.54.67": "USA",
    "45.10.20.30": "Germany",
    "99.99.99.99": "Russia"
}

if not df.empty:
    df["country"] = df["source_ip"].map(ip_country_map).fillna("Unknown")
    country_counts = df["country"].value_counts().reset_index()
    country_counts.columns = ["country", "count"]
    country_counts["lat"] = country_counts["country"].apply(lambda c: COUNTRY_COORDS.get(c, (0,0))[0])
    country_counts["lon"] = country_counts["country"].apply(lambda c: COUNTRY_COORDS.get(c, (0,0))[1])
    country_counts["marker_size"] = country_counts["count"].apply(lambda c: min(10 + math.sqrt(c) * 6, 40))

    fig = go.Figure()
    random.seed(42)
    star_lats = [random.uniform(-90, 90) for _ in range(150)]
    star_lons = [random.uniform(-180, 180) for _ in range(150)]
    fig.add_trace(go.Scattergeo(
        lat=star_lats, lon=star_lons, mode="markers",
        marker=dict(size=1.5, color="#3A4258", opacity=0.6),
        showlegend=False, hoverinfo="skip"
    ))
    fig.add_trace(go.Scattergeo(
        lat=country_counts["lat"], lon=country_counts["lon"], mode="markers",
        marker=dict(size=country_counts["marker_size"] * 2.2, color="rgba(0, 212, 255, 0.18)", line=dict(width=0)),
        showlegend=False, hoverinfo="skip"
    ))
    fig.add_trace(go.Scattergeo(
        lat=country_counts["lat"], lon=country_counts["lon"],
        text=country_counts["country"] + ": " + country_counts["count"].astype(str),
        mode="markers+text",
        marker=dict(size=country_counts["marker_size"], color="#00E5FF", line=dict(width=1.5, color="#FFFFFF"), opacity=0.95),
        textposition="top center", textfont=dict(color="#FAFAFA", size=13),
        showlegend=False
    ))
    fig.update_geos(
        projection_type="orthographic",
        projection_rotation=dict(lon=40, lat=20, roll=0),
        showland=True, landcolor="#1C2333",
        showocean=True, oceancolor="#0B0E14",
        showcountries=True, countrycolor="#2E3548",
        showcoastlines=True, coastlinecolor="#2E3548",
        bgcolor="#0E1117"
    )
    fig.update_layout(
        paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
        font=dict(color="#FAFAFA"), margin=dict(l=0, r=0, t=10, b=0), height=550
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No location data yet.")

st.caption("Auto-refreshes every 10 seconds")
time.sleep(10)
st.rerun()
