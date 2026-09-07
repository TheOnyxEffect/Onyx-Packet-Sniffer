import json
import os
import streamlit as st
import pandas as pd

ALERTS_FILE = "alerts.json"

st.set_page_config(
    page_title="Onyx Threat Detector",
    layout="wide",
)


def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


st.title("Onyx Threat Detector Dashboard")
st.caption("Live alerts from network traffic mapped to MITRE ATT&CK")

if st.button("Refresh Alerts"):
    st.rerun()
    
alerts = load_alerts()

if not alerts:
    st.info("No alerts yet. Make sure detector.py is running in another terminal.")
else:
    col1, col2, col3, col4 = st.columns(4)

    critical = len([a for a in alerts if a["severity"] == "Critical"])
    high = len([a for a in alerts if a["severity"] == "High"])
    medium = len([a for a in alerts if a["severity"] == "Medium"])
    low = len([a for a in alerts if a["severity"] == "Low"])

    col1.metric("Critical", critical)
    col2.metric("High", high)
    col3.metric("Medium", medium)
    col4.metric("Low", low)
    st.subheader("Alert Feed")

    df = pd.DataFrame(alerts)
    display_cols = ["timestamp", "severity", "rule", "technique", "tactic", "src_ip", "detail"]
    available = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available], use_container_width=True)

    st.subheader("MITRE ATT&CK Coverage")
    technique_counts = df["technique"].value_counts()
    st.bar_chart(technique_counts)

    st.subheader("Alerts by Severity")
    severity_order = ["Critical", "High", "Medium", "Low"]
    severity_counts = df["severity"].value_counts().reindex(severity_order, fill_value=0)
    st.bar_chart(severity_counts)