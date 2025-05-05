import streamlit as st
import pandas as pd
import requests

st.title("AI-Powered SOC Dashboard")
uploaded_file = st.file_uploader("Upload Network Logs (CSV)", type=["csv"])

if uploaded_file:
    response = requests.post(
        "http://localhost:8000/predict_anomaly/",
        files={"file": uploaded_file}
    )
    alerts = response.json()
    st.subheader("Detected Anomalies")
    if alerts:
        df_alerts = pd.DataFrame(alerts)
        st.dataframe(df_alerts)
    else:
        st.success("No anomalies detected!")
