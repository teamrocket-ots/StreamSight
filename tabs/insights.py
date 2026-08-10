import pandas as pd
import plotly.express as px
import streamlit as st

from ui import STRETCH
from analysis import categorize_delays, detect_anomalies_in_delays

BOTTLENECK_COLOURS = {
    "Device→Broker": "#1E88E5",
    "Broker Processing": "#FFC107",
    "Cloud Upload": "#4CAF50",
}

SUMMARY_COLUMNS = [
    "msg_id",
    "device_to_broker_delay",
    "broker_processing_delay",
    "cloud_upload_delay",
    "total_delay",
    "bottleneck",
]


def show_insights_tab(df_delays: pd.DataFrame):
    """Categorised delays, thresholds and detected anomalies."""
    st.subheader("Categorisation & Anomalies")
    st.markdown(
        """
        StreamSight classifies transmission delays into:
        - **Device→Broker** transmission time
        - **Broker Processing** duration
        - **Cloud Upload** latency

        Anomalies are highlighted for faster troubleshooting.
        """
    )

    if df_delays is None or df_delays.empty:
        st.info(
            "No delay measurements available to categorise.\n\n"
            "This is expected for captures made entirely of MQTT QoS 0 traffic, "
            "which sends no PUBACK to pair a PUBLISH against."
        )
        return

    df_delays = df_delays.copy()

    if "bottleneck" not in df_delays.columns:
        df_delays = categorize_delays(df_delays)

    # Thresholds are recomputed every run. Caching them in session state made a
    # second upload display the previous capture's thresholds.
    df_delays, thresholds = detect_anomalies_in_delays(df_delays)

    st.subheader("Anomaly Detection Thresholds")
    if thresholds:
        st.table(pd.DataFrame({
            "Delay Type": list(thresholds),
            "Threshold (ms)": [f"{value:.3f}" for value in thresholds.values()],
        }))
    else:
        st.info("Not enough data to derive anomaly thresholds.")

    st.subheader("Bottleneck Analysis")
    if "bottleneck" in df_delays.columns and df_delays["bottleneck"].notna().any():
        counts = df_delays["bottleneck"].value_counts().reset_index()
        counts.columns = ["Bottleneck", "Count"]
        fig = px.pie(
            counts, values="Count", names="Bottleneck",
            title="Primary Delay Contributors",
            color="Bottleneck", color_discrete_map=BOTTLENECK_COLOURS,
        )
        st.plotly_chart(fig, **STRETCH, key="bottleneck_pie")
    else:
        st.info("Bottleneck analysis not available.")

    st.subheader("Detected Anomalies")
    if "is_anomaly" not in df_delays.columns:
        st.info("Anomaly detection not available.")
        return

    anomalies = df_delays[df_delays["is_anomaly"]]
    st.write(f"Number of anomalous messages: {len(anomalies)}")
    if anomalies.empty:
        st.info("No anomalies detected.")
        return

    available = [c for c in SUMMARY_COLUMNS if c in anomalies.columns]
    st.dataframe(anomalies[available], **STRETCH, key="anomalies_table")
