import pandas as pd
import plotly.express as px  # noqa: F401 -- used by the category pie charts below
import streamlit as st

from analysis import categorize_delays, detect_anomalies_in_delays
from visualizations import hist_with_boundaries

CATEGORY_COLOURS = {
    "Low": "green",
    "Normal": "blue",
    "High": "orange",
    "Very High": "red",
}

DELAY_VIEWS = [
    ("device_to_broker_delay", "Device→Broker Delay", "blue"),
    ("broker_processing_delay", "Broker Processing Delay", "green"),
    ("cloud_upload_delay", "Cloud Upload Delay", "red"),
    ("total_delay", "Total Delay", "purple"),
]


def show_delay_analysis_tab(df_delays):
    """Per-component MQTT delay distributions, categories and anomalies."""
    st.subheader("Delay Breakdown by Component")

    if df_delays is None or df_delays.empty:
        st.info(
            "No MQTT delay measurements are available.\n\n"
            "Delay components need a PUBLISH paired with its PUBACK. Captures made "
            "entirely of QoS 0 traffic contain no PUBACK, so no end-to-end delay can "
            "be derived from them."
        )
        return

    df_delays = df_delays.copy()
    required = {c for c, _, _ in DELAY_VIEWS}
    missing = required - set(df_delays.columns)
    if missing == required:
        st.error("No MQTT delay data found in this capture.")
        return
    if missing:
        st.warning(f"Some delay metrics are missing: {', '.join(sorted(missing))}")

    if "bottleneck" not in df_delays.columns:
        df_delays = categorize_delays(df_delays)
    if "is_anomaly" not in df_delays.columns:
        df_delays, _ = detect_anomalies_in_delays(df_delays)

    _show_metrics(df_delays)

    tabs = st.tabs([label for _, label, _ in DELAY_VIEWS] + ["Anomalies"])
    for tab, (column, label, colour) in zip(tabs, DELAY_VIEWS):
        with tab:
            _show_delay_view(df_delays, column, label, colour)

    with tabs[-1]:
        _show_anomalies(df_delays)


def _show_metrics(df_delays):
    columns = st.columns(len(DELAY_VIEWS))
    for col, (column, label, _) in zip(columns, DELAY_VIEWS):
        if column in df_delays.columns:
            value = df_delays[column].mean()
            col.metric(f"Avg {label}", f"{value:.3f} ms" if pd.notna(value) else "N/A")
        else:
            col.metric(f"Avg {label}", "N/A")


def _show_delay_view(df_delays, column, label, colour):
    st.subheader(f"{label} Analysis")
    if column not in df_delays.columns:
        st.warning(f"{label} data not available.")
        return

    st.plotly_chart(
        hist_with_boundaries(df_delays, column, f"{label} Distribution", color=colour),
        use_container_width=True,
    )

    category_col = f"{column}_category"
    if category_col in df_delays.columns and df_delays[category_col].notna().any():
        counts = df_delays[category_col].value_counts().reset_index()
        counts.columns = ["Category", "Count"]
        fig = px.pie(
            counts, values="Count", names="Category",
            title=f"{label} Categories",
            color="Category", color_discrete_map=CATEGORY_COLOURS,
        )
        st.plotly_chart(fig, use_container_width=True)

    if column == "total_delay" and "bottleneck" in df_delays.columns:
        counts = df_delays["bottleneck"].value_counts().reset_index()
        counts.columns = ["Bottleneck", "Count"]
        fig = px.pie(
            counts, values="Count", names="Bottleneck",
            title="Delay Bottleneck Distribution",
            color="Bottleneck",
            color_discrete_map={
                "Device→Broker": "blue",
                "Broker Processing": "green",
                "Cloud Upload": "red",
            },
        )
        st.plotly_chart(fig, use_container_width=True)


def _show_anomalies(df_delays):
    st.subheader("Delay Anomalies")
    if "is_anomaly" not in df_delays.columns:
        st.warning("Anomaly detection data not available.")
        return

    anomaly_count = int(df_delays["is_anomaly"].sum())
    total = len(df_delays)
    pct = (anomaly_count / total * 100) if total else 0
    st.metric("Anomalies Detected", f"{anomaly_count} ({pct:.1f}%)")

    if not anomaly_count:
        st.info("No anomalies detected in the delay data.")
        return

    st.dataframe(df_delays[df_delays["is_anomaly"]], use_container_width=True)

    by_component = {}
    for col in df_delays.columns:
        if col.endswith("_anomaly"):
            label = col.replace("_anomaly", "").replace("_", " ").title()
            by_component[label] = int(df_delays[col].sum())

    if by_component:
        fig = px.bar(
            pd.DataFrame({
                "Component": list(by_component),
                "Anomaly Count": list(by_component.values()),
            }),
            x="Component", y="Anomaly Count",
            title="Anomalies by Component", color="Component",
        )
        st.plotly_chart(fig, use_container_width=True)
