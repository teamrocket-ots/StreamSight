import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

BOTTLENECK_COLOURS = {
    "Device→Broker": "#1E88E5",
    "Broker Processing": "#FFC107",
    "Cloud Upload": "#4CAF50",
}

#: Candidate delay series, in the order they are offered.
#: (label, frame key, column, timestamp column, unit)
SERIES = [
    ("TCP Round-Trip Time", "tcp", "rtt", "timestamp"),
    ("TCP ACK Delay", "tcp", "ack_delay", "timestamp"),
    ("TCP Inter-Packet Delay", "tcp", "ipd", "timestamp"),
    ("TCP Jitter", "tcp", "jitter", "timestamp"),
    ("UDP Inter-Packet Delay", "udp", "ipd", "timestamp"),
    ("UDP Jitter", "udp", "jitter", "timestamp"),
    ("MQTT Total Delay", "delays", "total_delay", "device_publish_time"),
    ("MQTT Device→Broker Delay", "delays", "device_to_broker_delay", "device_publish_time"),
]

#: Plotting every point of a large capture is slow and unreadable; beyond this
#: the series is sampled (deterministically, so the chart is stable on rerun).
MAX_POINTS = 4000


def show_timeline_tab(df_delays, df_retrans, df_tcp=None, df_udp=None):
    """Temporal view of whatever delay measurements the capture supports."""
    st.header("Timeline")
    st.markdown("Delay behaviour and network events over the life of the capture.")

    frames = {
        "tcp": df_tcp if df_tcp is not None else pd.DataFrame(),
        "udp": df_udp if df_udp is not None else pd.DataFrame(),
        "delays": df_delays if df_delays is not None else pd.DataFrame(),
    }

    available = [
        (label, key, column, time_col)
        for label, key, column, time_col in SERIES
        if _has_series(frames[key], column, time_col)
    ]

    if not available:
        st.info(
            "No delay measurements in this capture to plot over time.\n\n"
            "Delay needs a completed round trip — an acknowledged TCP segment, a "
            "multi-packet UDP flow, or an MQTT PUBLISH paired with its PUBACK."
        )
    else:
        _show_delay_timeline(frames, available)

    st.divider()
    _show_retransmission_timeline(df_retrans)

    if _has_series(frames["delays"], "total_delay", "device_publish_time"):
        st.divider()
        _show_correlations(frames["delays"])


def _has_series(df, column, time_col):
    return (
        df is not None
        and not df.empty
        and column in df.columns
        and time_col in df.columns
        and df[column].notna().any()
    )


def _show_delay_timeline(frames, available):
    labels = [entry[0] for entry in available]
    choice = st.selectbox("Metric", labels, index=0)
    label, key, column, time_col = next(e for e in available if e[0] == choice)

    source = frames[key]
    plot_df = source.loc[source[column].notna(), [time_col, column]].copy()

    # Timestamps are epoch seconds; reading them as milliseconds compresses the
    # capture 1000x and plots it in January 1970.
    plot_df["time"] = pd.to_datetime(plot_df[time_col], unit="s")

    for extra in ("conn_label", "bottleneck"):
        if extra in source.columns:
            plot_df[extra] = source.loc[plot_df.index, extra]

    mean_val = plot_df[column].mean()
    std_val = plot_df[column].std()
    threshold = mean_val + 2 * std_val if pd.notna(std_val) else None

    if threshold is not None:
        plot_df["Anomaly"] = np.where(plot_df[column] > threshold, "Anomaly", "Normal")
        anomalies = int((plot_df["Anomaly"] == "Anomaly").sum())
    else:
        anomalies = 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Samples", f"{len(plot_df):,}")
    col2.metric("Median", f"{plot_df[column].median():.3f} ms")
    col3.metric("95th pct", f"{plot_df[column].quantile(0.95):.3f} ms")
    col4.metric("Anomalies", f"{anomalies:,}")

    sampled = plot_df
    if len(plot_df) > MAX_POINTS:
        # Keep every anomaly, sample the rest: the outliers are the point of the chart.
        keep = plot_df[plot_df.get("Anomaly", "Normal") == "Anomaly"]
        rest = plot_df.drop(keep.index)
        sampled = pd.concat([
            keep, rest.sample(min(len(rest), MAX_POINTS), random_state=0)
        ]).sort_values("time")
        st.caption(
            f"Showing {len(sampled):,} of {len(plot_df):,} points "
            "(all anomalies kept, the rest sampled)."
        )

    colour = "Anomaly" if "Anomaly" in sampled.columns else None
    fig = px.scatter(
        sampled,
        x="time",
        y=column,
        color=colour,
        color_discrete_map={"Anomaly": "#d62728", "Normal": "#1f77b4"},
        hover_data=[c for c in ("conn_label",) if c in sampled.columns],
        title=f"{label} Over Time",
        labels={column: f"{label} (ms)", "time": "Time"},
        opacity=0.7,
    )
    fig.update_traces(marker=dict(size=5))
    if threshold is not None:
        fig.add_hline(
            y=threshold, line_dash="dot", line_color="red",
            annotation_text=f"Anomaly threshold ({threshold:.3f} ms)",
        )
    fig.update_xaxes(rangeslider_visible=True)
    st.plotly_chart(fig, use_container_width=True)

    if "bottleneck" in plot_df.columns and plot_df["bottleneck"].notna().any():
        counts = plot_df["bottleneck"].value_counts().reset_index()
        counts.columns = ["Bottleneck", "Count"]
        fig_b = px.bar(
            counts, x="Bottleneck", y="Count",
            title="Dominant Delay Contributor",
            color="Bottleneck", color_discrete_map=BOTTLENECK_COLOURS,
        )
        st.plotly_chart(fig_b, use_container_width=True)


def _show_retransmission_timeline(df_retrans):
    st.subheader("TCP Retransmissions")

    if df_retrans is None or df_retrans.empty:
        st.info("No TCP retransmission events detected.")
        return

    # The retransmission frame's time column is named "time", not "timestamp".
    time_col = next((c for c in ("time", "timestamp") if c in df_retrans.columns), None)
    if time_col is None:
        st.warning("Retransmission events have no timestamp column to plot.")
        return

    plot_df = df_retrans.copy()
    plot_df["timestamp"] = pd.to_datetime(plot_df[time_col], unit="s")

    col1, col2 = st.columns([1, 3])
    col1.metric("Total Retransmissions", f"{len(df_retrans):,}")

    fig = px.scatter(
        plot_df, x="timestamp", y=[1] * len(plot_df),
        title="Retransmission Events",
        labels={"timestamp": "Time"}, height=220,
    )
    fig.update_traces(marker=dict(color="red", size=9, symbol="line-ns", line=dict(width=2)))
    fig.update_yaxes(visible=False)
    with col2:
        st.plotly_chart(fig, use_container_width=True)


def _show_correlations(df_delays):
    st.subheader("MQTT Delay Correlations")
    corr_columns = [
        col for col in
        ("device_to_broker_delay", "broker_processing_delay",
         "cloud_upload_delay", "total_delay")
        if col in df_delays.columns
    ]
    if len(corr_columns) < 2:
        st.info("Not enough delay components for a correlation matrix.")
        return

    fig = px.imshow(
        df_delays[corr_columns].corr(),
        text_auto=True, color_continuous_scale="RdBu_r",
        title="Delay Component Correlations",
    )
    st.plotly_chart(fig, use_container_width=True)
