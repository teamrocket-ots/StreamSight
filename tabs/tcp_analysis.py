import pandas as pd
import plotly.express as px
import streamlit as st

from analysis import analyze_tcp_delays, compute_retransmission_rate
from pcap_parser import TCP_PROTOCOLS
from visualizations import (
    connection_rtt_chart,
    delay_over_time,
    format_ms,
    tcp_delay_distribution,
    tcp_health_timeline,
)

#: Metrics surfaced as their own sub-tab, with the unit used for display.
DELAY_METRICS = [
    ("rtt", "Round-Trip Time", "Time between a segment and its acknowledgement."),
    ("ack_delay", "ACK Delay", "Time from sending data to the peer acknowledging it."),
    ("ipd", "Inter-Packet Delay", "Gap between consecutive packets on a connection."),
    ("jitter", "Jitter", "Variation in inter-packet delay."),
    ("retrans_delay", "Retransmission Delay", "Gap back to the original transmission."),
]

HEALTH_COLUMNS = [
    ("is_retrans", "Retransmissions", "Segments the receiver never acknowledged in time."),
    ("zero_window", "Zero Window", "Receiver buffer full — a receiver-side stall, not a network fault."),
    ("window_full", "Window Full", "Sender has filled the receiver's advertised window."),
    ("duplicate_ack", "Duplicate ACKs", "Usually indicates a gap in the received sequence."),
    ("out_of_order", "Out of Order", "Segments arriving out of sequence."),
    ("spurious_retrans", "Spurious Retransmissions", "Data resent that had already arrived."),
]


def show_tcp_analysis_tab(df_packets, df_retrans, df_tcp=None):
    """Display TCP performance analysis built on the per-packet metric frame."""
    st.header("TCP")

    if df_tcp is None:
        df_tcp = pd.DataFrame()

    # Decoded and encrypted MQTT both ride on TCP, so both belong in TCP totals.
    tcp_packets = (
        df_packets[df_packets["protocol"].isin(TCP_PROTOCOLS)]
        if not df_packets.empty and "protocol" in df_packets.columns
        else pd.DataFrame()
    )

    if tcp_packets.empty and df_tcp.empty:
        st.warning("No TCP data available in this capture.")
        return

    if not df_tcp.empty:
        df_tcp, conn_stats = analyze_tcp_delays(df_tcp.copy())
    else:
        conn_stats = {}

    _show_overview(tcp_packets, df_retrans, df_tcp, df_packets)

    tab_labels = ["Delay Metrics", "TCP Health", "Connections", "Traffic Flow", "Retransmissions"]
    tcp_tabs = st.tabs(tab_labels)

    with tcp_tabs[0]:
        _show_delay_metrics(df_tcp)
    with tcp_tabs[1]:
        _show_health(df_tcp)
    with tcp_tabs[2]:
        _show_connections(df_tcp, conn_stats)
    with tcp_tabs[3]:
        _show_flow(tcp_packets)
    with tcp_tabs[4]:
        _show_retransmissions(df_retrans)


def _show_overview(tcp_packets, df_retrans, df_tcp, df_packets):
    st.subheader("TCP Performance Overview")
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("TCP Packets", f"{len(tcp_packets)}")
    col2.metric("Retransmissions", f"{len(df_retrans)}")
    # Same denominator as the Overview tab, so the two agree.
    col3.metric(
        "Retransmission Rate",
        f"{compute_retransmission_rate(df_packets, df_retrans):.2f}%",
        help="Retransmitted packets as a share of TCP packets. A proxy for loss, not a direct measurement.",
    )

    if not df_tcp.empty and "rtt" in df_tcp.columns:
        rtt = df_tcp["rtt"].dropna()
        col4.metric("Median RTT", format_ms(rtt.median()) if not rtt.empty else "N/A")
    else:
        col4.metric("Median RTT", "N/A")


def _show_delay_metrics(df_tcp):
    st.subheader("Delay Metric Distributions")
    if df_tcp.empty:
        st.info("No per-packet TCP metrics available.")
        return

    available = [
        (col, label, help_text)
        for col, label, help_text in DELAY_METRICS
        if col in df_tcp.columns and df_tcp[col].notna().any()
    ]
    if not available:
        st.info(
            "No delay metrics could be measured. This happens when a capture holds "
            "no complete request/response pairs — for example a one-way capture."
        )
        return

    metric_tabs = st.tabs([label for _, label, _ in available])
    for tab, (col, label, help_text) in zip(metric_tabs, available):
        with tab:
            st.caption(help_text)
            series = df_tcp[col].dropna()
            stat1, stat2, stat3, stat4 = st.columns(4)
            stat1.metric("Samples", f"{len(series)}")
            stat2.metric("Mean", format_ms(series.mean()))
            stat3.metric("Median", format_ms(series.median()))
            stat4.metric("95th pct", format_ms(series.quantile(0.95)))

            st.plotly_chart(
                tcp_delay_distribution(df_tcp, col, f"TCP {label} Distribution"),
                use_container_width=True,
                key=f"tcp_dist_{col}",
            )

            if "timestamp" in df_tcp.columns:
                fig, log_scale = delay_over_time(df_tcp, col, label)
                st.plotly_chart(fig, use_container_width=True, key=f"tcp_time_{col}")
                if log_scale:
                    st.caption(
                        "Y-axis is logarithmic: this metric is heavily right-tailed, "
                        "so a linear axis would flatten every point onto the baseline."
                    )


def _show_health(df_tcp):
    st.subheader("TCP Health Events")
    st.caption(
        "These are the direct causes of transmission delay. A zero-window event means "
        "the receiver's buffer filled — the delay is flow control, not the network."
    )
    if df_tcp.empty:
        st.info("No TCP health data available.")
        return

    present = [(c, label, hint) for c, label, hint in HEALTH_COLUMNS if c in df_tcp.columns]
    if not present:
        st.info("No TCP expert-analysis fields available in this capture.")
        return

    cols = st.columns(min(len(present), 3))
    for index, (column, label, hint) in enumerate(present):
        count = int(df_tcp[column].fillna(False).astype(bool).sum())
        cols[index % len(cols)].metric(label, f"{count}", help=hint)

    st.plotly_chart(tcp_health_timeline(df_tcp), use_container_width=True, key="tcp_analysis_chart_2")


def _show_connections(df_tcp, conn_stats):
    st.subheader("Connection Analysis")
    if df_tcp.empty or "conn_id" not in df_tcp.columns:
        st.info("No connection data available.")
        return

    label_col = "conn_label" if "conn_label" in df_tcp.columns else "conn_id"
    st.metric("Distinct TCP Connections", f"{df_tcp['conn_id'].nunique()}")

    st.plotly_chart(connection_rtt_chart(df_tcp), use_container_width=True, key="tcp_analysis_chart_3")

    _show_encrypted_stream_metrics(df_tcp, label_col)

    aggregations = {"packets": ("timestamp", "size")}
    for col in ("rtt", "ack_delay", "ipd", "jitter"):
        if col in df_tcp.columns:
            aggregations[f"mean_{col}"] = (col, "mean")
    for col in ("conn_bytes", "conn_duration", "conn_throughput_kbps", "tls_handshake_ms"):
        if col in df_tcp.columns:
            aggregations[col] = (col, "first")
    if "is_retrans" in df_tcp.columns:
        aggregations["retransmissions"] = ("is_retrans", "sum")

    summary = df_tcp.groupby(label_col).agg(**aggregations).reset_index()
    summary = summary.sort_values("packets", ascending=False)

    st.subheader("Per-Connection Summary")
    st.dataframe(summary, use_container_width=True)


def _show_encrypted_stream_metrics(df_tcp, label_col):
    """Throughput and TLS setup cost — what stays measurable when the payload is encrypted."""
    has_throughput = "conn_throughput_kbps" in df_tcp.columns
    has_handshake = "tls_handshake_ms" in df_tcp.columns and df_tcp["tls_handshake_ms"].notna().any()

    if not has_throughput and not has_handshake:
        return

    st.subheader("Encrypted Stream Metrics")
    st.caption(
        "For TLS-encrypted streams (including MQTT over port 8883) the payload cannot "
        "be inspected, but transport behaviour still can."
    )

    col1, col2 = st.columns(2)
    if has_throughput:
        per_conn = df_tcp.groupby(label_col)["conn_throughput_kbps"].first().dropna()
        if not per_conn.empty:
            col1.metric("Peak Throughput", f"{per_conn.max():,.0f} kbit/s")
            col1.metric("Total Bytes", f"{int(df_tcp.groupby(label_col)['conn_bytes'].first().sum()):,}")

    if has_handshake:
        handshakes = df_tcp.groupby(label_col)["tls_handshake_ms"].first().dropna()
        if not handshakes.empty:
            col2.metric("Median TLS Handshake", format_ms(handshakes.median()))
            col2.metric("Slowest TLS Handshake", format_ms(handshakes.max()))


def _show_flow(tcp_packets):
    st.subheader("TCP Traffic Flow")
    if tcp_packets.empty or "timestamp" not in tcp_packets.columns:
        st.warning("Timestamp data not available for flow analysis.")
        return

    flow = tcp_packets.copy()
    # Epoch seconds, not milliseconds: unit='ms' here compresses the capture
    # 1000x and plots it in January 1970.
    flow["datetime"] = pd.to_datetime(flow["timestamp"], unit="s")

    try:
        resampled = flow.set_index("datetime").resample("1s").size().reset_index(name="packet_count")
        fig = px.area(
            resampled, x="datetime", y="packet_count",
            title="TCP Traffic Flow",
            labels={"packet_count": "Packet Count", "datetime": "Time"},
        )
        fig.update_xaxes(tickformat="%H:%M:%S", rangeslider_visible=True)
        st.plotly_chart(fig, use_container_width=True, key="tcp_analysis_chart_4")
    except Exception as exc:
        st.error(f"Error creating flow chart: {exc}")


def _show_retransmissions(df_retrans):
    st.subheader("Retransmission Analysis")
    if df_retrans.empty:
        st.info("No retransmissions detected in this capture.")
        return

    over_time = df_retrans.copy()
    over_time["count"] = 1
    try:
        over_time["time"] = pd.to_datetime(over_time["time"], unit="s")
        grouped = over_time.set_index("time").resample("1s").sum(numeric_only=True)
        grouped = grouped["count"].reset_index()

        fig = px.line(
            grouped, x="time", y="count",
            title="Retransmissions Over Time",
            labels={"count": "Number of Retransmissions", "time": "Time"},
        )
        fig.update_xaxes(tickformat="%H:%M:%S", rangeslider_visible=True)
        st.plotly_chart(fig, use_container_width=True, key="tcp_analysis_chart_5")
    except Exception as exc:
        st.error(f"Error creating timeline: {exc}")

    st.subheader("Retransmission Events")
    st.dataframe(df_retrans, use_container_width=True)
