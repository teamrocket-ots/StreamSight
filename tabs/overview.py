import plotly.express as px
import streamlit as st

from ui import STRETCH
from analysis import compute_retransmission_rate
from pcap_parser import PROTO_MQTT_TLS
from visualizations import format_ms

PROTOCOL_COLOURS = {
    "MQTT": "green",
    PROTO_MQTT_TLS: "teal",
    "TCP": "blue",
    "UDP": "orange",
    "OTHER": "gray",
}


def show_overview_tab(df_packets, df_delays, df_retrans):
    """Capture-level summary metrics and protocol distribution."""
    st.header("Overview")

    total_packets = len(df_packets)
    retrans_rate = compute_retransmission_rate(df_packets, df_retrans)

    anomaly_count = (
        int(df_delays["is_anomaly"].sum())
        if not df_delays.empty and "is_anomaly" in df_delays.columns else 0
    )
    avg_total_delay = (
        df_delays["total_delay"].mean()
        if not df_delays.empty and "total_delay" in df_delays.columns else None
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Packets", f"{total_packets}")
    col2.metric(
        "Avg MQTT E2E Delay",
        format_ms(avg_total_delay) if avg_total_delay is not None else "N/A",
    )
    col3.metric(
        "TCP Retransmission Rate",
        f"{retrans_rate:.3f}%",
        help="Retransmitted packets as a share of TCP packets. A proxy for loss, "
             "not a direct measurement of it.",
    )
    col4.metric("Delay Anomalies", f"{anomaly_count}")

    if not df_packets.empty and "timestamp" in df_packets.columns:
        duration = df_packets["timestamp"].max() - df_packets["timestamp"].min()
        st.caption(f"Capture duration: {duration:.2f} s across {total_packets} packets.")

    st.subheader("Protocol Distribution")
    if df_packets.empty or "protocol" not in df_packets.columns:
        st.info("No protocol data available.")
        return

    proto_count = df_packets["protocol"].value_counts().reset_index()
    proto_count.columns = ["protocol", "count"]

    fig = px.bar(
        proto_count, x="protocol", y="count",
        title="Packet Count by Protocol",
        labels={"count": "Count", "protocol": "Protocol"},
        color="protocol", color_discrete_map=PROTOCOL_COLOURS,
    )
    fig.update_traces(marker_line_color="rgba(0,0,0,0.5)", marker_line_width=1)
    st.plotly_chart(fig, **STRETCH, key="overview_chart_1")

    if PROTO_MQTT_TLS in set(proto_count["protocol"]):
        encrypted = int((df_packets["protocol"] == PROTO_MQTT_TLS).sum())
        decoded = int((df_packets["protocol"] == "MQTT").sum())
        st.caption(
            f"**MQTT totals — {decoded + encrypted} packets: "
            f"{decoded} decoded, {encrypted} encrypted.** "
            "Encrypted MQTT is TLS on port 8883, identified by port rather than by "
            "decoding it. Message types, IDs and QoS cannot be read, so it is "
            "analysed on the **TCP Analysis** tab, where transport-level metrics "
            "(RTT, retransmissions, window events) still apply."
        )

    if "ip_version" in df_packets.columns:
        versions = df_packets["ip_version"].value_counts().to_dict()
        parts = [f"IPv{int(k)}: {v}" for k, v in sorted(versions.items()) if k == k]
        if parts:
            st.caption("Address families — " + ", ".join(parts))
