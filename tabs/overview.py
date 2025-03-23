import streamlit as st
import plotly.express as px
from analysis import compute_packet_loss

def show_overview_tab(df_packets, df_delays, df_retrans):
    """
    Display the Overview tab with summary metrics and protocol distribution.
    """
    st.header("Overview")

    # Calculate metrics
    total_packets = len(df_packets)
    earliest_ts = df_packets["timestamp"].min() if total_packets > 0 else 0
    latest_ts = df_packets["timestamp"].max() if total_packets > 0 else 0
    packet_loss_pct = compute_packet_loss(df_packets, df_retrans)
    anomaly_count = len(df_delays[df_delays["is_anomaly"] == True]) if "is_anomaly" in df_delays.columns else 0
    avg_total_delay = df_delays["total_delay"].mean() if "total_delay" in df_delays.columns else 0

    # Display key metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Packets", f"{total_packets}")
    col2.metric("Avg E2E Delay", f"{avg_total_delay:.3f}s")
    col3.metric("Packet Loss %", f"{packet_loss_pct:.3f}%")

    # Protocol distribution visualization
    st.subheader("Protocol Distribution")
    if not df_packets.empty:
        proto_count = df_packets["protocol"].value_counts().reset_index()
        proto_count.columns = ["protocol", "count"]
        
        fig_proto = px.bar(
            proto_count, 
            x="protocol", 
            y="count",
            title="Packet Count by Protocol",
            labels={"count": "Count", "protocol": "Protocol"},
            color="protocol",
            color_discrete_map={
                "MQTT": "green",
                "TCP": "blue",
                "UDP": "orange",
                "OTHER": "gray"
            }
        )
        fig_proto.update_traces(marker_line_color='rgba(0,0,0,0.5)', marker_line_width=1)
        st.plotly_chart(fig_proto, use_container_width=True)
    else:
        st.info("No protocol data available.")