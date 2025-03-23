import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from visualizations import hist_with_boundaries
from analysis import analyze_tcp_delays, categorize_delays

def show_tcp_analysis_tab(df_packets, df_retrans):
    """Display TCP-specific analysis and visualizations using general packet data"""
    st.header("TCP Delay Analysis")
    
    # Filter for TCP packets only
    tcp_packets = df_packets[df_packets["protocol"] == "TCP"].copy() if "protocol" in df_packets.columns else pd.DataFrame()
    
    if tcp_packets.empty:
        st.warning("No TCP data available in the uploaded PCAP file.")
        return
    
    # Calculate basic TCP metrics
    total_tcp_packets = len(tcp_packets)
    retrans_count = len(df_retrans) if not df_retrans.empty else 0
    packet_loss_pct = (retrans_count / total_tcp_packets) * 100 if total_tcp_packets > 0 else 0
    
    # Overview metrics
    st.subheader("TCP Performance Overview")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total TCP Packets", f"{total_tcp_packets}")
    
    with col2:
        st.metric("Retransmissions", f"{retrans_count}")
    
    with col3:
        st.metric("Packet Loss", f"{packet_loss_pct:.2f}%")
    
    # Create tabs for different analyses
    tcp_tabs = st.tabs([
        "Retransmission Analysis", 
        "TCP Flow", 
        "TCP Connections",
    ])
    
    with tcp_tabs[0]:
        st.subheader("Retransmission Analysis")
        if not df_retrans.empty:
            # Show retransmissions over time
            retrans_over_time = df_retrans.copy()
            retrans_over_time["count"] = 1
            
            try:
                # Convert epoch to datetime and set as index
                retrans_over_time["time"] = pd.to_datetime(retrans_over_time["time"], unit='s')
                retrans_grouped = retrans_over_time.set_index("time")
                retrans_grouped = retrans_grouped.resample("1s").sum()["count"].reset_index()
                
                fig = px.line(
                    retrans_grouped,
                    x="time",
                    y="count",
                    title="Retransmissions Over Time",
                    labels={"count": "Number of Retransmissions", "time": "Time"}
                )
                # Format datetime axis properly
                fig.update_xaxes(
                    tickformat="%H:%M:%S",
                    rangeslider_visible=True
                )
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Error creating timeline: {str(e)}")
                
            # Display raw retransmission data
            st.subheader("Retransmission Events")
            st.dataframe(df_retrans)
        else:
            st.info("No retransmissions detected in the data.")
    
    # In tcp_analysis.py, modify the TCP Flow Analysis section:
    with tcp_tabs[1]:
        st.subheader("TCP Flow Analysis")
        
        if "timestamp" in tcp_packets.columns:
            # Convert epoch timestamp to datetime
            tcp_packets["datetime"] = pd.to_datetime(tcp_packets["timestamp"], unit='s')
            
            try:
                # Group by time intervals using datetime
                tcp_flow = tcp_packets.set_index("datetime")
                tcp_flow = tcp_flow.resample("1s").size().reset_index(name="packet_count")
                
                fig = px.area(
                    tcp_flow,
                    x="datetime",
                    y="packet_count",
                    title="TCP Traffic Flow",
                    labels={"packet_count": "Packet Count", "datetime": "Time"}
                )
                # Improve time axis formatting
                fig.update_xaxes(
                    tickformat="%H:%M:%S",
                    rangeslider_visible=True
                )
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Error creating flow chart: {str(e)}")
        else:
            st.warning("Timestamp data not available for TCP flow analysis.")
    
    with tcp_tabs[2]:
        st.subheader("TCP Connection Analysis")
        
        if all(col in tcp_packets.columns for col in ["src_ip", "dst_ip", "src_port", "dst_port"]):
            # Create connection IDs
            tcp_packets["conn_id"] = tcp_packets.apply(
                lambda row: f"{row['src_ip']}:{row['src_port']}-{row['dst_ip']}:{row['dst_port']}", 
                axis=1
            )
            
            # Count packets per connection
            conn_stats = tcp_packets.groupby("conn_id").size().reset_index(name="packet_count")
            conn_stats = conn_stats.sort_values("packet_count", ascending=False)
            
            # Show top connections
            st.subheader("Top TCP Connections")
            
            fig = px.bar(
                conn_stats.head(10),
                x="conn_id",
                y="packet_count",
                title="Top 10 TCP Connections by Packet Count",
                labels={"conn_id": "Connection", "packet_count": "Packet Count"}
            )
            fig.update_layout(xaxis={'tickangle': 45})
            st.plotly_chart(fig, use_container_width=True)
            
            # Show connection details
            st.subheader("TCP Connection Details")
            st.dataframe(conn_stats)
        else:
            st.warning("IP and port data not available for connection analysis.")
