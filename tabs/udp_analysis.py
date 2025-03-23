import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

from visualizations import hist_with_boundaries, udp_jitter_plot, congestion_heatmap
from analysis import analyze_udp_delays

def show_udp_analysis_tab(df_udp):
    """Display UDP-specific analysis and visualizations"""
    st.header("UDP Delay Analysis")
    
    if df_udp.empty:
        st.warning("No UDP data available in the uploaded PCAP file.")
        return
    
    # Process data for analysis
    df_udp, conn_stats = analyze_udp_delays(df_udp)
    
    # Overview metrics
    st.subheader("UDP Performance Overview")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if "ipd" in df_udp.columns:
            ipd_data = df_udp[df_udp['ipd'].notna()]
            if not ipd_data.empty:
                st.metric("Average Inter-Packet Delay", f"{ipd_data['ipd'].mean():.4f}s")
        
        # Estimated packet loss
        if conn_stats:
            total_loss = sum(stats.get('possible_loss_sum', 0) for stats in conn_stats.values())
            total_packets = sum(stats.get('total_packets', 0) for stats in conn_stats.values())
            if total_packets > 0:
                loss_pct = (total_loss / (total_packets + total_loss)) * 100
                st.metric("Estimated Packet Loss", f"{loss_pct:.2f}%")
    
    with col2:
        if "jitter" in df_udp.columns:
            jitter_data = df_udp[df_udp['jitter'].notna()]
            if not jitter_data.empty:
                st.metric("Average Jitter", f"{jitter_data['jitter'].mean():.4f}s")
                st.metric("Max Jitter", f"{jitter_data['jitter'].max():.4f}s")
    
    with col3:
        if "congestion_score" in df_udp.columns:
            congestion_data = df_udp[df_udp['congestion_score'].notna()]
            if not congestion_data.empty:
                st.metric("Average Congestion Score", f"{congestion_data['congestion_score'].mean():.4f}")
        
        # Total connections
        if "conn_id" in df_udp.columns:
            st.metric("Total UDP Connections", f"{len(df_udp['conn_id'].unique())}")
    
    # Create tabs for different analyses
    udp_tabs = st.tabs([
        "Inter-Packet Delay", 
        "Jitter Analysis", 
        "Packet Loss", 
        "Congestion Analysis"
    ])
    
    with udp_tabs[0]:
        st.subheader("Inter-Packet Delay (IPD) Analysis")
        if "ipd" in df_udp.columns:
            ipd_data = df_udp[df_udp['ipd'].notna()]
            if not ipd_data.empty:
                st.plotly_chart(hist_with_boundaries(ipd_data, "ipd", "UDP Inter-Packet Delay Distribution", color="green"), use_container_width=True)
                
                # Show IPD variation over time
                if "timestamp" in df_udp.columns:
                    fig = px.scatter(
                        ipd_data,
                        x="timestamp",
                        y="ipd",
                        color="conn_id" if len(ipd_data["conn_id"].unique()) < 10 else None,
                        title="Inter-Packet Delay Over Time",
                        labels={"ipd": "Inter-Packet Delay (s)", "timestamp": "Time"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No Inter-Packet Delay measurements detected in the data.")
        else:
            st.warning("No Inter-Packet Delay data available.")
    
    with udp_tabs[1]:
        st.subheader("Jitter Analysis")
        if "jitter" in df_udp.columns:
            jitter_data = df_udp[df_udp['jitter'].notna()]
            if not jitter_data.empty:
                st.plotly_chart(hist_with_boundaries(jitter_data, "jitter", "UDP Jitter Distribution", color="orange"), use_container_width=True)
                
                # Show jitter by connection
                if "conn_id" in jitter_data.columns:
                    jitter_by_conn = jitter_data.groupby("conn_id")["jitter"].mean().reset_index()
                    
                    fig = px.bar(
                        jitter_by_conn.sort_values("jitter", ascending=False),
                        x="conn_id",
                        y="jitter",
                        title="Average Jitter by Connection",
                        labels={"jitter": "Average Jitter (s)", "conn_id": "Connection"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No jitter measurements detected in the data.")
        else:
            st.warning("No Jitter data available.")
    
    with udp_tabs[2]:
        st.subheader("Packet Loss Analysis")
        if "possible_loss" in df_udp.columns:
            loss_data = df_udp[df_udp['possible_loss'] > 0]
            if not loss_data.empty:
                # Show packet loss over time
                if "timestamp" in loss_data.columns:
                    fig = px.scatter(
                        loss_data,
                        x="timestamp",
                        y="possible_loss",
                        size="possible_loss",
                        color="conn_id" if len(loss_data["conn_id"].unique()) < 10 else None,
                        title="Estimated Packet Loss Events Over Time",
                        labels={"possible_loss": "Estimated Lost Packets", "timestamp": "Time"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Show packet loss by connection
                if "conn_id" in loss_data.columns:
                    loss_by_conn = loss_data.groupby("conn_id")["possible_loss"].sum().reset_index()
                    
                    fig = px.bar(
                        loss_by_conn.sort_values("possible_loss", ascending=False),
                        x="conn_id",
                        y="possible_loss",
                        title="Total Estimated Packet Loss by Connection",
                        labels={"possible_loss": "Estimated Lost Packets", "conn_id": "Connection"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No packet loss detected in the data.")
        else:
            st.warning("No Packet Loss data available.")
    
    with udp_tabs[3]:
        st.subheader("Congestion Analysis")
        if "congestion_score" in df_udp.columns:
            congestion_data = df_udp[df_udp['congestion_score'].notna()]
            if not congestion_data.empty:
                # Plot jitter vs packet loss
                st.plotly_chart(udp_jitter_plot(df_udp), use_container_width=True)
                
                # Show congestion heatmap
                st.plotly_chart(congestion_heatmap(df_udp), use_container_width=True)
                
                # Show congestion level distribution
                if "congestion_level" in df_udp.columns:
                    congestion_counts = df_udp["congestion_level"].value_counts().reset_index()
                    congestion_counts.columns = ["Congestion Level", "Count"]
                    
                    fig = px.pie(
                        congestion_counts,
                        values="Count",
                        names="Congestion Level",
                        title="Distribution of Congestion Levels",
                        color="Congestion Level",
                        color_discrete_map={
                            "Low": "green",
                            "Medium": "yellow",
                            "High": "orange",
                            "Very High": "red"
                        }
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No congestion measurements detected in the data.")
        else:
            st.warning("No Congestion data available.")
