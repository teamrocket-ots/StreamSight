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
    
    try:
        # Process data for analysis
        df_udp, conn_stats = analyze_udp_delays(df_udp)
    except Exception as e:
        st.error(f"Error analyzing UDP data: {str(e)}")
        return

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
            try:
                total_loss = sum(stats.get('possible_loss_sum', 0) for stats in conn_stats.values())
                total_packets = sum(stats.get('total_packets', 0) for stats in conn_stats.values())
                if total_packets > 0:
                    loss_pct = (total_loss / (total_packets + total_loss)) * 100
                    st.metric("Estimated Packet Loss", f"{loss_pct:.2f}%")
            except Exception as e:
                st.warning(f"Couldn't calculate packet loss: {str(e)}")
    
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
    
    # Helper function for safe figure display
    def safe_display(fig_func, *args, **kwargs):
        try:
            fig = fig_func(*args, **kwargs)
            st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.error(f"Couldn't generate visualization: {str(e)}")

    with udp_tabs[0]:
        st.subheader("Inter-Packet Delay (IPD) Analysis")
        if "ipd" in df_udp.columns:
            ipd_data = df_udp[df_udp['ipd'].notna()]
            if not ipd_data.empty:
                safe_display(hist_with_boundaries, ipd_data, "ipd", "UDP Inter-Packet Delay Distribution", "green")
                
                if "timestamp" in df_udp.columns:
                    try:
                        fig = px.scatter(
                            ipd_data,
                            x="timestamp",
                            y="ipd",
                            color="conn_id" if len(ipd_data["conn_id"].unique()) < 10 else None,
                            title="Inter-Packet Delay Over Time",
                            labels={"ipd": "Delay (s)", "timestamp": "Time"}
                        )
                        safe_display(lambda: fig)
                    except Exception as e:
                        st.warning(f"Couldn't create time series: {str(e)}")
        else:
            st.warning("No Inter-Packet Delay data available.")

    with udp_tabs[1]:
        st.subheader("Jitter Analysis")
        if "jitter" in df_udp.columns:
            jitter_data = df_udp[df_udp['jitter'].notna()]
            if not jitter_data.empty:
                safe_display(hist_with_boundaries, jitter_data, "jitter", "UDP Jitter Distribution", "orange")
                
                if "conn_id" in jitter_data.columns:
                    try:
                        jitter_by_conn = jitter_data.groupby("conn_id")["jitter"].mean().reset_index()
                        fig = px.bar(
                            jitter_by_conn.sort_values("jitter", ascending=False),
                            x="conn_id",
                            y="jitter",
                            title="Average Jitter by Connection",
                            labels={"jitter": "Jitter (s)", "conn_id": "Connection"}
                        )
                        safe_display(lambda: fig)
                    except Exception as e:
                        st.warning(f"Couldn't create connection jitter plot: {str(e)}")
        else:
            st.warning("No Jitter data available.")

    with udp_tabs[2]:
        st.subheader("Packet Loss Analysis")
        if "possible_loss" in df_udp.columns:
            loss_data = df_udp[df_udp['possible_loss'] > 0]
            if not loss_data.empty:
                if "timestamp" in loss_data.columns:
                    try:
                        fig = px.scatter(
                            loss_data,
                            x="timestamp",
                            y="possible_loss",
                            size="possible_loss",
                            color="conn_id" if len(loss_data["conn_id"].unique()) < 10 else None,
                            title="Estimated Packet Loss Events",
                            labels={"possible_loss": "Lost Packets", "timestamp": "Time"}
                        )
                        safe_display(lambda: fig)
                    except Exception as e:
                        st.warning(f"Couldn't create loss timeline: {str(e)}")
                
                if "conn_id" in loss_data.columns:
                    try:
                        loss_by_conn = loss_data.groupby("conn_id")["possible_loss"].sum().reset_index()
                        fig = px.bar(
                            loss_by_conn.sort_values("possible_loss", ascending=False),
                            x="conn_id",
                            y="possible_loss",
                            title="Total Packet Loss by Connection",
                            labels={"possible_loss": "Lost Packets", "conn_id": "Connection"}
                        )
                        safe_display(lambda: fig)
                    except Exception as e:
                        st.warning(f"Couldn't create loss by connection plot: {str(e)}")
            else:
                st.info("No packet loss detected.")
        else:
            st.warning("No Packet Loss data available.")

    with udp_tabs[3]:
        st.subheader("Congestion Analysis")
        if "congestion_score" in df_udp.columns:
            congestion_data = df_udp[df_udp['congestion_score'].notna()]
            if not congestion_data.empty:
                safe_display(udp_jitter_plot, df_udp)
                safe_display(congestion_heatmap, df_udp)
                
                if "congestion_level" in df_udp.columns:
                    try:
                        congestion_counts = df_udp["congestion_level"].value_counts().reset_index()
                        congestion_counts.columns = ["Level", "Count"]
                        fig = px.pie(
                            congestion_counts,
                            values="Count",
                            names="Level",
                            title="Congestion Level Distribution",
                            color="Level",
                            color_discrete_map={
                                "Low": "green",
                                "Medium": "yellow",
                                "High": "orange",
                                "Very High": "red"
                            }
                        )
                        safe_display(lambda: fig)
                    except Exception as e:
                        st.warning(f"Couldn't create congestion pie chart: {str(e)}")
        else:
            st.warning("No Congestion data available.")