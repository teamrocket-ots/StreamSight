import streamlit as st
import pandas as pd
import plotly.express as px


def show_timeline_tab(df_delays, df_retrans):
    """
    Display temporal analysis of packet transmission
    """
    st.header("Timeline Analysis")
    st.markdown("""
    Temporal analysis of packet transmission, showing patterns, delays, anomalies, and congestion events over time.
    """)

    # Enhanced time-series visualization
    if not df_delays.empty:
        df_delays_plot = df_delays.copy()
        df_delays_plot["timestamp"] = pd.to_datetime(df_delays_plot["device_publish_time"], unit='s')
        
        # Check if bottleneck column exists
        bottleneck_col = "bottleneck" if "bottleneck" in df_delays_plot.columns else None
        is_anomaly_col = "is_anomaly" if "is_anomaly" in df_delays_plot.columns else None
        
        # Set up plot parameters
        plot_params = {
            "data_frame": df_delays_plot,
            "x": "timestamp",
            "y": "total_delay",
            "size": "total_delay",
            "size_max": 15,
            "title": "Total Delay Over Time with Bottleneck Identification",
            "labels": {
                "timestamp": "Time", 
                "total_delay": "Total Delay (s)",
                "bottleneck": "Primary Delay Contributor"
            }
        }
        
        # Add bottleneck coloring if available
        if bottleneck_col:
            plot_params["color"] = bottleneck_col
            plot_params["color_discrete_map"] = {
                "Device→Broker": "#1E88E5",
                "Broker Processing": "#FFC107",
                "Cloud Upload": "#4CAF50"
            }
        
        # Add symbol mapping only if the anomaly column exists
        if is_anomaly_col:
            # Create a temporary column in the dataframe for the symbols
            df_delays_plot["symbol_col"] = df_delays_plot[is_anomaly_col].map({True: "triangle-up", False: "circle"})
            plot_params["symbol"] = "symbol_col"
        
        # Create figure
        fig_timeline = px.scatter(**plot_params)
        
        # Add horizontal lines for mean and thresholds
        fig_timeline.add_hline(
            y=df_delays["total_delay"].mean(), 
            line_width=1, 
            line_dash="dash", 
            line_color="black",
            annotation_text="Mean", 
            annotation_position="right"
        )
        
        # Add threshold line if available in session state
        if "thresholds" in st.session_state and "total_delay" in st.session_state.thresholds:
            fig_timeline.add_hline(
                y=st.session_state.thresholds["total_delay"], 
                line_width=1, 
                line_dash="dot", 
                line_color="red",
                annotation_text="Anomaly Threshold", 
                annotation_position="right"
            )
        
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Correlation heatmap between delays
        st.subheader("Delay Correlations")
        corr_columns = ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay", "total_delay"]
        corr_matrix = df_delays[corr_columns].corr()
        
        fig_corr = px.imshow(
            corr_matrix,
            text_auto=True,
            color_continuous_scale='RdBu_r',
            title="Correlation Between Different Delay Types"
        )
        st.plotly_chart(fig_corr, use_container_width=True)
    else:
        st.info("No delay data available for timeline analysis.")

    # Also show retransmissions over time if we have any
    if not df_retrans.empty:
        df_retrans_plot = df_retrans.copy()
        df_retrans_plot["timestamp"] = pd.to_datetime(df_retrans_plot["time"], unit='s')
        
        fig_ret = px.scatter(
            df_retrans_plot, 
            x="timestamp", 
            y=[1]*len(df_retrans_plot),
            title="TCP Retransmissions Over Time",
            labels={"timestamp":"Time"},
            height=250
        )
        fig_ret.update_traces(marker=dict(color="red", size=10, symbol="x"))
        fig_ret.update_yaxes(visible=False)
        st.plotly_chart(fig_ret, use_container_width=True)
    else:
        st.info("No TCP retransmission events found.")