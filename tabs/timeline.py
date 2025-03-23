import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np

def show_timeline_tab(df_delays, df_retrans):
    """Display temporal analysis of packet transmission with robust anomaly handling"""
    st.header("Timeline Analysis")
    st.markdown("""
    Temporal analysis showing network patterns, delays, and anomalies over time.
    """)

    # Enhanced time-series visualization
    if not df_delays.empty:
        # Make a clean copy of the dataframe for processing
        df_delays_plot = df_delays.copy()
        
        # Convert timestamp and handle missing columns
        if 'device_publish_time' in df_delays_plot.columns:
            df_delays_plot["timestamp"] = pd.to_datetime(
                df_delays_plot["device_publish_time"], 
                unit='ms'
            )
        
        # Anomaly detection - calculate fresh threshold each time
        if 'total_delay' in df_delays_plot.columns:
            # IMPORTANT: Calculate statistics on the raw data before any modifications
            raw_mean_total = df_delays['total_delay'].mean()  # Use original df
            raw_std_total = df_delays['total_delay'].std()    # Use original df
            threshold = raw_mean_total + 2 * raw_std_total
            
            # Store the calculated threshold in session state for consistency
            st.session_state['calculated_threshold'] = threshold
            
            # Apply anomaly detection using the calculated threshold
            df_delays_plot['is_anomaly'] = df_delays_plot['total_delay'] > threshold
            
            # Count anomalies and display to user
            anomaly_count = df_delays_plot['is_anomaly'].sum()
            if anomaly_count > 0:
                st.warning(f"Found {anomaly_count} anomalies exceeding threshold of {threshold:.4f}ms")
            else:
                st.info(f"No anomalies found using threshold of {threshold:.4f}ms")

        # Visualization parameters
        plot_params = {
            "data_frame": df_delays_plot,
            "x": "timestamp",
            "y": "total_delay",
            "size": "total_delay",
            "size_max": 15,
            "title": "Total Delay Over Time with Anomaly Detection",
            "labels": {"total_delay": "Total Delay (ms)"}
        }

        # Create a combined visualization that shows both bottlenecks and anomalies
        if 'is_anomaly' in df_delays_plot.columns:
            # Use symbol to indicate anomalies
            df_delays_plot["symbol_col"] = df_delays_plot['is_anomaly'].map(
                {True: "triangle-up", False: "circle"}
            )
            plot_params["symbol"] = "symbol_col"
            
            # If bottleneck column exists, create a combined column for coloring
            if 'bottleneck' in df_delays_plot.columns:
                # Create a new column that combines bottleneck and anomaly information
                df_delays_plot["display_category"] = df_delays_plot.apply(
                    lambda row: f"{row['bottleneck']} (Anomaly)" if row['is_anomaly'] 
                               else row['bottleneck'], 
                    axis=1
                )
                
                # Update color mapping to show both bottleneck and anomaly status
                color_map = {
                    "Device→Broker": "#1E88E5",
                    "Device→Broker (Anomaly)": "#FF0000",  # Red for anomalies
                    "Broker Processing": "#FFC107",
                    "Broker Processing (Anomaly)": "#FF0000",
                    "Cloud Upload": "#4CAF50",
                    "Cloud Upload (Anomaly)": "#FF0000"
                }
                
                plot_params.update({
                    "color": "display_category",
                    "color_discrete_map": color_map
                })
            else:
                # If no bottleneck column, just color by anomaly
                plot_params.update({
                    "color": "is_anomaly",
                    "color_discrete_map": {True: "red", False: "blue"}
                })

        # If only bottleneck exists (no anomalies), use original bottleneck coloring
        elif 'bottleneck' in df_delays_plot.columns:
            plot_params.update({
                "color": "bottleneck",
                "color_discrete_map": {
                    "Device→Broker": "#1E88E5",
                    "Broker Processing": "#FFC107",
                    "Cloud Upload": "#4CAF50"
                }
            })

        fig_timeline = px.scatter(**plot_params)

        # Always use the calculated threshold for the line
        if 'total_delay' in df_delays_plot.columns and 'calculated_threshold' in st.session_state:
            fig_timeline.add_hline(
                y=st.session_state['calculated_threshold'],
                line_dash="dot", 
                line_color="red",
                annotation_text=f"Anomaly Threshold ({st.session_state['calculated_threshold']:.4f}ms)"
            )

        st.plotly_chart(fig_timeline, use_container_width=True)
        # Correlation matrix with safety checks
        st.subheader("Delay Correlations")
        corr_columns = [col for col in [
            "device_to_broker_delay", 
            "broker_processing_delay", 
            "cloud_upload_delay", 
            "total_delay"
        ] if col in df_delays.columns]
        
        if len(corr_columns) >= 2:
            corr_matrix = df_delays[corr_columns].corr()
            fig_corr = px.imshow(
                corr_matrix,
                text_auto=True,
                color_continuous_scale='RdBu_r',
                title="Delay Component Correlations"
            )
            st.plotly_chart(fig_corr, use_container_width=True)
        else:
            st.warning("Insufficient data for correlation analysis")

    else:
        st.info("No delay data available for timeline analysis.")

    # Retransmission visualization with column fix
    if not df_retrans.empty:
        df_retrans_plot = df_retrans.copy()
        
        if 'timestamp' in df_retrans_plot.columns:  # Updated column name
            df_retrans_plot["timestamp"] = pd.to_datetime(
                df_retrans_plot["timestamp"], 
                unit='ms'
            )
            
            fig_ret = px.scatter(
                df_retrans_plot, 
                x="timestamp", 
                y=[1]*len(df_retrans_plot),
                title="TCP Retransmissions Timeline",
                labels={"timestamp": "Time"},
                height=250
            )
            fig_ret.update_traces(
                marker=dict(color="red", size=10, symbol="x"),
                selector=dict(mode='markers')
            )
            fig_ret.update_yaxes(visible=False)
            st.plotly_chart(fig_ret, use_container_width=True)
    else:
        st.info("No TCP retransmission events detected.")