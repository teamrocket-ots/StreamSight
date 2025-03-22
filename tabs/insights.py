import streamlit as st
import pandas as pd
import plotly.express as px


def show_insights_tab(df_delays):
    """
    Display insights and categorization of delays
    """
    st.header("Insights & Categorization")
    st.markdown("""
    StreamSight automatically classifies transmission delays into:
    - **Device→Broker** transmission time
    - **Broker Processing** duration
    - **Cloud Upload** latency
    - **Retransmissions** events
    
    Anomalies are highlighted for faster troubleshooting.
    """)

    # Display thresholds for anomaly detection
    if "thresholds" not in st.session_state:
        # If thresholds were not calculated, do it here (this should normally happen in analysis.py)
        st.session_state.thresholds = {}
        delay_types = ["device_to_broker_delay", "broker_processing_delay", 
                      "cloud_upload_delay", "total_delay"]
        
        for col in delay_types:
            if col in df_delays.columns:
                mean_val = df_delays[col].mean()
                std_val = df_delays[col].std()
                
                # Different thresholds based on delay type
                if col == "device_to_broker_delay":
                    threshold_multiplier = 2.0  # More sensitive for local network
                elif col == "broker_processing_delay":
                    threshold_multiplier = 2.5
                elif col == "cloud_upload_delay":
                    threshold_multiplier = 3.0  # Less sensitive (more variable)
                else:  # total_delay
                    threshold_multiplier = 2.0
                    
                cutoff = mean_val + threshold_multiplier * std_val
                st.session_state.thresholds[col] = cutoff
    
    st.subheader("Anomaly Detection Thresholds")
    threshold_df = pd.DataFrame({
        "Delay Type": list(st.session_state.thresholds.keys()),
        "Threshold (s)": [f"{val:.3f}" for val in st.session_state.thresholds.values()]
    })
    st.table(threshold_df)

    # Display bottleneck analysis 
    st.subheader("Bottleneck Analysis")
    if "bottleneck" in df_delays.columns:
        bottleneck_counts = df_delays["bottleneck"].value_counts().reset_index()
        bottleneck_counts.columns = ["Bottleneck", "Count"]
        
        fig_bottleneck = px.pie(
            bottleneck_counts, 
            values="Count", 
            names="Bottleneck",
            title="Primary Delay Contributors",
            color="Bottleneck",
            color_discrete_map={
                "Device→Broker": "#1E88E5",
                "Broker Processing": "#FFC107",
                "Cloud Upload": "#4CAF50"
            }
        )
        st.plotly_chart(fig_bottleneck, use_container_width=True)
    else:
        st.info("Bottleneck analysis not available. Run categorize_delays() first.")
    
    # Display delay categorization
    st.subheader("Delay Categorization")
    categories = ["Low", "Normal", "High", "Very High"]
    delay_types = ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]
    
    for delay_type in delay_types:
        cat_col = f"{delay_type}_category"
        if cat_col in df_delays.columns:
            cat_counts = df_delays[cat_col].value_counts().reindex(categories).fillna(0).reset_index()
            cat_counts.columns = ["Category", "Count"]
            
            st.write(f"**{delay_type.replace('_', ' ').title()}**")
            fig_cat = px.bar(
                cat_counts,
                x="Category",
                y="Count",
                color="Category",
                color_discrete_map={
                    "Low": "green",
                    "Normal": "blue",
                    "High": "orange",
                    "Very High": "red"
                }
            )
            fig_cat.update_traces(marker_line_color='rgba(0,0,0,0.5)', marker_line_width=1)
            st.plotly_chart(fig_cat, use_container_width=True)
        else:
            st.info(f"Categories for {delay_type} not available.")
    
    # Display anomalies
    st.subheader("Detected Anomalies")
    if "is_anomaly" in df_delays.columns:
        anomalies = df_delays[df_delays["is_anomaly"] == True]
        st.write(f"Number of anomaly messages: {len(anomalies)}")
        if not anomalies.empty:
            st.dataframe(anomalies[["msg_id", "device_to_broker_delay", "broker_processing_delay", 
                                    "cloud_upload_delay", "total_delay", "bottleneck"]])
        else:
            st.info("No anomalies detected.")
    else:
        st.info("Anomaly detection not available. Run detect_anomalies_in_delays() first.")