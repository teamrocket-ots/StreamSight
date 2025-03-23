import streamlit as st
import pandas as pd
import plotly.express as px

def categorize_delays(df: pd.DataFrame) -> pd.DataFrame:
    """
    Categorize each delay type into Low, Normal, High, Very High.
    Also sets a 'bottleneck' column to indicate which delay is highest.
    """
    delay_types = ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]
    categories = ["Low", "Normal", "High", "Very High"]
    
    for col in delay_types:
        if col in df.columns:
            df[f"{col}_category"] = pd.qcut(
                df[col], 
                q=[0, 0.25, 0.5, 0.75, 1.0],
                labels=categories, 
                duplicates="drop"
            )
    
    if all(col in df.columns for col in delay_types):
        df["bottleneck"] = df[delay_types].idxmax(axis=1)
        df["bottleneck"] = df["bottleneck"].replace({
            "device_to_broker_delay": "Device→Broker",
            "broker_processing_delay": "Broker Processing",
            "cloud_upload_delay": "Cloud Upload"
        })
    
    return df

def detect_anomalies_in_delays(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flag anomalies in each delay column if it exceeds mean + 3 * std.
    """
    df["is_anomaly"] = False
    for col in ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]:
        if col in df.columns:
            threshold = df[col].mean() + 3 * df[col].std()
            df.loc[df[col] > threshold, "is_anomaly"] = True
    return df

def show_insights_tab(df_delays: pd.DataFrame):
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

    # -------------------------------------------------------------------
    # 1) Auto-categorize if needed columns missing
    # -------------------------------------------------------------------
    needed_bottleneck = "bottleneck" in df_delays.columns
    needed_categories = all(
        f"{col}_category" in df_delays.columns 
        for col in ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]
    )
    needed_anomalies = "is_anomaly" in df_delays.columns

    if not needed_bottleneck or not needed_categories:
        df_delays = categorize_delays(df_delays)
    
    if not needed_anomalies:
        df_delays = detect_anomalies_in_delays(df_delays)

    # -------------------------------------------------------------------
    # 2) Threshold Calculation
    # -------------------------------------------------------------------
    if "thresholds" not in st.session_state:
        st.session_state.thresholds = {}
        delay_types = ["device_to_broker_delay", "broker_processing_delay", 
                       "cloud_upload_delay", "total_delay"]
        
        for col in delay_types:
            if col in df_delays.columns:
                mean_val = df_delays[col].mean()
                std_val = df_delays[col].std()
                
                if col == "device_to_broker_delay":
                    threshold_multiplier = 2.0
                elif col == "broker_processing_delay":
                    threshold_multiplier = 2.5
                elif col == "cloud_upload_delay":
                    threshold_multiplier = 3.0
                else:
                    threshold_multiplier = 2.0
                    
                cutoff = mean_val + threshold_multiplier * std_val
                st.session_state.thresholds[col] = cutoff
    
    st.subheader("Anomaly Detection Thresholds")
    if "thresholds" in st.session_state and st.session_state.thresholds:
        threshold_df = pd.DataFrame({
            "Delay Type": list(st.session_state.thresholds.keys()),
            "Threshold (s)": [f"{val:.3f}" for val in st.session_state.thresholds.values()]
        })
        st.table(threshold_df)
    else:
        st.info("No thresholds found.")

    # -------------------------------------------------------------------
    # 3) Bottleneck Analysis (Fixed duplicate key)
    # -------------------------------------------------------------------
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
        st.plotly_chart(fig_bottleneck, use_container_width=True, key="bottleneck_pie")
    else:
        st.info("Bottleneck analysis not available.")

    # -------------------------------------------------------------------
    # 5) Anomaly Display
    # -------------------------------------------------------------------
    st.subheader("Detected Anomalies")
    if "is_anomaly" in df_delays.columns:
        anomalies = df_delays[df_delays["is_anomaly"]]
        st.write(f"Number of anomaly messages: {len(anomalies)}")
        if not anomalies.empty:
            st.dataframe(anomalies[[
                "msg_id", 
                "device_to_broker_delay", 
                "broker_processing_delay", 
                "cloud_upload_delay", 
                "total_delay", 
                "bottleneck"
            ]], key="anomalies_table")  # Unique key for table
        else:
            st.info("No anomalies detected.")
    else:
        st.info("Anomaly detection not available.")