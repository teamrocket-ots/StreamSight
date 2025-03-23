import streamlit as st
from visualizations import hist_with_boundaries
import pandas as pd


def show_delay_analysis_tab(df_delays):
    """Display delay analysis visualizations"""
    st.header("MQTT Delay Analysis")
    
    # Check what columns are available
    available_columns = set(df_delays.columns)
    required_columns = {
        "device_to_broker_delay", 
        "broker_processing_delay", 
        "cloud_upload_delay", 
        "total_delay"
    }
    missing_columns = required_columns - available_columns
    
    if missing_columns:
        st.warning(f"Some delay metrics are missing: {', '.join(missing_columns)}")
        
        # If your PCAP doesn't have MQTT data, show this message
        if len(missing_columns) == len(required_columns):
            st.error("No MQTT delay data found in the PCAP file. Try uploading a file with MQTT traffic.")
            return
    
    # Display metrics in a row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if "device_to_broker_delay" in df_delays.columns:
            avg_dev = df_delays["device_to_broker_delay"].mean()
            st.metric("Avg Device→Broker", f"{avg_dev:.3f}s")
        else:
            st.metric("Avg Device→Broker", "N/A")
    
    with col2:
        if "broker_processing_delay" in df_delays.columns:
            avg_broker = df_delays["broker_processing_delay"].mean()
            st.metric("Avg Broker Proc", f"{avg_broker:.3f}s")
        else:
            st.metric("Avg Broker Proc", "N/A")
    
    with col3:
        if "cloud_upload_delay" in df_delays.columns:
            avg_cloud = df_delays["cloud_upload_delay"].mean()
            st.metric("Avg Cloud Upload", f"{avg_cloud:.3f}s")
        else:
            st.metric("Avg Cloud Upload", "N/A")
    
    with col4:
        if "total_delay" in df_delays.columns:
            avg_total = df_delays["total_delay"].mean()
            st.metric("Avg Total Delay", f"{avg_total:.3f}s")
        else:
            st.metric("Avg Total Delay", "N/A")
    
    # Create tabs for different delay analyses
    delay_tabs = st.tabs([
        "Device→Broker Delay",
        "Broker Processing Delay",
        "Cloud Upload Delay",
        "Total Delay",
        "Anomalies"
    ])
    
    # Device to Broker delay histogram
    with delay_tabs[0]:
        st.subheader("Device to Broker Delay Analysis")
        if "device_to_broker_delay" in df_delays.columns:
            fig = hist_with_boundaries(df_delays, "device_to_broker_delay", 
                                     "Device to Broker Delay Distribution", color="blue")
            st.plotly_chart(fig, use_container_width=True)
            
            if "device_to_broker_delay_category" in df_delays.columns:
                # Show categories
                category_counts = df_delays["device_to_broker_delay_category"].value_counts().reset_index()
                category_counts.columns = ["Category", "Count"]
                
                fig = px.pie(
                    category_counts, 
                    values="Count", 
                    names="Category",
                    title="Device to Broker Delay Categories",
                    color="Category",
                    color_discrete_map={
                        "Low": "green",
                        "Normal": "blue",
                        "High": "orange",
                        "Very High": "red"
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Device to Broker delay data not available.")
    
    # Broker Processing delay histogram
    with delay_tabs[1]:
        st.subheader("Broker Processing Delay Analysis")
        if "broker_processing_delay" in df_delays.columns:
            fig = hist_with_boundaries(df_delays, "broker_processing_delay", 
                                     "Broker Processing Delay Distribution", color="green")
            st.plotly_chart(fig, use_container_width=True)
            
            if "broker_processing_delay_category" in df_delays.columns:
                # Show categories
                category_counts = df_delays["broker_processing_delay_category"].value_counts().reset_index()
                category_counts.columns = ["Category", "Count"]
                
                fig = px.pie(
                    category_counts, 
                    values="Count", 
                    names="Category",
                    title="Broker Processing Delay Categories",
                    color="Category",
                    color_discrete_map={
                        "Low": "green",
                        "Normal": "blue",
                        "High": "orange",
                        "Very High": "red"
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Broker Processing delay data not available.")
    
    # Cloud Upload delay histogram
    with delay_tabs[2]:
        st.subheader("Cloud Upload Delay Analysis")
        if "cloud_upload_delay" in df_delays.columns:
            fig = hist_with_boundaries(df_delays, "cloud_upload_delay", 
                                     "Cloud Upload Delay Distribution", color="red")
            st.plotly_chart(fig, use_container_width=True)
            
            if "cloud_upload_delay_category" in df_delays.columns:
                # Show categories
                category_counts = df_delays["cloud_upload_delay_category"].value_counts().reset_index()
                category_counts.columns = ["Category", "Count"]
                
                fig = px.pie(
                    category_counts, 
                    values="Count", 
                    names="Category",
                    title="Cloud Upload Delay Categories",
                    color="Category",
                    color_discrete_map={
                        "Low": "green",
                        "Normal": "blue",
                        "High": "orange",
                        "Very High": "red"
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Cloud Upload delay data not available.")
    
    # Total delay histogram
    with delay_tabs[3]:
        st.subheader("Total Delay Analysis")
        if "total_delay" in df_delays.columns:
            fig = hist_with_boundaries(df_delays, "total_delay", 
                                     "Total Delay Distribution", color="purple")
            st.plotly_chart(fig, use_container_width=True)
            
            # Show bottleneck if available
            if "bottleneck" in df_delays.columns:
                bottleneck_counts = df_delays["bottleneck"].value_counts().reset_index()
                bottleneck_counts.columns = ["Bottleneck", "Count"]
                
                fig = px.pie(
                    bottleneck_counts, 
                    values="Count", 
                    names="Bottleneck",
                    title="Delay Bottleneck Distribution",
                    color="Bottleneck",
                    color_discrete_map={
                        "Device→Broker": "blue",
                        "Broker Processing": "green",
                        "Cloud Upload": "red"
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Total delay data not available.")
    
    # Anomalies tab
    with delay_tabs[4]:
        st.subheader("Delay Anomalies")
        if "is_anomaly" in df_delays.columns:
            # Count anomalies
            anomaly_count = df_delays["is_anomaly"].sum()
            total_count = len(df_delays)
            anomaly_pct = (anomaly_count / total_count) * 100 if total_count > 0 else 0
            
            st.metric("Anomalies Detected", f"{anomaly_count} ({anomaly_pct:.1f}%)")
            
            # Show anomalous records
            if anomaly_count > 0:
                st.subheader("Anomalous Delay Records")
                st.dataframe(df_delays[df_delays["is_anomaly"] == True])
                
                # Show anomaly breakdown by component
                anomaly_by_component = {}
                for col in ["device_to_broker_delay_anomaly", "broker_processing_delay_anomaly", 
                           "cloud_upload_delay_anomaly", "total_delay_anomaly"]:
                    if col in df_delays.columns:
                        component = col.replace("_anomaly", "").replace("_", " ").title()
                        anomaly_by_component[component] = df_delays[col].sum()
                
                if anomaly_by_component:
                    anomaly_df = pd.DataFrame({
                        "Component": list(anomaly_by_component.keys()),
                        "Anomaly Count": list(anomaly_by_component.values())
                    })
                    
                    fig = px.bar(
                        anomaly_df,
                        x="Component",
                        y="Anomaly Count",
                        title="Anomalies by Component",
                        color="Component"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No anomalies detected in the delay data.")
        else:
            st.warning("Anomaly detection data not available.")
