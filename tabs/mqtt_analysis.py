import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
import datetime

from visualizations import hist_with_boundaries, mqtt_delay_components
from analysis import analyze_mqtt_delays

def show_mqtt_analysis_tab(df_mqtt):
    """Display MQTT-specific analysis and visualizations"""
    st.header("MQTT Delay Analysis")
    
    if df_mqtt.empty:
        st.warning("No MQTT data available in the uploaded PCAP file.")
        return
    
    # Process data for analysis
    df_mqtt, stats = analyze_mqtt_delays(df_mqtt)
    
    # Overview metrics
    st.subheader("MQTT Performance Overview")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if "device_to_broker_delay" in df_mqtt.columns:
            d2b_data = df_mqtt[df_mqtt['device_to_broker_delay'].notna()]
            if not d2b_data.empty:
                st.metric("Avg Device→Broker Delay", f"{d2b_data['device_to_broker_delay'].mean():.4f}s")
        
        # Display detected clients and brokers
        if 'detected_clients' in stats and 'detected_brokers' in stats:
            st.write("Detected Clients and Brokers:")
            
            # Display clients
            st.write(f"- Total Unique Clients: {stats['total_clients']}")
            for client in stats['detected_clients']:
                st.write(f"  - {client}")
            
            # Display brokers
            st.write(f"- Total Unique Brokers: {stats['total_brokers']}")
            for broker in stats['detected_brokers']:
                st.write(f"  - {broker}")
    
    with col2:
        if "broker_processing_delay" in df_mqtt.columns:
            bp_data = df_mqtt[df_mqtt['broker_processing_delay'].notna()]
            if not bp_data.empty:
                st.metric("Avg Broker Processing Delay", f"{bp_data['broker_processing_delay'].mean():.4f}s")
    
    with col3:
        if "cloud_upload_delay" in df_mqtt.columns:
            cu_data = df_mqtt[df_mqtt['cloud_upload_delay'].notna()]
            if not cu_data.empty:
                st.metric("Avg Cloud Upload Delay", f"{cu_data['cloud_upload_delay'].mean():.4f}s")
    
    # Create tabs for different analyses
    mqtt_tabs = st.tabs([
        "Delay Components", 
        "Client-Broker Delay", 
        "Broker Processing", 
        "Cloud Delay",
        "Message Flow"
    ])
    
    with mqtt_tabs[0]:
        st.subheader("MQTT Delay Component Analysis")
        
        # Show delay components visualization
        st.plotly_chart(mqtt_delay_components(df_mqtt), use_container_width=True)
        
        # Show bottleneck analysis if available
        if "bottleneck" in df_mqtt.columns:
            bottleneck_counts = df_mqtt["bottleneck"].value_counts().reset_index()
            bottleneck_counts.columns = ["Bottleneck", "Count"]
            
            fig = px.pie(
                bottleneck_counts,
                values="Count",
                names="Bottleneck",
                title="Distribution of Delay Bottlenecks",
                color="Bottleneck",
                color_discrete_map={
                    "Device→Broker": "blue",
                    "Broker Processing": "green",
                    "Cloud Upload": "red"
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with mqtt_tabs[1]:
        st.subheader("Client-Broker Delay Analysis")
        if "device_to_broker_delay" in df_mqtt.columns:
            d2b_data = df_mqtt[df_mqtt['device_to_broker_delay'].notna()]
            if not d2b_data.empty:
                st.plotly_chart(hist_with_boundaries(d2b_data, "device_to_broker_delay", 
                                               "Client-Broker Delay Distribution", 
                                               color="blue"), use_container_width=True)
                
                # Show delays over time
                if "timestamp" in df_mqtt.columns:
                    fig = px.scatter(
                        d2b_data,
                        x="timestamp",
                        y="device_to_broker_delay",
                        color="msg_type_name" if "msg_type_name" in d2b_data.columns else None,
                        title="Client-Broker Delay Over Time",
                        labels={"device_to_broker_delay": "Delay (s)", "timestamp": "Time"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Show delay categories
                if "device_to_broker_delay_category" in df_mqtt.columns:
                    category_counts = df_mqtt["device_to_broker_delay_category"].value_counts().reset_index()
                    category_counts.columns = ["Category", "Count"]
                    
                    fig = px.bar(
                        category_counts,
                        x="Category",
                        y="Count",
                        title="Client-Broker Delay Categories",
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
                st.warning("No Client-Broker delay measurements detected in the data.")
        else:
            st.warning("No Client-Broker Delay data available.")
    
    with mqtt_tabs[2]:
        st.subheader("Broker Processing Delay Analysis")
        if "broker_processing_delay" in df_mqtt.columns:
            bp_data = df_mqtt[df_mqtt['broker_processing_delay'].notna()]
            if not bp_data.empty:
                st.plotly_chart(hist_with_boundaries(bp_data, "broker_processing_delay", 
                                               "Broker Processing Delay Distribution", 
                                               color="green"), use_container_width=True)
                
                # Show delays over time
                if "timestamp" in df_mqtt.columns:
                    fig = px.scatter(
                        bp_data,
                        x="timestamp",
                        y="broker_processing_delay",
                        color="msg_type_name" if "msg_type_name" in bp_data.columns else None,
                        title="Broker Processing Delay Over Time",
                        labels={"broker_processing_delay": "Delay (s)", "timestamp": "Time"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Show delay by message type
                if "msg_type_name" in df_mqtt.columns:
                    bp_by_type = bp_data.groupby("msg_type_name")["broker_processing_delay"].mean().reset_index()
                    
                    fig = px.bar(
                        bp_by_type.sort_values("broker_processing_delay", ascending=False),
                        x="msg_type_name",
                        y="broker_processing_delay",
                        title="Average Broker Processing Delay by Message Type",
                        labels={"broker_processing_delay": "Average Delay (s)", 
                                "msg_type_name": "Message Type"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No Broker Processing delay measurements detected in the data.")
        else:
            st.warning("No Broker Processing Delay data available.")
    
    with mqtt_tabs[3]:
        st.subheader("Cloud Upload Delay Analysis")
        if "cloud_upload_delay" in df_mqtt.columns:
            cloud_data = df_mqtt[df_mqtt['cloud_upload_delay'].notna()]
            if not cloud_data.empty:
                st.plotly_chart(hist_with_boundaries(cloud_data, "cloud_upload_delay", 
                                               "Cloud Upload Delay Distribution", 
                                               color="red"), use_container_width=True)
                
                # Show delays over time
                if "timestamp" in df_mqtt.columns:
                    fig = px.scatter(
                        cloud_data,
                        x="timestamp",
                        y="cloud_upload_delay",
                        title="Cloud Upload Delay Over Time",
                        labels={"cloud_upload_delay": "Delay (s)", "timestamp": "Time"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Show cloud delay categories
                if "cloud_upload_delay_category" in df_mqtt.columns:
                    category_counts = df_mqtt["cloud_upload_delay_category"].value_counts().reset_index()
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
                st.warning("No Cloud Upload delay measurements detected in the data.")
        else:
            st.warning("No Cloud Upload Delay data available.")
    
    with mqtt_tabs[4]:
        st.subheader("MQTT Message Flow Analysis")
        
        # Display message flow diagram
        if "entity" in df_mqtt.columns and "msg_type_name" in df_mqtt.columns and "timestamp" in df_mqtt.columns:
            # Convert timestamps to readable format
            df_mqtt['time_str'] = [datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3] 
                                  for ts in df_mqtt['timestamp']]
            
            # Create a flow diagram
            flow_data = df_mqtt[['time_str', 'entity', 'msg_type_name', 'msg_id']].head(50)  # Limit to avoid overcrowding
            
            fig = go.Figure()
            
            entities = ['CLIENT', 'BROKER', 'CLOUD']
            entity_positions = {e: i for i, e in enumerate(entities)}
            
            # Add horizontal lines for each entity
            for i, entity in enumerate(entities):
                fig.add_shape(
                    type="line",
                    x0=0,
                    y0=i,
                    x1=1,
                    y1=i,
                    line=dict(color="lightgrey", width=1, dash="dash")
                )
                fig.add_annotation(
                    x=0,
                    y=i,
                    xref="paper",
                    text=entity,
                    showarrow=False,
                    font=dict(size=14)
                )
            
            # Add message arrows
            for i in range(len(flow_data) - 1):
                curr = flow_data.iloc[i]
                next_row = flow_data.iloc[i + 1]
                
                if curr['entity'] in entity_positions and next_row['entity'] in entity_positions:
                    y_start = entity_positions[curr['entity']]
                    y_end = entity_positions[next_row['entity']]
                    
                    if y_start != y_end:  # Only draw if entities are different
                        fig.add_trace(go.Scatter(
                            x=[i, i + 1],
                            y=[y_start, y_end],
                            mode='lines+markers+text',
                            line=dict(color="blue", width=1),
                            text=["", next_row['msg_type_name']],
                            textposition="top center",
                            showlegend=False
                        ))
            
            fig.update_layout(
                title="MQTT Message Flow",
                xaxis=dict(
                    title="Message Sequence",
                    showticklabels=False
                ),
                yaxis=dict(
                    showticklabels=False,
                    range=[-0.5, len(entities) - 0.5]
                ),
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Show the raw message flow data
            st.subheader("Message Sequence")
            st.dataframe(flow_data)
        else:
            st.warning("Insufficient data for message flow visualization.")
