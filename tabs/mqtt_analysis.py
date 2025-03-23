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
            st.write("Detected Network Entities:")
            st.write(f"**Number of Broker(s) - {stats['total_brokers']}:**")
            st.write(f"**Number of Client(s) - {stats['total_clients']}:**")
    
    with col2:
        if "broker_processing_delay" in df_mqtt.columns:
            bp_data = df_mqtt[df_mqtt['broker_processing_delay'].notna()]
            if not bp_data.empty:
                st.metric("Avg Broker Processing Delay", f"{bp_data['broker_processing_delay'].mean():.4f}s")
    
    # with col3:
    #     if "cloud_upload_delay" in df_mqtt.columns:
    #         cu_data = df_mqtt[df_mqtt['cloud_upload_delay'].notna()]
    #         if not cu_data.empty:
    #             st.metric("Avg Cloud Upload Delay", f"{cu_data['cloud_upload_delay'].mean():.4f}s")
    
    # Create tabs for different analyses
    mqtt_tabs = st.tabs([
        "Delay Components", 
        "Client-Broker Delay", 
        "Broker Processing", 
        # "Cloud Delay",
        "Network Topology"
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
    
    # with mqtt_tabs[3]:
    #     st.subheader("Cloud Upload Delay Analysis")
    #     if "cloud_upload_delay" in df_mqtt.columns:
    #         cloud_data = df_mqtt[df_mqtt['cloud_upload_delay'].notna()]
    #         if not cloud_data.empty:
    #             st.plotly_chart(hist_with_boundaries(cloud_data, "cloud_upload_delay", 
    #                                            "Cloud Upload Delay Distribution", 
    #                                            color="red"), use_container_width=True)
                
    #             # Show delays over time
    #             if "timestamp" in df_mqtt.columns:
    #                 fig = px.scatter(
    #                     cloud_data,
    #                     x="timestamp",
    #                     y="cloud_upload_delay",
    #                     title="Cloud Upload Delay Over Time",
    #                     labels={"cloud_upload_delay": "Delay (s)", "timestamp": "Time"}
    #                 )
    #                 st.plotly_chart(fig, use_container_width=True)
                
    #             # Show cloud delay categories
    #             if "cloud_upload_delay_category" in df_mqtt.columns:
    #                 category_counts = df_mqtt["cloud_upload_delay_category"].value_counts().reset_index()
    #                 category_counts.columns = ["Category", "Count"]
                    
    #                 fig = px.pie(
    #                     category_counts,
    #                     values="Count",
    #                     names="Category",
    #                     title="Cloud Upload Delay Categories",
    #                     color="Category",
    #                     color_discrete_map={
    #                         "Low": "green",
    #                         "Normal": "blue",
    #                         "High": "orange",
    #                         "Very High": "red"
    #                     }
    #                 )
    #                 st.plotly_chart(fig, use_container_width=True)
    #         else:
    #             st.warning("No Cloud Upload delay measurements detected in the data.")
    #     else:
    #         st.warning("No Cloud Upload Delay data available.")
    
    with mqtt_tabs[3]:  # Network Topology tab
        st.subheader("Network Topology Analysis")
        
        if 'detected_brokers' in stats and 'detected_clients' in stats:
            # Prepare nodes and edges
            nodes = []
            edges = []
            labels = []

            # Add brokers with IP addresses as labels
            for broker in stats['detected_brokers']:
                nodes.append({"id": broker, "label": broker, "type": "broker"})  # Use IP as label
                labels.append(broker)  # Use IP as label

            # Add clients with IP addresses as labels
            for client in stats['detected_clients']:
                nodes.append({"id": client, "label": client, "type": "client"})  # Use IP as label
                labels.append(client)  # Use IP as label
                
                # Find the broker this client is connected to
                broker = df_mqtt[(df_mqtt['src_ip'] == client) | (df_mqtt['dst_ip'] == client)]['dst_ip'].unique()
                if len(broker) > 0:
                    broker_label = next(n['label'] for n in nodes if n['id'] == broker[0])
                    edges.append({"from": broker_label, "to": client})

            # Prepare coordinates for nodes
            Xn = []  # X coordinates for nodes
            Yn = []  # Y coordinates for nodes
            Xe = []  # X coordinates for edges
            Ye = []  # Y coordinates for edges

            # Brokers on the left (x=0), clients on the right (x=1)
            for i, node in enumerate(nodes):
                if node['type'] == 'broker':
                    Xn.append(0)  # Brokers on the left
                    Yn.append(i)  # Spread vertically
                else:
                    Xn.append(1)  # Clients on the right
                    Yn.append(i)  # Spread vertically

            # Prepare edges
            for edge in edges:
                from_node = next(n for n in nodes if n['label'] == edge['from'])
                to_node = next(n for n in nodes if n['label'] == edge['to'])
                
                Xe += [Xn[nodes.index(from_node)], Xn[nodes.index(to_node)], None]  # Add None to break the line
                Ye += [Yn[nodes.index(from_node)], Yn[nodes.index(to_node)], None]

            # Create the graph
            fig = go.Figure()

            # Add edges (connections)
            fig.add_trace(go.Scatter(
                x=Xe,
                y=Ye,
                mode='lines',
                line=dict(color='rgb(210,210,210)', width=1),
                hoverinfo='none'
            ))

            # Add nodes (brokers and clients)
            fig.add_trace(go.Scatter(
                x=Xn,
                y=Yn,
                mode='markers',
                name='Nodes',
                marker=dict(
                    symbol='circle-dot',
                    size=18,
                    color=['#6175c1' if n['type'] == 'broker' else '#DB4551' for n in nodes],  # Brokers: blue, Clients: red
                    line=dict(color='rgb(50,50,50)', width=1)
                ),
                text=labels,  # Use IP addresses as labels
                hoverinfo='text',
                opacity=0.8
            ))

            # Update layout
            fig.update_layout(
                title="Client-Broker Network Topology (BLUE: Brokers, RED: Clients)",
                showlegend=False,
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=600,
                margin=dict(l=40, r=40, b=40, t=40)
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("No network topology data available.")

        # Revert to the original table format
        st.subheader("Message Communication Table")
        if not df_mqtt.empty:
            # Create communication table
            comm_columns = ['timestamp', 'src_ip', 'dst_ip', 'msg_type_name', 
                            'device_to_broker_delay', 'broker_processing_delay']
            comm_df = df_mqtt[comm_columns].copy()
            comm_df['timestamp'] = pd.to_datetime(comm_df['timestamp'], unit='s')
            comm_df['direction'] = np.where(
                comm_df['src_ip'].isin(stats['detected_clients']),
                'Client→Broker',
                'Broker→Client'
            )
            
            # Display scrollable table
            st.dataframe(
                comm_df.sort_values('timestamp', ascending=False),
                column_config={
                    "timestamp": "Time",
                    "src_ip": "Source",
                    "dst_ip": "Destination",
                    "msg_type_name": "Message Type",
                    "device_to_broker_delay": st.column_config.NumberColumn(
                        "Client→Broker Delay (s)",
                        format="%.4f"
                    ),
                    "broker_processing_delay": st.column_config.NumberColumn(
                        "Processing Delay (s)",
                        format="%.4f"
                    )
                },
                height=400,
                use_container_width=True
            )
        else:
            st.warning("No communication data available for table.")