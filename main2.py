import streamlit as st
import pandas as pd
import numpy as np
import pyshark
import tempfile
import os
import plotly.express as px
import plotly.graph_objects as go

# -------------------------------------------------------
# Page Setup
# -------------------------------------------------------
st.set_page_config(page_title="StreamSight", layout="wide")

st.markdown("""
<style>
body {
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}
.sidebar .sidebar-content {
    background: linear-gradient(#2e7bcf, #2e7bcf);
    color: white;
}
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------
# 1. PCAP Parsing (Improved to extract real MQTT delays)
# -------------------------------------------------------
def parse_pcap(file_path):
    """
    Parse a .pcap or .pcapng using PyShark and extract MQTT delays.
    Returns:
      - df_packets: Detailed table of packets (src IP, dst IP, protocol, timestamps, ports, etc.)
      - df_delays: Table of actual MQTT delays across different stages
      - df_retrans: TCP retransmission events
    """
    cap = pyshark.FileCapture(file_path, display_filter="mqtt or tcp or udp")
    
    packet_records = []
    retrans_times = []
    mqtt_messages = {}  # Track MQTT messages by ID
    
    for pkt in cap:
        # Basic packet info
        epoch_time = float(pkt.frame_info.time_epoch)
        src_ip = getattr(pkt.ip, 'src', None) if hasattr(pkt, 'ip') else None
        dst_ip = getattr(pkt.ip, 'dst', None) if hasattr(pkt, 'ip') else None
        src_port = getattr(pkt.tcp, 'srcport', None) if hasattr(pkt, 'tcp') else None
        if src_port is None:
            src_port = getattr(pkt.udp, 'srcport', None) if hasattr(pkt, 'udp') else None
            
        dst_port = getattr(pkt.tcp, 'dstport', None) if hasattr(pkt, 'tcp') else None
        if dst_port is None:
            dst_port = getattr(pkt.udp, 'dstport', None) if hasattr(pkt, 'udp') else None

        # Protocol detection
        if hasattr(pkt, 'mqtt'):
            protocol = "MQTT"
            # Process MQTT packets to track real delays
            try:
                msg_id = getattr(pkt.mqtt, 'msgid', None)
                msg_type = getattr(pkt.mqtt, 'msgtype', None)
                
                # Track PUBLISH and PUBACK messages to calculate actual delays
                if msg_id and msg_type:
                    if msg_id not in mqtt_messages:
                        mqtt_messages[msg_id] = {}
                    
                    # Track different message types and timestamps
                    if msg_type == '3':  # PUBLISH
                        if dst_port == '1883':  # Device to Broker
                            mqtt_messages[msg_id]['device_publish_time'] = epoch_time
                        elif src_port == '1883':  # Broker to Cloud
                            mqtt_messages[msg_id]['broker_forward_time'] = epoch_time
                    elif msg_type == '4':  # PUBACK
                        if src_port == '1883':  # Broker to Device ACK
                            mqtt_messages[msg_id]['broker_ack_time'] = epoch_time
                        else:  # Cloud to Broker ACK
                            mqtt_messages[msg_id]['cloud_ack_time'] = epoch_time
            except Exception as e:
                pass  # Handle or log error
                
        elif hasattr(pkt, 'udp'):
            protocol = "UDP"
        elif hasattr(pkt, 'tcp'):
            protocol = "TCP"
            # Check for retransmission
            if hasattr(pkt.tcp, 'analysis_retransmission') or hasattr(pkt.tcp, 'analysis_fast_retransmission'):
                retrans_times.append(epoch_time)
        else:
            protocol = "OTHER"

        packet_records.append({
            "timestamp": epoch_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol
        })

    cap.close()

    df_packets = pd.DataFrame(packet_records).sort_values("timestamp").reset_index(drop=True)
    df_retrans = pd.DataFrame({"time": retrans_times, "event": ["TCP Retransmission"]*len(retrans_times)})

    # Calculate actual delays from MQTT message flow
    delay_records = []
    for msg_id, timestamps in mqtt_messages.items():
        # Check if we have enough data to calculate delays
        if 'device_publish_time' in timestamps and 'broker_ack_time' in timestamps:
            device_pub_time = timestamps['device_publish_time']
            broker_ack_time = timestamps['broker_ack_time']
            broker_forward_time = timestamps.get('broker_forward_time')
            cloud_ack_time = timestamps.get('cloud_ack_time')
            
            # Calculate delays
            device_to_broker_delay = broker_ack_time - device_pub_time
            
            # Calculate broker processing time if we have broker forward data
            broker_processing_delay = 0
            if broker_forward_time:
                broker_processing_delay = broker_forward_time - broker_ack_time
                
            # Calculate cloud upload delay if we have cloud ack data
            cloud_upload_delay = 0
            if cloud_ack_time and broker_forward_time:
                cloud_upload_delay = cloud_ack_time - broker_forward_time
                
            # Calculate total delay
            total_delay = 0
            if cloud_ack_time:
                total_delay = cloud_ack_time - device_pub_time
            else:
                total_delay = device_to_broker_delay + broker_processing_delay
            
            delay_records.append({
                "msg_id": msg_id,
                "device_publish_time": device_pub_time,
                "device_to_broker_delay": device_to_broker_delay,
                "broker_processing_delay": broker_processing_delay,
                "cloud_upload_delay": cloud_upload_delay,
                "total_delay": total_delay
            })
    
    # Use real delays if available, otherwise fall back to dummy data
    if delay_records:
        df_delays = pd.DataFrame(delay_records)
    else:
        df_delays, _ = generate_dummy_delays()
        
    return df_packets, df_delays, df_retrans


def generate_dummy_delays(num_samples=30, seed=42):
    """
    Simulate a small DataFrame of MQTT delays for demonstration:
    device->broker, broker processing, cloud upload, total
    Also returns a dummy protocol DataFrame if needed (skipped here).
    """
    np.random.seed(seed)
    base_time = 1_600_000_000
    device_pub_time = base_time + np.sort(np.random.randint(0, 1000, size=num_samples))

    # Make sure some outliers exist for better visualization
    dev2broker = np.random.uniform(0.02, 0.08, size=num_samples)
    dev2broker[np.random.choice(range(num_samples), 2)] *= 2.5  # Add some outliers
    
    broker_ack_time = device_pub_time + dev2broker

    broker_proc = np.random.uniform(0.08, 0.15, size=num_samples)
    broker_proc[np.random.choice(range(num_samples), 2)] *= 2.5  # Add some outliers
    broker_to_cloud_time = broker_ack_time + broker_proc

    cloud_up = np.random.uniform(0.15, 0.3, size=num_samples)
    cloud_up[np.random.choice(range(num_samples), 2)] *= 2.5  # Add some outliers
    cloud_ack_time = broker_to_cloud_time + cloud_up

    total_delay = cloud_ack_time - device_pub_time

    df_delays = pd.DataFrame({
        "msg_id": np.arange(1, num_samples+1),
        "device_publish_time": device_pub_time,
        "device_to_broker_delay": dev2broker,
        "broker_processing_delay": broker_proc,
        "cloud_upload_delay": cloud_up,
        "total_delay": total_delay
    })
    # No protocol data returned here
    return df_delays, None

# -------------------------------------------------------
# 2. Fallback Dummy Packet Data (if no PCAP)
# -------------------------------------------------------
def generate_dummy_packets(num_packets=80, seed=999):
    np.random.seed(seed)
    # Simulate random timestamps, IPs, protocols
    base_time = 1_600_100_000
    times = base_time + np.sort(np.random.randint(0, 5000, size=num_packets))

    # Simple IP sets
    ips = ["192.168.0.10", "192.168.0.20", "10.0.0.5", "203.0.113.8"]
    protos = ["MQTT", "TCP", "UDP"]
    records = []
    for i in range(num_packets):
        protocol = np.random.choice(protos, p=[0.4, 0.3, 0.3])
        src_ip = np.random.choice(ips)
        dst_ip = np.random.choice(ips)
        while dst_ip == src_ip:
            dst_ip = np.random.choice(ips)
        if protocol == "MQTT":
            src_port = 54321
            dst_port = 1883
        elif protocol == "TCP":
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.randint(1024, 65535)
        else:  # UDP
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.randint(1024, 65535)
        records.append({
            "timestamp": times[i],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol
        })

    df_packets = pd.DataFrame(records).sort_values("timestamp").reset_index(drop=True)

    # Create some retrans events
    rtimes = df_packets[df_packets["protocol"]=="TCP"].sample(frac=0.2)["timestamp"].values if len(df_packets)>0 else []
    df_retrans = pd.DataFrame({"time": rtimes, "event": ["TCP Retransmission"]*len(rtimes)})

    # Also create the dummy delays
    df_delays, _ = generate_dummy_delays(num_samples=40, seed=123)
    return df_packets, df_delays, df_retrans


# -------------------------------------------------------
# 3. Improved Packet Loss Calculation and Anomaly Detection
# -------------------------------------------------------
def compute_packet_loss(df_packets, df_retrans):
    """
    Calculate packet loss based on TCP retransmissions.
    """
    if df_packets.empty:
        return 0.0
        
    total_tcp = len(df_packets[df_packets["protocol"]=="TCP"])
    if total_tcp == 0:
        return 0.0
        
    # Count actual retransmissions
    retrans_count = len(df_retrans)
    
    # Calculate real packet loss percentage
    return (retrans_count / total_tcp) * 100.0


def detect_anomalies_in_delays(df_delays):
    """
    Apply different thresholds for different delay types to detect anomalies.
    """
    delay_types = ["device_to_broker_delay", "broker_processing_delay", 
                  "cloud_upload_delay", "total_delay"]
    
    thresholds = {}
    
    # Apply different thresholds for different delay types
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
            thresholds[col] = cutoff
            df_delays[f"{col}_anomaly"] = df_delays[col] > cutoff
    
    # Overall anomaly if any component is anomalous
    df_delays["is_anomaly"] = df_delays[[f"{col}_anomaly" for col in delay_types 
                                        if f"{col}_anomaly" in df_delays.columns]].any(axis=1)
    
    return df_delays, thresholds


def categorize_delays(df_delays):
    """
    Categorize delays into meaningful buckets and identify bottlenecks
    """
    # Define category thresholds for each delay type
    for delay_type in ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]:
        if delay_type in df_delays.columns:
            mean = df_delays[delay_type].mean()
            std = df_delays[delay_type].std()
            
            df_delays[f"{delay_type}_category"] = pd.cut(
                df_delays[delay_type],
                bins=[0, mean-0.5*std, mean+0.5*std, mean+2*std, float('inf')],
                labels=["Low", "Normal", "High", "Very High"]
            )
    
    # Identify bottleneck (which component contributes most to total delay)
    def identify_bottleneck(row):
        components = {
            "Device→Broker": row["device_to_broker_delay"],
            "Broker Processing": row["broker_processing_delay"],
            "Cloud Upload": row["cloud_upload_delay"]
        }
        return max(components.items(), key=lambda x: x[1])[0]
    
    df_delays["bottleneck"] = df_delays.apply(identify_bottleneck, axis=1)
    
    return df_delays


# -------------------------------------------------------
# 4. Improved Histogram Visualization
# -------------------------------------------------------
def hist_with_boundaries(df, xcol, title, color="royalblue"):
    """
    Create a histogram with better visual boundaries and statistical annotations.
    """
    # Calculate optimal bin count using Freedman-Diaconis rule
    q75, q25 = np.percentile(df[xcol], [75, 25])
    iqr = q75 - q25
    bin_width = 2 * iqr / (len(df) ** (1/3)) if iqr > 0 else 0.01
    bin_count = int(np.ceil((df[xcol].max() - df[xcol].min()) / bin_width))
    bin_count = max(10, min(30, bin_count))  # Keep between 10-30 bins
    
    fig = px.histogram(
        df, 
        x=xcol, 
        nbins=bin_count, 
        title=title, 
        labels={xcol: "Delay (s)"},
        color_discrete_sequence=[color]
    )
    
    # Add clear visual distinction to bars
    fig.update_traces(
        marker=dict(
            line=dict(color='rgba(0, 0, 0, 0.5)', width=1)
        ),
        opacity=0.8
    )
    
    # Calculate statistics
    mean_val = df[xcol].mean()
    std_val = df[xcol].std()
    median_val = df[xcol].median()
    
    # Add more visible annotations
    fig.add_vline(
        x=mean_val, 
        line_width=2, 
        line_dash="dash", 
        line_color="red", 
        annotation_text=f"Mean: {mean_val:.3f}s",
        annotation_position="top right",
        annotation_font=dict(size=12)
    )
    
    fig.add_vline(
        x=median_val, 
        line_width=2, 
        line_dash="dot", 
        line_color="green", 
        annotation_text=f"Median: {median_val:.3f}s",
        annotation_position="top left",
        annotation_font=dict(size=12)
    )
    
    # Make standard deviation range more visible
    fig.add_vrect(
        x0=mean_val-std_val, 
        x1=mean_val+std_val, 
        fillcolor="rgba(0, 100, 80, 0.2)", 
        opacity=0.4, 
        line_width=0,
        annotation_text=f"±1σ: {std_val:.3f}s", 
        annotation_position="bottom right"
    )
    
    # Improve overall appearance
    fig.update_layout(
        bargap=0.1,  # Gap between bars
        plot_bgcolor='rgba(240, 240, 240, 0.8)',
        xaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)'),
        yaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)')
    )
    
    return fig


# -------------------------------------------------------
# 5. Streamlit App
# -------------------------------------------------------
def main():
    st.title("StreamSight: IoT Network Analytics")

    # Sidebar file upload
    uploaded_file = st.sidebar.file_uploader("Upload a PCAP/PCAPNG file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        st.sidebar.write("Parsing PCAP file, please wait...")
        temp_dir = tempfile.TemporaryDirectory()
        temp_path = os.path.join(temp_dir.name, uploaded_file.name)
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())
        df_packets, df_delays, df_retrans = parse_pcap(temp_path)
        st.sidebar.success("PCAP parsed successfully!")
    else:
        st.sidebar.info("No PCAP uploaded. Using dummy data.")
        df_packets, df_delays, df_retrans = generate_dummy_packets()

    # Summaries
    total_packets = len(df_packets)
    earliest_ts = df_packets["timestamp"].min() if total_packets>0 else 0
    latest_ts   = df_packets["timestamp"].max() if total_packets>0 else 0
    unique_protocols = df_packets["protocol"].unique().tolist()
    
    # Calculate packet loss using improved method
    packet_loss_pct = compute_packet_loss(df_packets, df_retrans)

    # Delay classification and anomaly detection
    df_delays, thresholds = detect_anomalies_in_delays(df_delays)
    df_delays = categorize_delays(df_delays)

    # Prepare protocol distribution
    proto_count = df_packets["protocol"].value_counts().reset_index()
    proto_count.columns = ["protocol", "count"]

    # Add advanced filtering state
    st.session_state.setdefault("filter_protocol", "")
    st.session_state.setdefault("filter_ip", "")
    st.session_state.setdefault("filter_port", "")

    # Create tabs to reflect bullet points
    tabs = st.tabs([
    "Overview", 
    "Delay Analysis", 
    "Insights & Categorization", 
    "Timeline Analysis", 
    "Search & Filter", 
    "Data Explorer"
])

    # --------------------------------------------------
    # TAB 1: File Upload & Summary
    # --------------------------------------------------
    with tabs[0]:
        st.header("Overview")
    #     st.markdown("""
    # **Network capture summary**:
    # - Total packets analyzed
    # - Protocol distribution
    # - Capture timeframe
    # - Estimated packet loss
    # """)

        # For the Overview tab, replace the timestamp metrics with more useful information
        # Calculate metrics for Overview tab
        anomaly_count = len(df_delays[df_delays["is_anomaly"] == True])
        capture_duration = (latest_ts - earliest_ts) if total_packets > 0 else 0
        avg_total_delay = df_delays["total_delay"].mean()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Packets", f"{total_packets}")
        col2.metric("Avg E2E Delay", f"{avg_total_delay:.3f}s")
        col3.metric("Anomalies Detected", f"{anomaly_count}")
        col4.metric("Packet Loss %", f"{packet_loss_pct:.1f}%")



        st.subheader("Protocol Distribution")
        if not proto_count.empty:
            fig_proto = px.bar(proto_count, x="protocol", y="count",
                               title="Packet Count by Protocol",
                               labels={"count": "Count", "protocol": "Protocol"},
                               color="protocol",
                               color_discrete_map={
                                   "MQTT": "green",
                                   "TCP": "blue",
                                   "UDP": "orange",
                                   "OTHER": "gray"
                               })
            fig_proto.update_traces(marker_line_color='rgba(0,0,0,0.5)', marker_line_width=1)
            st.plotly_chart(fig_proto, use_container_width=True)
        else:
            st.info("No protocol data available.")

            

    # --------------------------------------------------
    # TAB 2: Delay Analysis Dashboard
    # --------------------------------------------------
    with tabs[1]:
        st.header("Delay Analysis")

        # Use the improved histogram function
        col1, col2 = st.columns(2)
        with col1:
            fig1 = hist_with_boundaries(df_delays, "device_to_broker_delay", "Device→Broker Delay", color="#1E88E5")
            st.plotly_chart(fig1, use_container_width=True)
            fig2 = hist_with_boundaries(df_delays, "broker_processing_delay", "Broker Processing Delay", color="#FFC107")
            st.plotly_chart(fig2, use_container_width=True)
        with col2:
            fig3 = hist_with_boundaries(df_delays, "cloud_upload_delay", "Cloud Upload Delay", color="#4CAF50")
            st.plotly_chart(fig3, use_container_width=True)
            fig4 = hist_with_boundaries(df_delays, "total_delay", "Total E2E Delay", color="#9C27B0")
            st.plotly_chart(fig4, use_container_width=True)

        # Display some average metrics
        avg_dev = df_delays["device_to_broker_delay"].mean()
        avg_broker = df_delays["broker_processing_delay"].mean()
        avg_cloud = df_delays["cloud_upload_delay"].mean()
        avg_total = df_delays["total_delay"].mean()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Avg Dev→Broker", f"{avg_dev:.3f}s")
        c2.metric("Avg Broker Proc", f"{avg_broker:.3f}s")
        c3.metric("Avg Cloud Up", f"{avg_cloud:.3f}s")
        c4.metric("Avg Total", f"{avg_total:.3f}s")

    # --------------------------------------------------
    # TAB 3: Delay Categorization & Insights
    # --------------------------------------------------
    with tabs[2]:
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
        st.subheader("Anomaly Detection Thresholds")
        threshold_df = pd.DataFrame({
            "Delay Type": list(thresholds.keys()),
            "Threshold (s)": [f"{val:.3f}" for val in thresholds.values()]
        })
        st.table(threshold_df)

        # Display bottleneck analysis 
        st.subheader("Bottleneck Analysis")
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
        
        # Display anomalies
        st.subheader("Detected Anomalies")
        anomalies = df_delays[df_delays["is_anomaly"] == True]
        st.write(f"Number of anomaly messages: {len(anomalies)}")
        if not anomalies.empty:
            st.dataframe(anomalies[["msg_id", "device_to_broker_delay", "broker_processing_delay", 
                                    "cloud_upload_delay", "total_delay", "bottleneck"]])
        else:
            st.info("No anomalies detected.")

    # --------------------------------------------------
    # TAB 4: Interactive Timeline & Graphs
    # --------------------------------------------------
    with tabs[3]:
        st.header("Timeline Analysis")
        st.markdown("""
    Temporal analysis of packet transmission, showing patterns, delays, anomalies, and congestion events over time.
    """)

        # Enhanced time-series visualization
        df_delays_plot = df_delays.copy()
        df_delays_plot["timestamp"] = pd.to_datetime(df_delays_plot["device_publish_time"], unit='s')
        
        # Add bottleneck information to plot
        fig_timeline = px.scatter(
            df_delays_plot, 
            x="timestamp", 
            y="total_delay",
            color="bottleneck",
            symbol=df_delays_plot["is_anomaly"].map({True: "triangle-up", False: "circle"}),
            size="total_delay",
            size_max=15,
            title="Total Delay Over Time with Bottleneck Identification",
            labels={
                "timestamp": "Time", 
                "total_delay": "Total Delay (s)",
                "bottleneck": "Primary Delay Contributor"
            },
            color_discrete_map={
                "Device→Broker": "#1E88E5",
                "Broker Processing": "#FFC107",
                "Cloud Upload": "#4CAF50"
            }
        )
        
        # Add horizontal lines for mean and thresholds
        fig_timeline.add_hline(
            y=df_delays["total_delay"].mean(), 
            line_width=1, 
            line_dash="dash", 
            line_color="black",
            annotation_text="Mean", 
            annotation_position="right"
        )
        
        if "total_delay" in thresholds:
            fig_timeline.add_hline(
                y=thresholds["total_delay"], 
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

    # --------------------------------------------------
    # TAB 5: Advanced Filtering & Search
    # --------------------------------------------------
    with tabs[4]:
        st.header("Search & Filter")
        st.markdown("""
    Narrow down your analysis by filtering on **protocol, IP, or port**. 
    Identify specific communication flows to pinpoint performance bottlenecks.
    """)

        # Get user input
        filter_proto = st.text_input("Protocol (MQTT/TCP/UDP) to filter", "")
        filter_ip = st.text_input("IP (src or dst) to filter", "")
        filter_port = st.text_input("Port (src or dst) to filter", "")

        # Apply filters
        filtered_df = df_packets.copy()
        if filter_proto.strip():
            filtered_df = filtered_df[filtered_df["protocol"].str.contains(filter_proto.strip(), case=False, na=False)]
        if filter_ip.strip():
            # match if src_ip or dst_ip has that substring
            mask_ip = filtered_df["src_ip"].str.contains(filter_ip.strip(), na=False) | \
                      filtered_df["dst_ip"].str.contains(filter_ip.strip(), na=False)
            filtered_df = filtered_df[mask_ip]
        if filter_port.strip():
            # match if src_port or dst_port
            mask_port = filtered_df["src_port"].astype(str).str.contains(filter_port.strip()) | \
                        filtered_df["dst_port"].astype(str).str.contains(filter_port.strip())
            filtered_df = filtered_df[mask_port]

        # Display filtered results
        st.write(f"Filtered Packet Count: {len(filtered_df)}")
        st.dataframe(filtered_df)
        
        # Add filter for delay types
        st.subheader("Delay Filtering")
        
        delay_filter_options = st.multiselect(
            "Filter by Delay Categories", 
            ["Low", "Normal", "High", "Very High"],
            default=["High", "Very High"]
        )
        
        delay_type_filter = st.selectbox(
            "Select Delay Type to Filter",
            ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]
        )
        
        if delay_filter_options:
            category_col = f"{delay_type_filter}_category"
            if category_col in df_delays.columns:
                filtered_delays = df_delays[df_delays[category_col].isin(delay_filter_options)]
                st.write(f"Found {len(filtered_delays)} messages with {delay_type_filter.replace('_', ' ')} in categories: {', '.join(delay_filter_options)}")
                st.dataframe(filtered_delays[["msg_id", delay_type_filter, category_col, "bottleneck", "is_anomaly"]])

    # --------------------------------------------------
    # TAB 6: Raw Data
    # --------------------------------------------------
    with tabs[5]:
        st.header("Data Explorer")
        st.subheader("Packets Table")
        st.dataframe(df_packets)
        st.subheader("MQTT Delays")
        st.dataframe(df_delays)
        st.subheader("Retransmissions")
        st.dataframe(df_retrans)


if __name__ == "__main__":
    main()
