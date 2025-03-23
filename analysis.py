import pandas as pd
import numpy as np

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

def analyze_tcp_delays(df_tcp):
    """
    Analyze TCP-specific delays:
    - Inter-Packet Delay (IPD)
    - Retransmission Delay
    - RTT Delay
    - ACK Delay
    - Jitter
    """
    if df_tcp.empty:
        return df_tcp
    
    # Calculate statistics for each connection
    conn_stats = {}
    
    for conn_id in df_tcp['conn_id'].unique():
        conn_data = df_tcp[df_tcp['conn_id'] == conn_id]
        
        stats = {}
        # IPD statistics
        if 'ipd' in conn_data.columns:
            stats['ipd_mean'] = conn_data['ipd'].mean()
            stats['ipd_std'] = conn_data['ipd'].std()
        
        # Retransmission statistics
        if 'retrans_delay' in conn_data.columns:
            retrans = conn_data[conn_data['retrans_delay'].notna()]
            stats['retrans_count'] = len(retrans)
            stats['retrans_delay_mean'] = retrans['retrans_delay'].mean() if not retrans.empty else 0
        
        # RTT statistics
        if 'rtt' in conn_data.columns:
            rtt_data = conn_data[conn_data['rtt'].notna()]
            stats['rtt_mean'] = rtt_data['rtt'].mean() if not rtt_data.empty else 0
            stats['rtt_max'] = rtt_data['rtt'].max() if not rtt_data.empty else 0
        
        # ACK delay statistics
        if 'ack_delay' in conn_data.columns:
            ack_data = conn_data[conn_data['ack_delay'].notna()]
            stats['ack_delay_mean'] = ack_data['ack_delay'].mean() if not ack_data.empty else 0
        
        # Jitter statistics
        if 'jitter' in conn_data.columns:
            jitter_data = conn_data[conn_data['jitter'].notna()]
            stats['jitter_mean'] = jitter_data['jitter'].mean() if not jitter_data.empty else 0
            stats['jitter_max'] = jitter_data['jitter'].max() if not jitter_data.empty else 0
        
        conn_stats[conn_id] = stats
    
    # Detect anomalous delays
    for delay_col in ['ipd', 'retrans_delay', 'rtt', 'ack_delay', 'jitter']:
        if delay_col in df_tcp.columns:
            mean_val = df_tcp[delay_col].mean()
            std_val = df_tcp[delay_col].std()
            threshold = mean_val + 2 * std_val
            
            df_tcp[f'{delay_col}_anomaly'] = df_tcp[delay_col] > threshold
    
    return df_tcp, conn_stats

def analyze_udp_delays(df_udp):
    """
    Analyze UDP-specific delays:
    - Inter-Packet Delay (IPD)
    - Jitter
    - Packet Loss Detection
    - Congestion Estimation
    """
    if df_udp.empty:
        return df_udp
    
    # Calculate statistics for each connection
    conn_stats = {}
    
    for conn_id in df_udp['conn_id'].unique():
        conn_data = df_udp[df_udp['conn_id'] == conn_id]
        
        stats = {}
        # IPD statistics
        if 'ipd' in conn_data.columns:
            stats['ipd_mean'] = conn_data['ipd'].mean()
            stats['ipd_std'] = conn_data['ipd'].std()
        
        # Jitter statistics
        if 'jitter' in conn_data.columns:
            jitter_data = conn_data[conn_data['jitter'].notna()]
            stats['jitter_mean'] = jitter_data['jitter'].mean() if not jitter_data.empty else 0
            stats['jitter_max'] = jitter_data['jitter'].max() if not jitter_data.empty else 0
        
        # Packet loss statistics
        if 'possible_loss' in conn_data.columns:
            stats['possible_loss_sum'] = conn_data['possible_loss'].sum()
            stats['total_packets'] = len(conn_data)
            stats['packet_loss_pct'] = (stats['possible_loss_sum'] / (stats['total_packets'] + stats['possible_loss_sum'])) * 100
        
        # Congestion statistics
        if 'congestion_score' in conn_data.columns:
            stats['congestion_score_mean'] = conn_data['congestion_score'].mean()
            stats['congestion_score_max'] = conn_data['congestion_score'].max()
        
        conn_stats[conn_id] = stats
    
    # Categorize jitter levels
    if 'jitter' in df_udp.columns:
        mean_jitter = df_udp['jitter'].mean()
        std_jitter = df_udp['jitter'].std()
        
        df_udp['jitter_category'] = pd.cut(
            df_udp['jitter'],
            bins=[0, mean_jitter, mean_jitter + std_jitter, float('inf')],
            labels=['Low', 'Medium', 'High']
        )
    
    # Categorize congestion levels
    if 'congestion_score' in df_udp.columns:
        df_udp['congestion_level'] = pd.cut(
            df_udp['congestion_score'],
            bins=[0, 0.2, 0.5, 1.0, float('inf')],
            labels=['Low', 'Medium', 'High', 'Very High']
        )
    
    return df_udp, conn_stats

def analyze_mqtt_delays(df_mqtt):
    """
    Analyze MQTT-specific delays:
    - Broker Processing Delay
    - Broker-Client Delay (Device to Broker)
    - Cloud Delay
    """
    if df_mqtt.empty:
        return df_mqtt
    
    # Identify entities (Client, Broker, Cloud)
    entity_counts = df_mqtt.groupby('entity').size().to_dict()
    
    # Calculate statistics for each message type
    msg_type_stats = df_mqtt.groupby('msg_type_name').size().to_dict()
    
    # Categorize delays into meaningful buckets
    delay_types = ['broker_processing_delay', 'device_to_broker_delay', 
                  'cloud_upload_delay', 'total_delay']
    
    for delay_type in delay_types:
        if delay_type in df_mqtt.columns:
            mean = df_mqtt[delay_type].mean()
            std = df_mqtt[delay_type].std()
            
            df_mqtt[f'{delay_type}_category'] = pd.cut(
                df_mqtt[delay_type],
                bins=[0, mean-0.5*std, mean+0.5*std, mean+2*std, float('inf')],
                labels=['Low', 'Normal', 'High', 'Very High']
            )
    
    # Identify bottleneck (which component contributes most to total delay)
    if all(col in df_mqtt.columns for col in ['broker_processing_delay', 
                                             'device_to_broker_delay', 
                                             'cloud_upload_delay']):
        def identify_bottleneck(row):
            components = {
                "Device→Broker": row["device_to_broker_delay"],
                "Broker Processing": row["broker_processing_delay"],
                "Cloud Upload": row["cloud_upload_delay"]
            }
            return max(components.items(), key=lambda x: x[1])[0]
        
        df_mqtt["bottleneck"] = df_mqtt.apply(identify_bottleneck, axis=1)
    
    # Collect overall statistics
    stats = {
        'entity_counts': entity_counts,
        'msg_type_stats': msg_type_stats
    }
    
    for delay_type in delay_types:
        if delay_type in df_mqtt.columns:
            stats[f'{delay_type}_mean'] = df_mqtt[delay_type].mean()
            stats[f'{delay_type}_median'] = df_mqtt[delay_type].median()
            stats[f'{delay_type}_max'] = df_mqtt[delay_type].max()
            stats[f'{delay_type}_std'] = df_mqtt[delay_type].std()
    
    return df_mqtt, stats
