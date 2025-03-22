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