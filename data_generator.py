import pandas as pd
import numpy as np

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

def generate_dummy_packets(num_packets=80, seed=999):
    """
    Generate dummy packet data for demonstration.
    """
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