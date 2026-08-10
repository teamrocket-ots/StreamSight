"""Synthetic traffic generation for demo mode and for testing.

Generated packets are pushed through the same
:func:`pcap_parser.calculate_tcp_metrics` / :func:`~pcap_parser.calculate_udp_metrics`
functions the real parser uses, so the demo frames cannot drift out of schema
with the parsed ones -- and so the metric code gets exercised on a continuous
UDP stream, which none of the sample captures contain.
"""

import numpy as np
import pandas as pd

from pcap_parser import calculate_tcp_metrics, calculate_udp_metrics
from units import SEC_TO_MS

BASE_TIME = 1_600_000_000
CLIENT_IP = "192.168.0.10"
BROKER_IP = "192.168.0.20"
CLOUD_IP = "203.0.113.8"


def generate_dummy_delays(num_samples=30, seed=42):
    """Simulate MQTT delay components. Values are in milliseconds."""
    rng = np.random.default_rng(seed)
    device_pub_time = BASE_TIME + np.sort(rng.integers(0, 1000, size=num_samples)).astype(float)

    def component(low, high):
        values = rng.uniform(low, high, size=num_samples)
        # A few outliers, so anomaly detection has something to find.
        values[rng.choice(num_samples, size=min(2, num_samples), replace=False)] *= 2.5
        return values

    dev2broker = component(0.02, 0.08)
    broker_proc = component(0.08, 0.15)
    cloud_up = component(0.15, 0.30)

    df_delays = pd.DataFrame({
        "msg_id": [str(i) for i in range(1, num_samples + 1)],
        "device_publish_time": device_pub_time,
        "device_to_broker_delay": dev2broker * SEC_TO_MS,
        "broker_processing_delay": broker_proc * SEC_TO_MS,
        "cloud_upload_delay": cloud_up * SEC_TO_MS,
        "total_delay": (dev2broker + broker_proc + cloud_up) * SEC_TO_MS,
        "qos": 1,
    })
    return df_delays, None


def generate_dummy_tcp(num_packets=200, seed=7):
    """A synthetic bidirectional TCP conversation, with a handshake and retransmissions."""
    rng = np.random.default_rng(seed)
    packets = []
    t = float(BASE_TIME)
    conn_id, label = "tcp-0", f"{CLIENT_IP}:54321 - {BROKER_IP}:8883"

    def record(timestamp, from_client, seq, ack, syn=0, ack_flag=1, payload=0, retrans=False):
        return {
            "packet_id": len(packets),
            "timestamp": timestamp,
            "src_ip": CLIENT_IP if from_client else BROKER_IP,
            "dst_ip": BROKER_IP if from_client else CLIENT_IP,
            "ip_version": 4,
            "protocol": "TCP",
            "src_port": 54321 if from_client else 8883,
            "dst_port": 8883 if from_client else 54321,
            "seq_num": seq,
            "ack_num": ack,
            "flags_syn": syn,
            "flags_ack": ack_flag,
            "flags_rst": 0,
            "flags_fin": 0,
            "payload_size": payload,
            "is_retrans": retrans,
            "ack_rtt": np.nan,
            "conn_id": conn_id,
            "conn_label": label,
            "zero_window": False,
            "window_full": False,
            "duplicate_ack": False,
            "out_of_order": False,
            "spurious_retrans": False,
        }

    # Three-way handshake, so handshake_rtt has something to measure.
    packets.append(record(t, True, 0, 0, syn=1, ack_flag=0))
    t += 0.045
    packets.append(record(t, False, 0, 1, syn=1))
    t += 0.001
    packets.append(record(t, True, 1, 1))

    seq = 1
    for i in range(num_packets):
        t += float(rng.uniform(0.008, 0.014))
        payload = int(rng.integers(40, 1400))
        retrans = bool(rng.random() < 0.03)
        packets.append(record(t, True, seq, 1, payload=payload, retrans=retrans))
        if not retrans:
            seq += payload
        # The peer acknowledges after a short, occasionally long, delay.
        t += float(rng.uniform(0.002, 0.02)) * (5 if rng.random() < 0.05 else 1)
        ack_packet = record(t, False, 1, seq)
        if rng.random() < 0.04:
            ack_packet["zero_window"] = True
        if rng.random() < 0.03:
            ack_packet["duplicate_ack"] = True
        packets.append(ack_packet)

    return calculate_tcp_metrics({conn_id: packets})


def generate_dummy_udp(num_packets=300, seed=11):
    """A continuous UDP media-style stream at ~10 ms spacing, with jitter and gaps.

    Nominally RTP: sequence numbers are present, so the sequence-gap loss path is
    exercised as well as the timing-gap one.
    """
    rng = np.random.default_rng(seed)
    packets = []
    t = float(BASE_TIME)
    seq = 1000
    conn_id, label = "udp-0", f"{CLIENT_IP}:5004 - {CLOUD_IP}:5004"

    for i in range(num_packets):
        # 10 ms nominal spacing with jitter; occasional stalls stand in for loss.
        gap = float(rng.normal(0.010, 0.0015))
        dropped = 0
        if rng.random() < 0.04:
            dropped = int(rng.integers(1, 4))
            gap += 0.010 * dropped
        t += max(gap, 0.0005)
        seq += 1 + dropped

        packets.append({
            "packet_id": i,
            "timestamp": t,
            "src_ip": CLIENT_IP,
            "dst_ip": CLOUD_IP,
            "ip_version": 4,
            "protocol": "UDP",
            "src_port": 5004,
            "dst_port": 5004,
            "payload_size": int(rng.integers(160, 1200)),
            "conn_id": conn_id,
            "conn_label": label,
            "is_multicast": False,
            "seq_num": seq,
        })

    return calculate_udp_metrics({conn_id: packets})


def generate_dummy_mqtt(num_messages=40, seed=5):
    """Synthetic MQTT packet records carrying QoS 1 delay components."""
    df_delays, _ = generate_dummy_delays(num_samples=num_messages, seed=seed)

    rows = []
    for i, delay_row in df_delays.iterrows():
        publish_time = float(delay_row["device_publish_time"])
        for offset, entity, msg_type, type_name, from_client in (
            (0.0, "CLIENT", "3", "PUBLISH", True),
            (float(delay_row["device_to_broker_delay"]) / SEC_TO_MS, "BROKER", "4", "PUBACK", False),
        ):
            rows.append({
                "packet_id": len(rows),
                "timestamp": publish_time + offset,
                "src_ip": CLIENT_IP if from_client else BROKER_IP,
                "dst_ip": BROKER_IP if from_client else CLIENT_IP,
                "ip_version": 4,
                "protocol": "MQTT",
                "src_port": 54321 if from_client else 1883,
                "dst_port": 1883 if from_client else 54321,
                "msg_id": str(delay_row["msg_id"]),
                "msg_type": msg_type,
                "msg_type_name": type_name,
                "conn_id": "mqtt-0",
                "conn_label": f"{CLIENT_IP}:54321 - {BROKER_IP}:1883",
                "entity": entity,
                "is_retrans": False,
            })

    df_mqtt = pd.DataFrame(rows)
    return df_mqtt.merge(df_delays, on="msg_id", how="left")


def generate_dummy_packets(num_packets=80, seed=999):
    """Generate a full demo dataset matching the real parser's output shape."""
    df_tcp = generate_dummy_tcp(seed=seed)
    df_udp = generate_dummy_udp(seed=seed)
    df_mqtt = generate_dummy_mqtt(seed=seed)
    df_delays, _ = generate_dummy_delays(num_samples=40, seed=seed)

    columns = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "ip_version", "protocol"]
    frames = [df[columns] for df in (df_tcp, df_udp, df_mqtt) if not df.empty]
    df_packets = (
        pd.concat(frames, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
        if frames else pd.DataFrame(columns=columns)
    )

    retrans_times = (
        df_tcp.loc[df_tcp["is_retrans"].fillna(False).astype(bool), "timestamp"].tolist()
        if "is_retrans" in df_tcp.columns else []
    )
    df_retrans = pd.DataFrame({
        "time": retrans_times,
        "event": ["TCP Retransmission"] * len(retrans_times),
    })

    return df_packets, df_delays, df_retrans, df_tcp, df_udp, df_mqtt
