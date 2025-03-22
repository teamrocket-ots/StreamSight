import pyshark
import pandas as pd
import numpy as np
from data_generator import generate_dummy_delays
import asyncio
import nest_asyncio
import sys

if sys.platform == "win32":
    # Windows-specific event loop policy
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
nest_asyncio.apply()
def parse_pcap(file_path):
    """
    Parse a .pcap or .pcapng using PyShark and extract MQTT delays.
    Returns:
      - df_packets: Detailed table of packets (src IP, dst IP, protocol, timestamps, ports, etc.)
      - df_delays: Table of actual MQTT delays across different stages
      - df_retrans: TCP retransmission events
    """

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    cap = pyshark.FileCapture(file_path, display_filter="mqtt or tcp or udp",eventloop=loop,use_json=True)

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
    loop.close()

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