import pyshark
import pandas as pd
import numpy as np
#from data_generator import generate_dummy_delays  # Only if you need dummy data

def parse_pcap(file_path):
    """
    Parse a .pcap or .pcapng using PyShark and extract:
      - df_packets: Detailed table of packets (src/dst IP, protocol, timestamps, ports, etc.)
      - df_delays: MQTT delays (Broker Processing, Broker-Client, Cloud Upload, Total)
      - df_retrans: TCP retransmission events
      - clients: IPs initiating MQTT CONNECT
      - brokers: IPs responding with CONNACK
    """
    # Capture all protocols
    cap = pyshark.FileCapture(file_path)
    
    packet_records = []
    retrans_times = []
    mqtt_messages = {}
    clients = set()
    brokers = set()
    
    for pkt in cap:
        # Attempt to get a valid timestamp
        try:
            epoch_time = float(pkt.frame_info.time_epoch)
        except Exception:
            continue  # skip packets lacking a valid timestamp
        
        # IP addresses if present
        src_ip = getattr(pkt.ip, 'src', None) if hasattr(pkt, 'ip') else None
        dst_ip = getattr(pkt.ip, 'dst', None) if hasattr(pkt, 'ip') else None
        
        # Safely get TCP/UDP ports
        src_port, dst_port = None, None
        if hasattr(pkt, 'tcp'):
            src_port = getattr(pkt.tcp, 'srcport', None)
            dst_port = getattr(pkt.tcp, 'dstport', None)
        elif hasattr(pkt, 'udp'):
            src_port = getattr(pkt.udp, 'srcport', None)
            dst_port = getattr(pkt.udp, 'dstport', None)
        
        # Determine protocol
        if hasattr(pkt, 'mqtt'):
            protocol = "MQTT"
            try:
                msg_id = getattr(pkt.mqtt, 'msgid', None)
                msg_type = getattr(pkt.mqtt, 'msgtype', None)
                
                # Identify connection initiation/response
                if msg_type == '1':  # CONNECT
                    if src_ip:
                        clients.add(src_ip)
                    if dst_ip:
                        brokers.add(dst_ip)
                    if msg_id not in mqtt_messages:
                        mqtt_messages[msg_id] = {}
                    mqtt_messages[msg_id]['connect_time'] = epoch_time
                
                elif msg_type == '2':  # CONNACK
                    if src_ip:
                        brokers.add(src_ip)
                    if msg_id not in mqtt_messages:
                        mqtt_messages[msg_id] = {}
                    mqtt_messages[msg_id]['connack_time'] = epoch_time
                
                elif msg_type == '3':  # PUBLISH
                    if msg_id not in mqtt_messages:
                        mqtt_messages[msg_id] = {}
                    # Client → Broker
                    if dst_port == '1883':
                        mqtt_messages[msg_id]['client_publish_time'] = epoch_time
                    # Broker → Cloud
                    elif src_port == '1883':
                        mqtt_messages[msg_id]['broker_forward_time'] = epoch_time
                
                elif msg_type == '4':  # PUBACK
                    if msg_id not in mqtt_messages:
                        mqtt_messages[msg_id] = {}
                    # Broker → Client ACK
                    if src_port == '1883':
                        mqtt_messages[msg_id]['broker_ack_time'] = epoch_time
                    # Cloud → Broker ACK
                    else:
                        mqtt_messages[msg_id]['cloud_ack_time'] = epoch_time
            
            except Exception as e:
                print(f"Error processing MQTT packet: {e}")
        
        elif hasattr(pkt, 'tcp'):
            protocol = "TCP"
            # Check for TCP retransmissions
            if hasattr(pkt.tcp, 'analysis_retransmission') or hasattr(pkt.tcp, 'analysis_fast_retransmission'):
                retrans_times.append(epoch_time)
        
        elif hasattr(pkt, 'udp'):
            protocol = "UDP"
        
        else:
            # Use highest_layer for DNS, VNC, HTTP, etc.
            protocol = getattr(pkt, 'highest_layer', 'UNKNOWN')
        
        # Build a record of the packet
        packet_records.append({
            "timestamp": epoch_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol
        })
    
    cap.close()
    
    # Build DataFrames
    df_packets = pd.DataFrame(packet_records).sort_values("timestamp").reset_index(drop=True)
    df_retrans = pd.DataFrame({"time": retrans_times, "event": ["TCP Retransmission"] * len(retrans_times)})
    
    # Log detected clients and brokers
    print("Detected Clients:", clients)
    print("Detected Brokers:", brokers)
    
    # Compute MQTT delays
    delay_records = []
    for msg_id, timestamps in mqtt_messages.items():
        # Need client_publish_time + broker_ack_time for a basic broker-client delay
        if 'client_publish_time' in timestamps and 'broker_ack_time' in timestamps:
            client_publish_time = timestamps['client_publish_time']
            broker_ack_time = timestamps['broker_ack_time']
            broker_forward_time = timestamps.get('broker_forward_time')
            cloud_ack_time = timestamps.get('cloud_ack_time')
            
            # Delays
            broker_client_delay = broker_ack_time - client_publish_time
            broker_processing_delay = (broker_forward_time - broker_ack_time) if broker_forward_time else 0
            cloud_upload_delay = (cloud_ack_time - broker_forward_time) if (cloud_ack_time and broker_forward_time) else 0
            
            # Total
            total_delay = (cloud_ack_time - client_publish_time) if cloud_ack_time else (
                broker_client_delay + broker_processing_delay
            )
            
            delay_records.append({
                "msg_id": msg_id,
                "client_publish_time": client_publish_time,
                "broker_client_delay": broker_client_delay,
                "broker_processing_delay": broker_processing_delay,
                "cloud_upload_delay": cloud_upload_delay,
                "total_delay": total_delay
            })
    
    df_delays = pd.DataFrame(delay_records) if delay_records else pd.DataFrame()
    if df_delays.empty:
        print("No MQTT delays detected.")
    
    print("MQTT Delay Summary:")
    print(df_delays.head())
    
    return df_packets, df_delays, df_retrans, clients, brokers
