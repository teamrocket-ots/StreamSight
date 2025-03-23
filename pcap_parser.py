import pyshark
import pandas as pd
import numpy as np
import asyncio
import nest_asyncio
import sys
from collections import defaultdict
from data_generator import generate_dummy_delays  # Using your updated import

# Set event loop policy and apply nest_asyncio (always apply to avoid loop issues)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
nest_asyncio.apply()

def parse_pcap(file_path):
    """
    Parse a .pcap or .pcapng file using PyShark and extract:
      - df_packets: General packet information (src/dst IP, protocol, timestamps, ports, etc.)
      - df_delays: MQTT delay components (Broker Processing, Broker-Client, Cloud Upload, Total)
      - df_retrans: TCP retransmission events
      - df_tcp: TCP-specific metrics (including IPD, RTT, jitter, etc.)
      - df_udp: UDP-specific metrics (including IPD, jitter, congestion score, etc.)
      - df_mqtt: MQTT-specific metrics (including delay calculations)
    
    The parser incorporates both standard MQTT messages and also treats TCP traffic on port 8883 as MQTT traffic.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Open the pcap file with a display filter for efficiency
    cap = pyshark.FileCapture(file_path, display_filter="mqtt or tcp or udp", 
                              eventloop=loop, use_json=True)
    
    # Initialize data structures for overall packet data and protocol-specific tracking
    packet_records = []
    retrans_times = []
    tcp_connections = defaultdict(list)
    udp_connections = defaultdict(list)
    mqtt_messages = {}       # For tracking delay components by message ID
    mqtt_connections = defaultdict(list)  # For MQTT-specific packet details
    clients = set()
    brokers = set()
    
    # Process each packet in the capture
    for packet_id, packet in enumerate(cap):
        try:
            # Extract common packet information
            timestamp = float(packet.frame_info.time_epoch)
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'OTHER'
            
            # Get IP addresses if available
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            else:
                src_ip, dst_ip = None, None

            # Get TCP/UDP ports (as strings for consistency with comparisons)
            src_port, dst_port = None, None
            if hasattr(packet, 'tcp'):
                src_port = getattr(packet.tcp, 'srcport', None)
                dst_port = getattr(packet.tcp, 'dstport', None)
            elif hasattr(packet, 'udp'):
                src_port = getattr(packet.udp, 'srcport', None)
                dst_port = getattr(packet.udp, 'dstport', None)
            
            # Base packet info record
            packet_info = {
                'packet_id': packet_id,
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol
            }
            
            # Process MQTT packets if present
            if hasattr(packet, 'mqtt'):
                protocol = "MQTT"
                try:
                    msg_id = getattr(packet.mqtt, 'msgid', None)
                    msg_type = getattr(packet.mqtt, 'msgtype', None)
                    # Map message type using helper
                    msg_type_name = get_mqtt_msg_type(msg_type)
                    
                    # Build a MQTT info record to be used in mqtt_connections
                    mqtt_info = {
                        **packet_info,
                        'src_port': int(src_port) if src_port is not None else 0,
                        'dst_port': int(dst_port) if dst_port is not None else 0,
                        'msg_id': msg_id,
                        'msg_type': msg_type,
                        'msg_type_name': msg_type_name,
                        'conn_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    }
                    
                    # Updated MQTT handling logic:
                    if msg_type == '1':  # CONNECT
                        if src_ip:
                            clients.add(src_ip)
                        if dst_ip:
                            brokers.add(dst_ip)
                        mqtt_messages.setdefault(msg_id, {})['connect_time'] = timestamp
                        mqtt_info['entity'] = 'CLIENT'
                    elif msg_type == '2':  # CONNACK
                        if src_ip:
                            brokers.add(src_ip)
                        mqtt_messages.setdefault(msg_id, {})['connack_time'] = timestamp
                        mqtt_info['entity'] = 'BROKER'
                    elif msg_type == '3':  # PUBLISH
                        mqtt_messages.setdefault(msg_id, {})
                        # Use port heuristics to decide role
                        if dst_port == '1883':
                            mqtt_messages[msg_id]['client_publish_time'] = timestamp
                            mqtt_info['entity'] = 'CLIENT'
                        elif src_port == '1883':
                            mqtt_messages[msg_id]['broker_forward_time'] = timestamp
                            mqtt_info['entity'] = 'BROKER'
                    elif msg_type == '4':  # PUBACK
                        mqtt_messages.setdefault(msg_id, {})
                        if src_port == '1883':
                            mqtt_messages[msg_id]['broker_ack_time'] = timestamp
                            mqtt_info['entity'] = 'BROKER'
                        else:
                            mqtt_messages[msg_id]['cloud_ack_time'] = timestamp
                            mqtt_info['entity'] = 'CLOUD'
                    else:
                        mqtt_info['entity'] = 'UNKNOWN'
                    
                    mqtt_connections[mqtt_info['conn_id']].append(mqtt_info)
                except Exception as e:
                    print(f"Error processing MQTT packet: {e}")
            
            # For TCP packets on port 8883 that are not marked as MQTT by PyShark
            elif hasattr(packet, 'tcp') and (src_port == '8883' or dst_port == '8883'):
                protocol = "MQTT"
                # Use TCP stream ID as a surrogate message ID
                msg_id = getattr(packet.tcp, 'stream', None)
                if msg_id is None:
                    msg_id = f'8883_{timestamp}'
                mqtt_messages.setdefault(msg_id, {})
                
                # Determine client and broker based on port direction
                if src_port == '8883':
                    broker_ip = src_ip
                    client_ip = dst_ip
                elif dst_port == '8883':
                    broker_ip = dst_ip
                    client_ip = src_ip
                
                if broker_ip:
                    brokers.add(broker_ip)
                if client_ip:
                    clients.add(client_ip)
                
                # Heuristic for delay timings on port 8883:
                if dst_port == '8883':
                    if 'client_publish_time' not in mqtt_messages[msg_id]:
                        mqtt_messages[msg_id]['client_publish_time'] = timestamp
                    else:
                        if 'broker_forward_time' not in mqtt_messages[msg_id]:
                            mqtt_messages[msg_id]['broker_forward_time'] = timestamp
                elif src_port == '8883':
                    if 'broker_ack_time' not in mqtt_messages[msg_id]:
                        mqtt_messages[msg_id]['broker_ack_time'] = timestamp
                    else:
                        if 'cloud_ack_time' not in mqtt_messages[msg_id]:
                            mqtt_messages[msg_id]['cloud_ack_time'] = timestamp
                
                # Build a basic MQTT info record for these packets
                mqtt_info = {
                    **packet_info,
                    'src_port': int(src_port) if src_port is not None else 0,
                    'dst_port': int(dst_port) if dst_port is not None else 0,
                    'msg_id': msg_id,
                    'msg_type': None,
                    'msg_type_name': None,
                    'conn_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
                    'entity': 'UNKNOWN'
                }
                mqtt_connections[mqtt_info['conn_id']].append(mqtt_info)
            
            # Process plain TCP packets (excluding the 8883 MQTT branch)
            elif hasattr(packet, 'tcp'):
                protocol = "TCP"
                src_port = int(src_port) if src_port is not None else 0
                dst_port = int(dst_port) if dst_port is not None else 0
                conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                seq_num = int(packet.tcp.seq) if hasattr(packet.tcp, 'seq') else 0
                ack_num = int(packet.tcp.ack) if hasattr(packet.tcp, 'ack') else 0
                
                flags_syn = 1 if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1' else 0
                flags_ack = 1 if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '1' else 0
                flags_rst = 1 if hasattr(packet.tcp, 'flags_reset') and packet.tcp.flags_reset == '1' else 0
                flags_fin = 1 if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1' else 0
                
                payload_size = len(packet) - int(packet.tcp.hdr_len) if hasattr(packet.tcp, 'hdr_len') else 0
                
                is_retrans = False
                if hasattr(packet.tcp, 'analysis_retransmission') or hasattr(packet.tcp, 'analysis_fast_retransmission'):
                    retrans_times.append(timestamp)
                    is_retrans = True
                
                tcp_info = {
                    **packet_info,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'seq_num': seq_num,
                    'ack_num': ack_num,
                    'flags_syn': flags_syn,
                    'flags_ack': flags_ack,
                    'flags_rst': flags_rst,
                    'flags_fin': flags_fin,
                    'payload_size': payload_size,
                    'is_retrans': is_retrans,
                    'conn_id': conn_id
                }
                tcp_connections[conn_id].append(tcp_info)
            
            # Process UDP packets
            elif hasattr(packet, 'udp'):
                protocol = "UDP"
                src_port = int(src_port) if src_port is not None else 0
                dst_port = int(dst_port) if dst_port is not None else 0
                conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                udp_info = {
                    **packet_info,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'payload_size': len(packet) if hasattr(packet, 'udp') else 0,
                    'conn_id': conn_id
                }
                if hasattr(packet, 'rtp'):
                    udp_info['seq_num'] = int(packet.rtp.seq) if hasattr(packet.rtp, 'seq') else None
                udp_connections[conn_id].append(udp_info)
            
            # For any other protocol, no additional processing is done
            
            # Record the general packet info
            packet_records.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol
            })
        except Exception as e:
            print(f"Error processing packet {packet_id}: {e}")
    
    cap.close()
    loop.close()
    
    # Build DataFrames for general packets and retransmissions
    df_packets = pd.DataFrame(packet_records).sort_values("timestamp").reset_index(drop=True)
    df_retrans = pd.DataFrame({"time": retrans_times, "event": ["TCP Retransmission"] * len(retrans_times)})
    
    print("Detected Clients:", clients)
    print("Detected Brokers:", brokers)
    
    # Calculate MQTT delays from tracked message timestamps
    df_delays = extract_mqtt_delays(mqtt_messages)
    if df_delays.empty:
        print("No MQTT delays detected.")
    else:
        print("MQTT Delay Summary:")
        print(df_delays.head())
    
    # Calculate protocol-specific metrics
    df_tcp = calculate_tcp_metrics(tcp_connections)
    df_udp = calculate_udp_metrics(udp_connections)
    df_mqtt = calculate_mqtt_metrics(mqtt_connections, mqtt_messages)
    
    return df_packets, df_delays, df_retrans, df_tcp, df_udp, df_mqtt

def get_mqtt_msg_type(type_code):
    """Map MQTT message type codes to names"""
    mqtt_types = {
        '1': "CONNECT", '2': "CONNACK", '3': "PUBLISH", '4': "PUBACK",
        '5': "PUBREC", '6': "PUBREL", '7': "PUBCOMP", '8': "SUBSCRIBE",
        '9': "SUBACK", '10': "UNSUBSCRIBE", '11': "UNSUBACK",
        '12': "PINGREQ", '13': "PINGRESP", '14': "DISCONNECT"
    }
    return mqtt_types.get(type_code, "UNKNOWN")

def is_external_ip(ip):
    """Determine if an IP is likely external/cloud service"""
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    if octets[0] == '10':
        return False
    if octets[0] == '172' and 16 <= int(octets[1]) <= 31:
        return False
    if octets[0] == '192' and octets[1] == '168':
        return False
    return True

def extract_mqtt_delays(mqtt_messages):
    """Calculate MQTT delay components from tracked message timestamps"""
    delay_records = []
    for msg_id, timestamps in mqtt_messages.items():
        # Ensure we have the minimum timestamps for delay calculation
        if 'client_publish_time' in timestamps and 'broker_ack_time' in timestamps:
            client_publish_time = timestamps['client_publish_time']
            broker_ack_time = timestamps['broker_ack_time']
            broker_forward_time = timestamps.get('broker_forward_time')
            cloud_ack_time = timestamps.get('cloud_ack_time')
            
            broker_client_delay = broker_ack_time - client_publish_time
            broker_processing_delay = (broker_forward_time - broker_ack_time) if broker_forward_time else 0
            cloud_upload_delay = (cloud_ack_time - broker_forward_time) if (cloud_ack_time and broker_forward_time) else 0
            
            total_delay = (cloud_ack_time - client_publish_time) if cloud_ack_time else (
                broker_client_delay + broker_processing_delay
            )
            
            delay_records.append({
                "msg_id": msg_id,
                "device_publish_time": client_publish_time,  # Ensure this matches
                "device_to_broker_delay": broker_ack_time - client_publish_time,  # Fixed column name
                "broker_processing_delay": (broker_forward_time - broker_ack_time) if broker_forward_time else 0,
                "cloud_upload_delay": (cloud_ack_time - broker_forward_time) if (cloud_ack_time and broker_forward_time) else 0,
                "total_delay": total_delay
})

    return pd.DataFrame(delay_records) if delay_records else pd.DataFrame()

def calculate_tcp_metrics(tcp_connections):
    """Calculate TCP-specific metrics such as IPD, RTT, jitter and retransmission details"""
    if not tcp_connections:
        return pd.DataFrame()
    
    tcp_data = []
    for conn_id, packets in tcp_connections.items():
        packets.sort(key=lambda x: x['timestamp'])
        for i in range(1, len(packets)):
            packets[i]['ipd'] = packets[i]['timestamp'] - packets[i-1]['timestamp']
        seq_nums = {}
        for i, pkt in enumerate(packets):
            seq = pkt['seq_num']
            if seq in seq_nums and seq > 0:
                packets[i]['retrans_delay'] = pkt['timestamp'] - packets[seq_nums[seq]]['timestamp']
            seq_nums.setdefault(seq, i)
        for i, pkt in enumerate(packets):
            if pkt['flags_syn'] == 1 and pkt['flags_ack'] == 0:
                for j in range(i+1, len(packets)):
                    if packets[j]['flags_syn'] == 1 and packets[j]['flags_ack'] == 1:
                        packets[i]['rtt'] = packets[j]['timestamp'] - pkt['timestamp']
                        break
        for i in range(len(packets)-1):
            if (packets[i]['payload_size'] > 0 and 
                packets[i+1]['flags_ack'] == 1 and
                packets[i+1]['ack_num'] == packets[i]['seq_num'] + packets[i]['payload_size']):
                packets[i]['ack_delay'] = packets[i+1]['timestamp'] - packets[i]['timestamp']
        for i in range(2, len(packets)):
            if 'ipd' in packets[i] and 'ipd' in packets[i-1]:
                packets[i]['jitter'] = abs(packets[i]['ipd'] - packets[i-1]['ipd'])
        tcp_data.extend(packets)
    
    df_tcp = pd.DataFrame(tcp_data)
    if 'is_retrans' in df_tcp.columns:
        total_packets = len(df_tcp)
        retrans_count = df_tcp['is_retrans'].sum()
        packet_loss_pct = (retrans_count / total_packets) * 100 if total_packets > 0 else 0
        df_tcp['packet_loss_pct'] = packet_loss_pct
    return df_tcp

def calculate_udp_metrics(udp_connections):
    """Calculate UDP-specific metrics such as IPD, jitter, and congestion score"""
    if not udp_connections:
        return pd.DataFrame()
    
    udp_data = []
    for conn_id, packets in udp_connections.items():
        packets.sort(key=lambda x: x['timestamp'])
        for i in range(1, len(packets)):
            packets[i]['ipd'] = packets[i]['timestamp'] - packets[i-1]['timestamp']
        ipds = [pkt['ipd'] for pkt in packets if 'ipd' in pkt]
        mean_ipd = np.mean(ipds) if ipds else 0
        std_ipd = np.std(ipds) if ipds else 0
        for i in range(2, len(packets)):
            if 'ipd' in packets[i] and 'ipd' in packets[i-1]:
                packets[i]['jitter'] = abs(packets[i]['ipd'] - packets[i-1]['ipd'])
                ipd_threshold = mean_ipd + 3 * std_ipd
                if packets[i]['ipd'] > ipd_threshold:
                    packets[i]['possible_loss'] = np.ceil(packets[i]['ipd'] / mean_ipd) - 1
                else:
                    packets[i]['possible_loss'] = 0
        if all('seq_num' in pkt for pkt in packets if pkt.get('seq_num') is not None):
            for i in range(1, len(packets)):
                if (packets[i].get('seq_num') is not None and 
                    packets[i-1].get('seq_num') is not None):
                    expected_seq = packets[i-1]['seq_num'] + 1
                    if packets[i]['seq_num'] > expected_seq:
                        packets[i]['seq_loss'] = packets[i]['seq_num'] - expected_seq
        for i in range(len(packets)):
            if 'jitter' in packets[i] and 'possible_loss' in packets[i]:
                jitter_ratio = packets[i]['jitter'] / mean_ipd if mean_ipd > 0 else 0
                packets[i]['congestion_score'] = jitter_ratio * 0.5 + (packets[i]['possible_loss'] / 5) * 0.5
        for i in range(len(packets)):
            packets[i]['mean_ipd'] = mean_ipd
            packets[i]['std_ipd'] = std_ipd
            packets[i]['total_packets'] = len(packets)
        udp_data.extend(packets)
    
    return pd.DataFrame(udp_data)

def calculate_mqtt_metrics(mqtt_connections, mqtt_messages):
    """Calculate MQTT-specific metrics and merge with delay information"""
    if not mqtt_connections:
        return pd.DataFrame()
    
    mqtt_data = []
    for conn_id, packets in mqtt_connections.items():
        packets.sort(key=lambda x: x['timestamp'])
        mqtt_data.extend(packets)
    
    df_mqtt = pd.DataFrame(mqtt_data)
    delay_metrics = extract_mqtt_delays(mqtt_messages)
    if not delay_metrics.empty and not df_mqtt.empty and 'msg_id' in df_mqtt.columns:
        df_mqtt = pd.merge(df_mqtt, delay_metrics, on='msg_id', how='left')
    return df_mqtt
