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
                              eventloop=loop)
    
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
                src_ip = str(packet.ip.src)
                dst_ip = str(packet.ip.dst)
            else:
                src_ip, dst_ip = None, None

            # Get TCP/UDP ports with proper type conversion
            src_port, dst_port = None, None
            if hasattr(packet, 'tcp'):
                try:
                    # Explicitly convert to string first, then to int
                    src_port = int(str(packet.tcp.srcport)) if hasattr(packet.tcp, 'srcport') else None
                    dst_port = int(str(packet.tcp.dstport)) if hasattr(packet.tcp, 'dstport') else None
                except (ValueError, TypeError):
                    src_port, dst_port = None, None
            elif hasattr(packet, 'udp'):
                try:
                    # Explicitly convert to string first, then to int
                    src_port = int(str(packet.udp.srcport)) if hasattr(packet.udp, 'srcport') else None
                    dst_port = int(str(packet.udp.dstport)) if hasattr(packet.udp, 'dstport') else None
                except (ValueError, TypeError):
                    src_port, dst_port = None, None
            
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
                    # Safely convert message ID
                    try:
                        msg_id = str(getattr(packet.mqtt, 'msgid', None))
                    except:
                        msg_id = f"mqtt_{packet_id}"
                    
                    # Safely convert message type
                    try:
                        msg_type = str(getattr(packet.mqtt, 'msgtype', None))
                    except:
                        msg_type = None
                    
                    # Map message type using helper
                    msg_type_name = get_mqtt_msg_type(msg_type)
                    
                    # Build a MQTT info record to be used in mqtt_connections
                    mqtt_info = {
                        **packet_info,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'msg_id': msg_id,
                        'msg_type': msg_type,
                        'msg_type_name': msg_type_name,
                        'conn_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}" if src_ip and dst_ip and src_port and dst_port else f"mqtt_{packet_id}"
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
                        if dst_port == 1883:
                            mqtt_messages[msg_id]['client_publish_time'] = timestamp
                            mqtt_info['entity'] = 'CLIENT'
                        elif src_port == 1883:
                            mqtt_messages[msg_id]['broker_forward_time'] = timestamp
                            mqtt_info['entity'] = 'BROKER'
                    elif msg_type == '4':  # PUBACK
                        mqtt_messages.setdefault(msg_id, {})
                        if src_port == 1883:
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
            elif hasattr(packet, 'tcp') and (src_port == 8883 or dst_port == 8883):
                protocol = "MQTT"
                
                # Get TCP stream ID as message identifier
                try:
                    msg_id = str(packet.tcp.stream)
                except AttributeError:
                    msg_id = f'8883_{timestamp}'  # Fallback ID
                
                mqtt_messages.setdefault(msg_id, {})
                
                # Identify broker/client based on port direction
                if src_port == 8883:
                    broker_ip = src_ip
                    client_ip = dst_ip
                else:
                    broker_ip = dst_ip
                    client_ip = src_ip
                
                # Track broker/client IPs
                brokers.add(broker_ip)
                clients.add(client_ip)
                
                # Calculate message timing metrics
                if dst_port == 8883:  # Client -> Broker
                    if 'client_publish_time' not in mqtt_messages[msg_id]:
                        mqtt_messages[msg_id]['client_publish_time'] = timestamp
                    else:
                        mqtt_messages[msg_id]['broker_forward_time'] = timestamp
                else:  # Broker -> Client
                    if 'broker_ack_time' not in mqtt_messages[msg_id]:
                        mqtt_messages[msg_id]['broker_ack_time'] = timestamp
                    else:
                        mqtt_messages[msg_id]['cloud_ack_time'] = timestamp
                
                # Determine entity role
                entity = 'BROKER' if src_ip == broker_ip else 'CLIENT'
                
                # Build connection info
                mqtt_info = {
                    **packet_info,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'msg_id': msg_id,
                    'msg_type': None, 
                    'msg_type_name': "UNKNOWN",#, Could parse actual MQTT control packet type here
                    'conn_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
                    'entity': entity,
                    'is_retrans': False
                }
                
                mqtt_connections[mqtt_info['conn_id']].append(mqtt_info)
                
                # Detect retransmissions
                if hasattr(packet.tcp, 'analysis_retransmission'):
                    mqtt_info['is_retrans'] = True
                    retrans_times.append(timestamp)
                
                
            # Process plain TCP packets (excluding the 8883 MQTT branch)
            elif hasattr(packet, 'tcp'):
                protocol = "TCP"
                conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}" if src_ip and dst_ip and src_port and dst_port else f"tcp_{packet_id}"
                
                # Safely convert sequence and acknowledgment numbers
                try:
                    seq_num = int(str(packet.tcp.seq)) if hasattr(packet.tcp, 'seq') else 0
                except (ValueError, TypeError):
                    seq_num = 0
                    
                try:
                    ack_num = int(str(packet.tcp.ack)) if hasattr(packet.tcp, 'ack') else 0
                except (ValueError, TypeError):
                    ack_num = 0
                
                # Safely extract TCP flags
                flags_syn = 1 if hasattr(packet.tcp, 'flags_syn') and str(packet.tcp.flags_syn) == '1' else 0
                flags_ack = 1 if hasattr(packet.tcp, 'flags_ack') and str(packet.tcp.flags_ack) == '1' else 0
                flags_rst = 1 if hasattr(packet.tcp, 'flags_reset') and str(packet.tcp.flags_reset) == '1' else 0
                flags_fin = 1 if hasattr(packet.tcp, 'flags_fin') and str(packet.tcp.flags_fin) == '1' else 0
                
                # Safely calculate payload size
                try:
                    hdr_len = int(str(packet.tcp.hdr_len)) if hasattr(packet.tcp, 'hdr_len') else 0
                    payload_size = len(packet) - hdr_len if hdr_len > 0 else 0
                except (ValueError, TypeError):
                    payload_size = 0
                
                is_retrans = False
                if hasattr(packet.tcp, 'analysis_retransmission') or hasattr(packet.tcp, 'analysis_fast_retransmission'):
                    print("Retransmission detected")
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
                
                # print("TCP packet fields:", dir(packet.tcp)) 

                is_retrans = False
                if hasattr(packet.tcp, 'analysis_retransmission') or hasattr(packet.tcp, 'analysis_fast_retransmission'):
                    print("Retransmission detected")
                    retrans_times.append(timestamp)
                    is_retrans = True

                tcp_info['is_retrans'] = is_retrans
                
            # Process UDP packets
            elif hasattr(packet, 'udp'):
                protocol = "UDP"
                conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}" if src_ip and dst_ip and src_port and dst_port else f"udp_{packet_id}"
                
                # Safely calculate payload size
                try:
                    payload_size = len(packet) if hasattr(packet, 'udp') else 0
                except:
                    payload_size = 0
                    
                udp_info = {
                    **packet_info,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'payload_size': payload_size,
                    'conn_id': conn_id
                }
                
                if hasattr(packet, 'rtp'):
                    try:
                        udp_info['seq_num'] = int(str(packet.rtp.seq)) if hasattr(packet.rtp, 'seq') else None
                    except (ValueError, TypeError):
                        udp_info['seq_num'] = None
                        
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
   ## else:
    ##   print("MQTT Delay Summary:")
    ##    print(df_delays.head())
    
    # Calculate protocol-specific metrics
    df_tcp = calculate_tcp_metrics(tcp_connections)
    df_udp = calculate_udp_metrics(udp_connections)
    df_mqtt = calculate_mqtt_metrics(mqtt_connections, mqtt_messages)
    
    # Ensure all numeric columns are properly typed for PyArrow compatibility
    df_packets = ensure_dataframe_types(df_packets)
    df_tcp = ensure_dataframe_types(df_tcp)
    df_udp = ensure_dataframe_types(df_udp)
    df_mqtt = ensure_dataframe_types(df_mqtt)
    df_delays = ensure_dataframe_types(df_delays)
    
    return df_packets, df_delays, df_retrans, df_tcp, df_udp, df_mqtt

def ensure_dataframe_types(df):
    """Ensure DataFrame column types are compatible with PyArrow"""
    if df.empty:
        return df
        
    # Define columns that should be numeric
    numeric_cols = ['src_port', 'dst_port', 'seq_num', 'ack_num', 'payload_size', 
                   'ipd', 'jitter', 'retrans_delay', 'rtt', 'ack_delay',
                   'device_to_broker_delay', 'broker_processing_delay', 
                   'cloud_upload_delay', 'total_delay']
    
    # Convert columns to appropriate types
    for col in df.columns:
        if col in numeric_cols and col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            
        # Handle boolean columns
        elif col in ['is_retrans', 'flags_syn', 'flags_ack', 'flags_rst', 'flags_fin'] and col in df.columns:
            df[col] = df[col].astype(bool)
            
        # Ensure string columns are actually strings
        elif col in ['src_ip', 'dst_ip', 'protocol', 'conn_id', 'msg_id', 'msg_type', 
                    'msg_type_name', 'entity'] and col in df.columns:
            df[col] = df[col].astype(str)
    
    return df

def get_mqtt_msg_type(type_code):
    """Map MQTT message type codes to names"""
    if type_code is None:
        return "UNKNOWN"
        
    mqtt_types = {
        '1': "CONNECT", '2': "CONNACK", '3': "PUBLISH", '4': "PUBACK",
        '5': "PUBREC", '6': "PUBREL", '7': "PUBCOMP", '8': "SUBSCRIBE",
        '9': "SUBACK", '10': "UNSUBSCRIBE", '11': "UNSUBACK",
        '12': "PINGREQ", '13': "PINGRESP", '14': "DISCONNECT"
    }
    return mqtt_types.get(str(type_code), "UNKNOWN")

def is_external_ip(ip):
    """Determine if an IP is likely external/cloud service"""
    if ip is None:
        return False
        
    try:
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
    except Exception:
        return False

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
                "msg_id": str(msg_id),
                "device_publish_time": client_publish_time,
                "device_to_broker_delay": broker_ack_time - client_publish_time,
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
    if not df_tcp.empty and 'is_retrans' in df_tcp.columns:
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
        ipds = [pkt.get('ipd', 0) for pkt in packets if 'ipd' in pkt]
        mean_ipd = np.mean(ipds) if ipds else 0
        std_ipd = np.std(ipds) if ipds else 0
        for i in range(2, len(packets)):
            if 'ipd' in packets[i] and 'ipd' in packets[i-1]:
                packets[i]['jitter'] = abs(packets[i]['ipd'] - packets[i-1]['ipd'])
                ipd_threshold = mean_ipd + 3 * std_ipd
                if packets[i]['ipd'] > ipd_threshold:
                    packets[i]['possible_loss'] = np.ceil(packets[i]['ipd'] / mean_ipd) - 1 if mean_ipd > 0 else 0
                else:
                    packets[i]['possible_loss'] = 0
        
        # Check for sequence numbers
        has_seq_nums = all(pkt.get('seq_num') is not None for pkt in packets)
        if has_seq_nums:
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
        # Ensure msg_id is string type in both DataFrames before merging
        df_mqtt['msg_id'] = df_mqtt['msg_id'].astype(str)
        delay_metrics['msg_id'] = delay_metrics['msg_id'].astype(str)
        df_mqtt = pd.merge(df_mqtt, delay_metrics, on='msg_id', how='left')
    
    return df_mqtt