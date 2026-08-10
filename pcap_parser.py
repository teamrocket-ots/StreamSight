"""PCAP/PCAPNG parsing and per-protocol metric extraction.

Connections are keyed on tshark's **stream index** (``tcp.stream`` / ``udp.stream``),
which is bidirectional. Keying on an endpoint string such as
``"src:sport-dst:dport"`` splits every connection into two half-flows that never
see each other, which makes bidirectional measurements (RTT, ACK delay)
impossible to compute.

All durations are reported in **milliseconds**; absolute timestamps stay in epoch
seconds.
"""

import asyncio
import logging
import sys
from collections import defaultdict

import nest_asyncio
import numpy as np
import pandas as pd
import pyshark

import tshark_backend
from units import SEC_TO_MS

logger = logging.getLogger(__name__)

# Set event loop policy and apply nest_asyncio (always apply to avoid loop issues)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
nest_asyncio.apply()

MQTT_PORT = 1883
MQTT_TLS_PORT = 8883

#: Port 8883 is IANA-registered ``secure-mqtt``, so this traffic is reported as
#: MQTT. The "(encrypted)" qualifier is not cosmetic: the payload is TLS, so
#: message types, message IDs and QoS cannot be read, and the label is a port
#: heuristic rather than a decode.
#:
#: The distinction has to survive into the data because it decides which metrics
#: are honest. Encrypted streams are analysed on the TCP path; feeding them into
#: the message-level delay pipeline is what previously produced "broker
#: processing delays" that were really TLS handshake timings.
PROTO_MQTT_TLS = "MQTT (encrypted)"

#: Protocol labels that ride on TCP, and so belong in a TCP-based denominator.
TCP_PROTOCOLS = frozenset({"TCP", "MQTT", PROTO_MQTT_TLS})

#: tshark expert-analysis fields worth surfacing, mapped to our column names.
#: These are the direct causes of transmission delay and are what makes it
#: possible to distinguish a receiver stall from a network problem.
TCP_HEALTH_FIELDS = {
    "analysis_zero_window": "zero_window",
    "analysis_window_full": "window_full",
    "analysis_duplicate_ack": "duplicate_ack",
    "analysis_out_of_order": "out_of_order",
    "analysis_spurious_retransmission": "spurious_retrans",
}

#: A packet counts as a retransmission if tshark flags it as any of these.
#: They overlap -- tshark flags fast and spurious retransmissions as plain
#: retransmissions too -- so membership must be tested as a set, not summed.
TCP_RETRANS_FIELDS = (
    "analysis_retransmission",
    "analysis_fast_retransmission",
    "analysis_spurious_retransmission",
)

#: UDP flows shorter than this cannot support meaningful jitter or loss
#: statistics. Request/response traffic (DNS, mDNS) sits well below it.
MIN_UDP_SAMPLES = 5

#: Timing-gap loss inference assumes a roughly constant packet rate. Bursty
#: traffic (fragmented video frames arriving back-to-back) drives the median
#: inter-packet delay toward zero, so a single idle gap divided by it yields an
#: absurd count -- observed at 20,137 "lost" packets in a 49-packet capture.
#: A flow is only treated as periodic when its median IPD is a meaningful
#: fraction of its mean.
MIN_IPD_REGULARITY = 0.5

#: Hard ceiling on packets inferred lost from one gap, so a pathological ratio
#: cannot dominate the totals even when the regularity gate lets a flow through.
MAX_INFERRED_LOSS = 100

#: Fraction of packets that must carry a sequence number before it is treated as
#: the authority for loss.
SEQUENCE_COVERAGE = 0.8


def _layer_fields(layer):
    """The set of field names a layer exposes, for cheap repeated presence tests.

    Field presence is tested through this set rather than ``hasattr``: a
    ``hasattr`` miss on a pyshark layer costs roughly 113 microseconds because
    the lookup raises internally, so probing a handful of usually-absent fields
    on every packet adds tens of seconds across a large capture.
    """
    try:
        return set(layer.field_names)
    except Exception:
        return set()


def _layer_names(packet):
    """The set of layer names on a packet (``ip``, ``ipv6``, ``tcp``, ``mqtt``, ...)."""
    try:
        return {layer.layer_name for layer in packet.layers}
    except Exception:
        return set()


def _field(layer, name, cast=None, default=None, fields=None):
    """Read a field off a pyshark layer, returning ``default`` if absent or unparseable.

    Pass ``fields`` (from :func:`_layer_fields`) to skip the expensive lookup
    for fields that are not present.
    """
    if fields is not None and name not in fields:
        return default
    try:
        raw = getattr(layer, name)
    except (AttributeError, KeyError):
        return default
    if raw is None:
        return default
    try:
        return cast(str(raw)) if cast else str(raw)
    except (ValueError, TypeError):
        return default


#: Field values pyshark uses for a set boolean flag. Which one appears depends
#: on the tshark version: older builds render TCP flags as "1", newer ones as
#: "True". Testing only for "1" silently makes every flag read as unset, which
#: disables anything keyed off SYN or ACK.
TRUTHY_FIELD_VALUES = {"1", "true", "True", "TRUE"}


def _layers_named(packet, name):
    """Every layer with the given name.

    A TCP segment carrying several MQTT messages is dissected as several ``mqtt``
    layers. ``packet.mqtt`` returns only the first, silently dropping the rest,
    so the layer list has to be walked instead.
    """
    try:
        return [layer for layer in packet.layers if layer.layer_name == name]
    except Exception:
        return []


def _flag(layer, name, fields=None):
    """Read a TCP flag field as 0/1, tolerating both "1" and "True" encodings."""
    return 1 if _field(layer, name, fields=fields) in TRUTHY_FIELD_VALUES else 0


def _is_retransmission(tcp_fields):
    """True if tshark flagged this packet as any kind of retransmission.

    Tested as set membership rather than a sum: tshark marks fast and spurious
    retransmissions as plain retransmissions as well, so adding the individual
    counts double-counts the same packets.
    """
    return not tcp_fields.isdisjoint(TCP_RETRANS_FIELDS)


def _extract_addresses(packet, layers):
    """Return ``(src_ip, dst_ip, ip_version)``, supporting both IPv4 and IPv6."""
    if "ip" in layers:
        return _field(packet.ip, "src"), _field(packet.ip, "dst"), 4
    if "ipv6" in layers:
        return _field(packet.ipv6, "src"), _field(packet.ipv6, "dst"), 6
    return None, None, None


def _conn_label(src_ip, src_port, dst_ip, dst_port):
    """Human-readable endpoint pair, for display only -- never used as a key."""
    return f"{src_ip}:{src_port} - {dst_ip}:{dst_port}"


def _iter_rows(file_path, backend="auto"):
    """Yield normalised packet rows from the selected reader."""
    if backend not in ("auto", "tshark", "pyshark"):
        raise ValueError(f"unknown backend {backend!r}")

    if backend in ("auto", "tshark"):
        try:
            yield from tshark_backend.iter_rows(file_path)
            return
        except tshark_backend.TSharkUnavailable:
            if backend == "tshark":
                raise
            logger.info("Fast tshark reader unavailable; falling back to PyShark.")

    yield from _iter_rows_pyshark(file_path)


def _iter_rows_pyshark(file_path, display_filter="mqtt or tcp or udp"):
    """Yield normalised packet rows via PyShark.

    Kept as a fallback for environments where tshark cannot be driven directly.
    Slower, because PyShark deserialises every layer of every packet.
    """
    previous_loop = None
    try:
        previous_loop = asyncio.get_event_loop()
    except RuntimeError:
        previous_loop = None

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    cap = None
    try:
        cap = pyshark.FileCapture(
            file_path,
            display_filter=display_filter,
            eventloop=loop,
            keep_packets=False,
        )
        for packet_id, packet in enumerate(cap):
            try:
                yield _row_from_pyshark(packet, packet_id)
            except Exception as exc:
                logger.debug("Skipping packet %s: %s", packet_id, exc)
    finally:
        if cap is not None:
            try:
                cap.close()
            except Exception as exc:
                logger.debug("Error closing capture: %s", exc)
        # Restore whatever loop was installed before, so a second parse in the
        # same session does not inherit a closed loop.
        try:
            loop.close()
        except Exception:
            pass
        if previous_loop is not None and not previous_loop.is_closed():
            asyncio.set_event_loop(previous_loop)
        else:
            asyncio.set_event_loop(asyncio.new_event_loop())


def _row_from_pyshark(packet, packet_id):
    """Normalise a PyShark packet into the shared row shape."""
    layers = _layer_names(packet)
    src_ip, dst_ip, ip_version = _extract_addresses(packet, layers)

    has_tcp = "tcp" in layers
    has_udp = "udp" in layers and not has_tcp
    tcp_fields = _layer_fields(packet.tcp) if has_tcp else set()
    udp_fields = _layer_fields(packet.udp) if has_udp else set()

    if has_tcp:
        src_port = _field(packet.tcp, "srcport", int, fields=tcp_fields)
        dst_port = _field(packet.tcp, "dstport", int, fields=tcp_fields)
    elif has_udp:
        src_port = _field(packet.udp, "srcport", int, fields=udp_fields)
        dst_port = _field(packet.udp, "dstport", int, fields=udp_fields)
    else:
        src_port = dst_port = None

    row = {
        "packet_id": packet_id,
        "timestamp": float(packet.frame_info.time_epoch),
        "layers": layers,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_version": ip_version,
        "src_port": src_port,
        "dst_port": dst_port,
        "has_tcp": has_tcp,
        "has_udp": has_udp,
        "has_mqtt": "mqtt" in layers,
        "tcp_stream": _field(packet.tcp, "stream", fields=tcp_fields) if has_tcp else None,
        "seq_num": (_field(packet.tcp, "seq", int, 0, fields=tcp_fields) if has_tcp else 0),
        "ack_num": (_field(packet.tcp, "ack", int, 0, fields=tcp_fields) if has_tcp else 0),
        "payload_size": (_field(packet.tcp, "len", int, 0, fields=tcp_fields) if has_tcp else 0),
        "flags_syn": _flag(packet.tcp, "flags_syn", tcp_fields) if has_tcp else 0,
        "flags_ack": _flag(packet.tcp, "flags_ack", tcp_fields) if has_tcp else 0,
        "flags_rst": _flag(packet.tcp, "flags_reset", tcp_fields) if has_tcp else 0,
        "flags_fin": _flag(packet.tcp, "flags_fin", tcp_fields) if has_tcp else 0,
        "is_retrans": _is_retransmission(tcp_fields),
        "ack_rtt": (_field(packet.tcp, "analysis_ack_rtt", float, fields=tcp_fields)
                    if has_tcp else None),
        "udp_stream": _field(packet.udp, "stream", fields=udp_fields) if has_udp else None,
        "udp_length": _field(packet.udp, "length", int, fields=udp_fields) if has_udp else None,
        "rtp_seq": _field(packet.rtp, "seq", int) if "rtp" in layers else None,
        "mqtt_types": [],
        "mqtt_ids": [],
        "mqtt_qos": 0,
        "is_tls_handshake": _is_tls_handshake(packet, layers),
    }

    for field, column in TCP_HEALTH_FIELDS.items():
        row[column] = field in tcp_fields

    if row["has_mqtt"]:
        types, ids = [], []
        qos = 0
        for mqtt_layer in _layers_named(packet, "mqtt"):
            mqtt_fields = _layer_fields(mqtt_layer)
            msg_type = _field(mqtt_layer, "msgtype", fields=mqtt_fields)
            if msg_type:
                types.append(msg_type)
            msg_id = _field(mqtt_layer, "msgid", fields=mqtt_fields)
            if msg_id:
                ids.append(msg_id)
            qos = _field(mqtt_layer, "qos", int, qos, fields=mqtt_fields)
        row["mqtt_types"] = types
        row["mqtt_ids"] = ids
        row["mqtt_qos"] = qos

    return row


def parse_pcap(file_path, backend="auto"):
    """
    Parse a .pcap or .pcapng file and extract:
      - df_packets: General packet information (src/dst IP, protocol, timestamps, ports)
      - df_delays: MQTT delay components (Broker Processing, Broker-Client, Cloud, Total)
      - df_retrans: TCP retransmission events
      - df_tcp: TCP-specific metrics (IPD, RTT, ACK delay, jitter, health flags)
      - df_udp: UDP-specific metrics (IPD, jitter, congestion score)
      - df_mqtt: MQTT-specific metrics, for genuinely decoded MQTT only

    Traffic on port 8883 is MQTT over TLS. Its payload is encrypted, so it is
    analysed on the TCP path and labelled ``MQTT (encrypted)`` rather than given
    fabricated message IDs and payload-level delays.

    ``backend`` selects the reader:
      - ``"auto"`` (default): the fast ``tshark -T fields`` reader, falling back
        to PyShark if tshark cannot be driven directly.
      - ``"tshark"``: force the fast reader, raising if it is unavailable.
      - ``"pyshark"``: force the PyShark reader.

    Both produce identical frames; the fast reader avoids generating and parsing
    tshark's full XML output for fields that are never read.
    """
    packet_records = []
    retrans_times = []
    tcp_connections = defaultdict(list)
    udp_connections = defaultdict(list)
    mqtt_messages = {}
    mqtt_connections = defaultdict(list)
    clients = set()
    brokers = set()

    for row in _iter_rows(file_path, backend):
        try:
            timestamp = row["timestamp"]
            src_ip, dst_ip = row["src_ip"], row["dst_ip"]
            src_port, dst_port = row["src_port"], row["dst_port"]
            has_tcp, has_udp = row["has_tcp"], row["has_udp"]

            is_mqtt_tls = has_tcp and MQTT_TLS_PORT in (src_port, dst_port)

            # Resolve the protocol label *before* building packet_info, so
            # records copied from it do not carry a stale value.
            if row["has_mqtt"]:
                protocol = "MQTT"
            elif is_mqtt_tls:
                protocol = PROTO_MQTT_TLS
            elif has_tcp:
                protocol = "TCP"
            elif has_udp:
                protocol = "UDP"
            else:
                protocol = "OTHER"

            packet_info = {
                "packet_id": row["packet_id"],
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ip_version": row["ip_version"],
                "protocol": protocol,
            }

            # --- Genuinely decoded MQTT (unencrypted, typically port 1883) ---
            if row["has_mqtt"]:
                _record_mqtt(
                    row, packet_info, mqtt_messages, mqtt_connections, clients, brokers,
                )

            # --- TCP, including MQTT-over-TLS on 8883 ---
            if has_tcp:
                tcp_info = _build_tcp_record(row, packet_info)
                if tcp_info["is_retrans"]:
                    retrans_times.append(timestamp)
                tcp_connections[tcp_info["conn_id"]].append(tcp_info)

            elif has_udp:
                udp_info = _build_udp_record(row, packet_info)
                udp_connections[udp_info["conn_id"]].append(udp_info)

            packet_records.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "ip_version": row["ip_version"],
                "protocol": protocol,
            })
        except Exception as exc:
            logger.debug("Skipping packet %s: %s", row.get("packet_id"), exc)

    df_packets = pd.DataFrame(packet_records)
    if not df_packets.empty:
        df_packets = df_packets.sort_values("timestamp").reset_index(drop=True)

    df_retrans = pd.DataFrame({
        "time": retrans_times,
        "event": ["TCP Retransmission"] * len(retrans_times),
    })

    logger.info("Detected MQTT clients: %s", clients or "none")
    logger.info("Detected MQTT brokers: %s", brokers or "none")

    df_delays = extract_mqtt_delays(mqtt_messages)
    if df_delays.empty:
        logger.info("No MQTT delays detected.")

    df_tcp = calculate_tcp_metrics(tcp_connections)
    df_udp = calculate_udp_metrics(udp_connections)
    df_mqtt = calculate_mqtt_metrics(mqtt_connections, mqtt_messages)

    df_packets = ensure_dataframe_types(df_packets)
    df_tcp = ensure_dataframe_types(df_tcp)
    df_udp = ensure_dataframe_types(df_udp)
    df_mqtt = ensure_dataframe_types(df_mqtt)
    df_delays = ensure_dataframe_types(df_delays)

    return df_packets, df_delays, df_retrans, df_tcp, df_udp, df_mqtt


#: TLS record content type 22 is "handshake". Everything before the first
#: application-data record is connection setup, not payload.
TLS_HANDSHAKE_CONTENT_TYPE = "22"


def _is_tls_handshake(packet, layers):
    """True if this packet carries a TLS handshake record.

    Only read for packets that actually have a TLS layer, so non-TLS captures
    pay nothing for it.
    """
    if "tls" not in layers:
        return False
    tls_fields = _layer_fields(packet.tls)
    if "handshake_type" in tls_fields:
        return True
    return _field(
        packet.tls, "record_content_type", fields=tls_fields
    ) == TLS_HANDSHAKE_CONTENT_TYPE


def _build_tcp_record(row, packet_info):
    """Build one TCP packet record, keyed on the bidirectional stream index."""
    # tcp.stream is tshark's bidirectional conversation index: both directions of
    # a connection share it. An endpoint string would not.
    stream = row["tcp_stream"]
    conn_id = f"tcp-{stream}" if stream is not None else f"tcp-pkt-{row['packet_id']}"

    # tshark computes RTT per acknowledged segment, which yields far more
    # samples than the handshake alone and needs no reimplementation.
    ack_rtt = row["ack_rtt"]

    record = {
        **packet_info,
        "src_port": row["src_port"],
        "dst_port": row["dst_port"],
        "seq_num": row["seq_num"],
        "ack_num": row["ack_num"],
        "flags_syn": row["flags_syn"],
        "flags_ack": row["flags_ack"],
        "flags_rst": row["flags_rst"],
        "flags_fin": row["flags_fin"],
        # tcp.len is the payload length as tshark computes it. Deriving it from
        # len(packet) - hdr_len omits the IP and Ethernet headers and is wrong.
        "payload_size": row["payload_size"],
        "is_retrans": row["is_retrans"],
        "ack_rtt": ack_rtt * SEC_TO_MS if ack_rtt is not None else np.nan,
        "is_tls_handshake": row["is_tls_handshake"],
        "conn_id": conn_id,
        "conn_label": _conn_label(
            row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"]
        ),
    }

    for column in TCP_HEALTH_FIELDS.values():
        record[column] = row.get(column, False)

    return record


def _build_udp_record(row, packet_info):
    """Build one UDP packet record, keyed on the bidirectional stream index."""
    stream = row["udp_stream"]
    conn_id = f"udp-{stream}" if stream is not None else f"udp-pkt-{row['packet_id']}"

    # udp.length covers the 8-byte UDP header plus payload.
    udp_length = row["udp_length"]
    payload_size = max(udp_length - 8, 0) if udp_length is not None else 0

    return {
        **packet_info,
        "src_port": row["src_port"],
        "dst_port": row["dst_port"],
        "payload_size": payload_size,
        "conn_id": conn_id,
        "conn_label": _conn_label(
            row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"]
        ),
        "is_multicast": _is_multicast(row["dst_ip"]),
        "seq_num": row["rtp_seq"],
    }


def _is_multicast(ip):
    """True for IPv4 224.0.0.0/4 or IPv6 ff00::/8 destinations.

    Multicast has no bidirectional peer, so it cannot be treated as a
    conversation for jitter or RTT purposes.
    """
    if not ip:
        return False
    if ":" in ip:
        return ip.lower().startswith("ff")
    first = ip.split(".")[0]
    return first.isdigit() and 224 <= int(first) <= 239


def _record_mqtt(row, packet_info, mqtt_messages, mqtt_connections, clients, brokers):
    """Record a genuinely decoded MQTT packet.

    A single TCP segment can carry several MQTT messages, in which case tshark
    reports the fields comma-joined (e.g. ``msgtype == "3,14"``). Each message is
    recorded separately rather than the whole frame being dropped.
    """
    packet_id = row["packet_id"]
    try:
        timestamp = row["timestamp"]
        src_ip, dst_ip = row["src_ip"], row["dst_ip"]
        src_port, dst_port = row["src_port"], row["dst_port"]
        stream = row["tcp_stream"]
        has_tcp = row["has_tcp"]

        msg_types = row["mqtt_types"] or [None]
        msg_ids = row["mqtt_ids"]

        for index, msg_type in enumerate(msg_types):
            raw_id = msg_ids[index] if index < len(msg_ids) else None
            msg_id = _mqtt_message_key(stream, raw_id, packet_id, index)

            mqtt_info = {
                **packet_info,
                "protocol": "MQTT",
                "src_port": src_port,
                "dst_port": dst_port,
                "msg_id": msg_id,
                "msg_type": msg_type,
                "msg_type_name": get_mqtt_msg_type(msg_type),
                "conn_id": f"mqtt-{stream}" if has_tcp else f"mqtt-pkt-{packet_id}",
                "conn_label": _conn_label(src_ip, src_port, dst_ip, dst_port),
                "is_retrans": row["is_retrans"],
            }

            if msg_type == "1":  # CONNECT
                if src_ip:
                    clients.add(src_ip)
                if dst_ip:
                    brokers.add(dst_ip)
                mqtt_messages.setdefault(msg_id, {})["connect_time"] = timestamp
                mqtt_info["entity"] = "CLIENT"
            elif msg_type == "2":  # CONNACK
                if src_ip:
                    brokers.add(src_ip)
                mqtt_messages.setdefault(msg_id, {})["connack_time"] = timestamp
                mqtt_info["entity"] = "BROKER"
            elif msg_type == "3":  # PUBLISH
                mqtt_messages.setdefault(msg_id, {})
                if dst_port == MQTT_PORT:
                    mqtt_messages[msg_id]["client_publish_time"] = timestamp
                    mqtt_info["entity"] = "CLIENT"
                elif src_port == MQTT_PORT:
                    mqtt_messages[msg_id]["broker_forward_time"] = timestamp
                    mqtt_info["entity"] = "BROKER"
                else:
                    mqtt_info["entity"] = "UNKNOWN"
            elif msg_type == "4":  # PUBACK
                mqtt_messages.setdefault(msg_id, {})
                if src_port == MQTT_PORT:
                    mqtt_messages[msg_id]["broker_ack_time"] = timestamp
                    mqtt_info["entity"] = "BROKER"
                else:
                    mqtt_messages[msg_id]["cloud_ack_time"] = timestamp
                    mqtt_info["entity"] = "CLOUD"
            else:
                mqtt_info["entity"] = "UNKNOWN"

            mqtt_messages.setdefault(msg_id, {})["qos"] = row["mqtt_qos"]
            mqtt_connections[mqtt_info["conn_id"]].append(mqtt_info)
    except Exception as exc:
        logger.debug("Error processing MQTT packet %s: %s", packet_id, exc)


def _mqtt_message_key(stream, raw_id, packet_id, index):
    """Build a message key that stays distinct for QoS 0 traffic.

    QoS 0 PUBLISH messages carry no ``mqtt.msgid``. Falling back to the string
    ``"None"`` would collapse every QoS-0 message in a capture into one bucket,
    so the frame index is used to keep them apart.
    """
    if raw_id and raw_id != "None":
        return f"{stream}:{raw_id}"
    return f"{stream}:qos0:{packet_id}:{index}"


def ensure_dataframe_types(df):
    """Ensure DataFrame column types are compatible with PyArrow."""
    if df.empty:
        return df

    numeric_cols = {
        'src_port', 'dst_port', 'seq_num', 'ack_num', 'payload_size',
        'ipd', 'jitter', 'retrans_delay', 'rtt', 'ack_rtt', 'handshake_rtt',
        'ack_delay', 'ip_version', 'possible_loss', 'congestion_score',
        'mean_ipd', 'median_ipd', 'std_ipd', 'total_packets',
        'conn_duration', 'conn_bytes', 'conn_throughput_kbps', 'tls_handshake_ms',
        'device_to_broker_delay', 'broker_processing_delay',
        'cloud_upload_delay', 'total_delay',
    }
    bool_cols = {
        'is_retrans', 'flags_syn', 'flags_ack', 'flags_rst', 'flags_fin',
        'is_multicast', 'insufficient_samples', 'is_tls_handshake',
        'loss_not_estimated',
    } | set(TCP_HEALTH_FIELDS.values())
    string_cols = {
        'src_ip', 'dst_ip', 'protocol', 'conn_id', 'conn_label', 'msg_id',
        'msg_type', 'msg_type_name', 'entity',
    }

    for col in df.columns:
        if col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        elif col in bool_cols:
            # Replace missing values before casting: a bare astype(bool) turns
            # NaN into True, which would silently mark packets as retransmissions.
            filled = df[col].where(df[col].notna(), False)
            df[col] = filled.infer_objects(copy=False).astype(bool)
        elif col in string_cols:
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


def extract_mqtt_delays(mqtt_messages):
    """Calculate MQTT delay components from tracked message timestamps.

    Requires a PUBACK to pair with a PUBLISH, which QoS 0 never sends. A capture
    made entirely of QoS-0 traffic therefore yields no rows; the caller is
    expected to explain that rather than showing an empty table.
    """
    delay_records = []
    for msg_id, timestamps in mqtt_messages.items():
        if 'client_publish_time' not in timestamps or 'broker_ack_time' not in timestamps:
            continue

        client_publish_time = timestamps['client_publish_time']
        broker_ack_time = timestamps['broker_ack_time']
        broker_forward_time = timestamps.get('broker_forward_time')
        cloud_ack_time = timestamps.get('cloud_ack_time')

        device_to_broker = broker_ack_time - client_publish_time
        # A broker often forwards before it acks, which makes this negative.
        # Clamping keeps the value out of the "silently dropped by pd.cut" hole
        # while the flag preserves the fact that it happened.
        raw_processing = (broker_forward_time - broker_ack_time) if broker_forward_time else 0.0
        broker_processing = max(raw_processing, 0.0)
        cloud_upload = (
            cloud_ack_time - broker_forward_time
            if (cloud_ack_time and broker_forward_time) else 0.0
        )
        total = (
            cloud_ack_time - client_publish_time
            if cloud_ack_time else device_to_broker + broker_processing
        )

        delay_records.append({
            "msg_id": str(msg_id),
            "device_publish_time": client_publish_time,
            "device_to_broker_delay": device_to_broker * SEC_TO_MS,
            "broker_processing_delay": broker_processing * SEC_TO_MS,
            "cloud_upload_delay": cloud_upload * SEC_TO_MS,
            "total_delay": total * SEC_TO_MS,
            "out_of_order": raw_processing < 0,
            "qos": timestamps.get("qos", 0),
        })

    return pd.DataFrame(delay_records) if delay_records else pd.DataFrame()


def calculate_tcp_metrics(tcp_connections):
    """Calculate TCP metrics: IPD, RTT, ACK delay, jitter and retransmission delay.

    Every metric here is computed within one bidirectional stream, so both
    directions of the conversation are visible to it.
    """
    if not tcp_connections:
        return pd.DataFrame()

    tcp_data = []
    for conn_id, packets in tcp_connections.items():
        packets.sort(key=lambda x: x['timestamp'])

        for i in range(1, len(packets)):
            packets[i]['ipd'] = (packets[i]['timestamp'] - packets[i - 1]['timestamp']) * SEC_TO_MS

        # Retransmission delay: gap from a segment's original transmission to the
        # moment it was resent. Measured per direction, since the two directions
        # have independent sequence spaces.
        #
        # Only packets tshark flagged as retransmissions get a value, and only
        # sequence-consuming packets are tracked as candidate originals. A bare
        # ACK carries no payload and does not advance the sender's sequence
        # number, so every ACK in a flow shares one seq_num; matching on seq_num
        # alone therefore pairs unrelated ACKs and reports the time between them
        # as a retransmission delay -- tens of seconds on a long capture, on
        # captures containing no retransmissions at all.
        first_transmission = {}
        for i, pkt in enumerate(packets):
            key = (pkt.get('src_ip'), pkt.get('src_port'), pkt['seq_num'])
            if pkt['is_retrans']:
                original = first_transmission.get(key)
                if original is not None:
                    packets[i]['retrans_delay'] = (
                        pkt['timestamp'] - packets[original]['timestamp']
                    ) * SEC_TO_MS
            elif pkt['payload_size'] > 0 or pkt['flags_syn'] == 1 or pkt['flags_fin'] == 1:
                first_transmission.setdefault(key, i)

        # Handshake RTT: SYN -> SYN/ACK. Only one per connection, and distinct
        # from the per-ACK RTT that tshark supplies on every acknowledged segment.
        for i, pkt in enumerate(packets):
            if pkt['flags_syn'] == 1 and pkt['flags_ack'] == 0:
                for j in range(i + 1, len(packets)):
                    if packets[j]['flags_syn'] == 1 and packets[j]['flags_ack'] == 1:
                        packets[i]['handshake_rtt'] = (
                            packets[j]['timestamp'] - pkt['timestamp']
                        ) * SEC_TO_MS
                        break

        _compute_ack_delays(packets)

        for i in range(2, len(packets)):
            if 'ipd' in packets[i] and 'ipd' in packets[i - 1]:
                packets[i]['jitter'] = abs(packets[i]['ipd'] - packets[i - 1]['ipd'])

        _annotate_connection_summary(packets)
        tcp_data.extend(packets)

    df_tcp = pd.DataFrame(tcp_data)

    # `rtt` is the headline round-trip metric: tshark's per-ACK measurement where
    # available, falling back to the handshake measurement.
    if not df_tcp.empty:
        ack_rtt = df_tcp['ack_rtt'] if 'ack_rtt' in df_tcp.columns else np.nan
        handshake = df_tcp['handshake_rtt'] if 'handshake_rtt' in df_tcp.columns else np.nan
        if 'ack_rtt' in df_tcp.columns:
            df_tcp['rtt'] = ack_rtt if 'handshake_rtt' not in df_tcp.columns \
                else ack_rtt.fillna(handshake)
        elif 'handshake_rtt' in df_tcp.columns:
            df_tcp['rtt'] = handshake

    if not df_tcp.empty and 'is_retrans' in df_tcp.columns:
        total_packets = len(df_tcp)
        retrans_count = df_tcp['is_retrans'].sum()
        df_tcp['retrans_rate_pct'] = (
            (retrans_count / total_packets) * 100 if total_packets else 0
        )

    return df_tcp


def _annotate_connection_summary(packets):
    """Attach per-connection throughput and TLS handshake duration to each packet.

    These are the metrics that remain meaningful on an encrypted stream, where
    the payload cannot be inspected at all.
    """
    if not packets:
        return

    duration = packets[-1]['timestamp'] - packets[0]['timestamp']
    total_bytes = sum(pkt.get('payload_size') or 0 for pkt in packets)
    throughput = (total_bytes * 8 / duration / 1000) if duration > 0 else np.nan

    handshake_times = [
        pkt['timestamp'] for pkt in packets if pkt.get('is_tls_handshake')
    ]
    # Time from the first handshake record to the last: how long connection
    # setup cost before any application data could flow.
    handshake_ms = (
        (handshake_times[-1] - handshake_times[0]) * SEC_TO_MS
        if len(handshake_times) >= 2 else np.nan
    )

    for pkt in packets:
        pkt['conn_duration'] = duration
        pkt['conn_bytes'] = total_bytes
        pkt['conn_throughput_kbps'] = throughput
        pkt['tls_handshake_ms'] = handshake_ms


def _compute_ack_delays(packets):
    """Time from a data segment being sent to the peer acknowledging it.

    Matches cumulatively (``ack_num >= seq_num + payload_size``) rather than on
    exact equality, because one ACK routinely covers several segments once TCP
    reassembly is in play.
    """
    # Oldest unacknowledged data segment per direction.
    pending = defaultdict(list)

    for pkt in packets:
        direction = (pkt.get('src_ip'), pkt.get('src_port'))
        reverse = (pkt.get('dst_ip'), pkt.get('dst_port'))

        if pkt['payload_size'] > 0 and not pkt.get('is_retrans'):
            pending[direction].append(pkt)

        if pkt['flags_ack'] == 1:
            waiting = pending.get(reverse)
            if not waiting:
                continue
            still_waiting = []
            for sent in waiting:
                if pkt['ack_num'] >= sent['seq_num'] + sent['payload_size']:
                    sent.setdefault(
                        'ack_delay',
                        (pkt['timestamp'] - sent['timestamp']) * SEC_TO_MS,
                    )
                else:
                    still_waiting.append(sent)
            pending[reverse] = still_waiting


def calculate_udp_metrics(udp_connections):
    """Calculate UDP metrics: IPD, RFC 3550 jitter, loss estimate and congestion.

    Flows shorter than :data:`MIN_UDP_SAMPLES` are flagged rather than measured.
    A two-packet DNS exchange cannot support a jitter or loss estimate, and
    computing one anyway produces confident-looking noise.
    """
    if not udp_connections:
        return pd.DataFrame()

    udp_data = []
    for conn_id, packets in udp_connections.items():
        packets.sort(key=lambda x: x['timestamp'])

        for i in range(1, len(packets)):
            packets[i]['ipd'] = (packets[i]['timestamp'] - packets[i - 1]['timestamp']) * SEC_TO_MS

        ipds = [pkt['ipd'] for pkt in packets if 'ipd' in pkt]
        sufficient = len(packets) >= MIN_UDP_SAMPLES and len(ipds) >= 2

        mean_ipd = float(np.mean(ipds)) if ipds else np.nan
        # The median is the baseline for loss detection: the mean is inflated by
        # the very gaps the heuristic is trying to find.
        median_ipd = float(np.median(ipds)) if ipds else np.nan
        std_ipd = float(np.std(ipds)) if ipds else np.nan

        if sufficient:
            _compute_udp_jitter_and_loss(packets, mean_ipd, std_ipd, median_ipd)

        for pkt in packets:
            pkt['mean_ipd'] = mean_ipd if sufficient else np.nan
            pkt['median_ipd'] = median_ipd if sufficient else np.nan
            pkt['std_ipd'] = std_ipd if sufficient else np.nan
            pkt['total_packets'] = len(packets)
            pkt['insufficient_samples'] = not sufficient

        udp_data.extend(packets)

    return pd.DataFrame(udp_data)


def _compute_udp_jitter_and_loss(packets, mean_ipd, std_ipd, median_ipd):
    """RFC 3550 jitter plus loss estimation.

    Loss comes from sequence numbers when the flow carries them, because that is
    an observation rather than an inference. The timing-gap heuristic is only a
    fallback, and only for flows regular enough for it to mean anything.
    """
    # RFC 3550: J starts at 0 and converges via J += (|D| - J)/16.
    prev_jitter = 0.0
    for i in range(2, len(packets)):
        if 'ipd' not in packets[i] or 'ipd' not in packets[i - 1]:
            continue
        delta = abs(packets[i]['ipd'] - packets[i - 1]['ipd'])
        prev_jitter = prev_jitter + (delta - prev_jitter) / 16
        packets[i]['jitter'] = prev_jitter

    sequenced = sum(1 for pkt in packets if pkt.get('seq_num') is not None)
    has_sequence = sequenced >= len(packets) * SEQUENCE_COVERAGE

    if has_sequence:
        _sequence_loss(packets)
    else:
        _timing_gap_loss(packets, mean_ipd, std_ipd, median_ipd)

    for pkt in packets:
        if 'jitter' in pkt and 'possible_loss' in pkt and mean_ipd and mean_ipd > 0:
            jitter_ratio = pkt['jitter'] / mean_ipd
            score = jitter_ratio * 0.5 + min(pkt['possible_loss'] / 5, 1.0) * 0.5
            pkt['congestion_score'] = min(score, 1.0)


def _sequence_loss(packets):
    """Loss observed directly from sequence numbers.

    Wraparound-aware: RTP sequence numbers are 16-bit, so a counter rolling over
    at 65535 is not a 65,000-packet loss.
    """
    for i in range(1, len(packets)):
        packets[i].setdefault('possible_loss', 0)
        current = packets[i].get('seq_num')
        previous = packets[i - 1].get('seq_num')
        if current is None or previous is None:
            continue
        gap = (current - previous - 1) % 65536
        # A very large gap means reordering or a different talker, not loss.
        if 0 < gap < 1000:
            packets[i]['seq_loss'] = gap
            packets[i]['possible_loss'] = gap


def _timing_gap_loss(packets, mean_ipd, std_ipd, median_ipd):
    """Loss inferred from idle gaps, for flows with no sequence numbers.

    Requires a roughly constant packet rate: dividing a gap by a near-zero
    median IPD otherwise produces counts far larger than the capture itself.
    """
    regular = (
        median_ipd and median_ipd > 0
        and mean_ipd and mean_ipd > 0
        and (median_ipd / mean_ipd) >= MIN_IPD_REGULARITY
    )
    if not regular:
        for pkt in packets:
            pkt['possible_loss'] = 0
            pkt['loss_not_estimated'] = True
        return

    threshold = mean_ipd + 3 * std_ipd
    for i in range(2, len(packets)):
        if 'ipd' not in packets[i]:
            continue
        if packets[i]['ipd'] > threshold:
            inferred = np.ceil(packets[i]['ipd'] / median_ipd) - 1
            packets[i]['possible_loss'] = float(
                min(max(inferred, 0), MAX_INFERRED_LOSS)
            )
        else:
            packets[i]['possible_loss'] = 0


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
        df_mqtt['msg_id'] = df_mqtt['msg_id'].astype(str)
        delay_metrics['msg_id'] = delay_metrics['msg_id'].astype(str)
        df_mqtt = pd.merge(df_mqtt, delay_metrics, on='msg_id', how='left')

    return df_mqtt
