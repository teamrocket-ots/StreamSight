"""Cross-protocol analysis helpers: categorisation, anomaly detection and root cause.

All delay values arriving here are already in milliseconds (see :mod:`units`).
"""

import numpy as np
import pandas as pd

from pcap_parser import TCP_PROTOCOLS
from rootcause_analysis import RootCauseAnalysis

DELAY_CATEGORIES = ["Low", "Normal", "High", "Very High"]

MQTT_DELAY_TYPES = [
    "device_to_broker_delay",
    "broker_processing_delay",
    "cloud_upload_delay",
    "total_delay",
]

def safe_cut(series, labels=DELAY_CATEGORIES):
    """Bucket a numeric series into ordered categories without ever raising.

    ``pd.cut`` with mean/std-derived edges is fragile on real network data:
    a right-skewed distribution (the normal shape for delay) drives
    ``mean - 0.5*std`` negative and the edges stop increasing, raising
    ``ValueError: bins must increase monotonically``. Uniform data collapses the
    edges to a single value and raises ``Bin edges must be unique``.

    Quantile edges are used instead: they are monotonic by construction and
    adapt to skew. Degenerate input yields an all-NaN categorical rather than an
    exception, so a tab renders empty instead of dying.
    """
    values = pd.to_numeric(series, errors="coerce")
    empty = pd.Series(np.nan, index=series.index, dtype="object")

    valid = values.dropna()
    if valid.empty or valid.nunique() < 2:
        return empty

    try:
        quantiles = np.linspace(0, 1, len(labels) + 1)
        edges = np.unique(np.nanquantile(valid, quantiles))
        if len(edges) < 2:
            return empty
        # One fewer label than edge, and the labels must stay in order.
        applied = labels[: len(edges) - 1]
        return pd.cut(
            values,
            bins=edges,
            labels=applied,
            include_lowest=True,
            duplicates="drop",
        )
    except (ValueError, TypeError):
        return empty


def tcp_packet_count(df_packets):
    """Number of packets carried over TCP, the correct denominator for retransmissions."""
    if df_packets.empty or "protocol" not in df_packets.columns:
        return 0
    return int(df_packets["protocol"].isin(TCP_PROTOCOLS).sum())


def compute_retransmission_rate(df_packets, df_retrans):
    """Retransmitted TCP packets as a percentage of TCP packets.

    Retransmission is a *proxy* for loss, not a measurement of it, and the
    denominator is TCP traffic only -- dividing by every packet in the capture
    (including UDP) understates the rate and disagrees with the TCP tab.
    """
    total_tcp = tcp_packet_count(df_packets)
    if not total_tcp:
        return 0.0
    return (len(df_retrans) / total_tcp) * 100.0


def detect_anomalies_in_delays(df_delays):
    """Flag per-component delay anomalies using component-specific thresholds."""
    thresholds = {}
    if df_delays.empty:
        return df_delays, thresholds

    multipliers = {
        "device_to_broker_delay": 2.0,   # local network, tighter bound
        "broker_processing_delay": 2.5,
        "cloud_upload_delay": 3.0,       # inherently more variable
        "total_delay": 2.0,
    }

    anomaly_cols = []
    for col in MQTT_DELAY_TYPES:
        if col not in df_delays.columns:
            continue
        mean_val = df_delays[col].mean()
        std_val = df_delays[col].std()
        if pd.isna(mean_val) or pd.isna(std_val):
            continue
        cutoff = mean_val + multipliers[col] * std_val
        thresholds[col] = cutoff
        df_delays[f"{col}_anomaly"] = df_delays[col] > cutoff
        anomaly_cols.append(f"{col}_anomaly")

    df_delays["is_anomaly"] = (
        df_delays[anomaly_cols].any(axis=1) if anomaly_cols else False
    )
    return df_delays, thresholds


def categorize_delays(df_delays):
    """Categorise delay components and identify the dominant contributor."""
    if df_delays.empty:
        return df_delays

    components = ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]
    for delay_type in components:
        if delay_type in df_delays.columns:
            df_delays[f"{delay_type}_category"] = safe_cut(df_delays[delay_type])

    present = [c for c in components if c in df_delays.columns]
    if present:
        labels = {
            "device_to_broker_delay": "Device→Broker",
            "broker_processing_delay": "Broker Processing",
            "cloud_upload_delay": "Cloud Upload",
        }
        # idxmax over the component columns is both faster and NaN-safe compared
        # with a row-wise max over a dict.
        df_delays["bottleneck"] = df_delays[present].idxmax(axis=1).map(labels)

    return df_delays


def analyze_tcp_delays(df_tcp):
    """Summarise TCP delay metrics per connection and flag anomalies.

    Always returns ``(df, conn_stats)`` -- returning a bare DataFrame on the
    empty branch made every caller's tuple-unpacking a latent crash.
    """
    if df_tcp.empty:
        return df_tcp, {}

    metrics = ["ipd", "rtt", "ack_delay", "jitter", "retrans_delay", "handshake_rtt"]
    available = [m for m in metrics if m in df_tcp.columns]

    conn_stats = {}
    if "conn_id" in df_tcp.columns and available:
        grouped = df_tcp.groupby("conn_id")[available].agg(["mean", "max", "std", "count"])
        for conn_id, row in grouped.iterrows():
            stats = {f"{metric}_{stat}": row[(metric, stat)]
                     for metric in available for stat in ("mean", "max", "std", "count")}
            if "is_retrans" in df_tcp.columns:
                stats["retrans_count"] = int(
                    df_tcp.loc[df_tcp["conn_id"] == conn_id, "is_retrans"].sum()
                )
            conn_stats[conn_id] = stats

    for col in available:
        mean_val = df_tcp[col].mean()
        std_val = df_tcp[col].std()
        if pd.isna(mean_val) or pd.isna(std_val):
            continue
        df_tcp[f"{col}_anomaly"] = df_tcp[col] > (mean_val + 2 * std_val)

    if "rtt" in df_tcp.columns:
        df_tcp["rtt_category"] = safe_cut(df_tcp["rtt"])

    return df_tcp, conn_stats


def analyze_udp_delays(df_udp):
    """Summarise UDP metrics per connection. Always returns ``(df, conn_stats)``."""
    if df_udp.empty:
        return df_udp, {}

    conn_stats = {}
    for conn_id in df_udp["conn_id"].unique():
        conn_data = df_udp[df_udp["conn_id"] == conn_id]
        stats = {"total_packets": len(conn_data)}

        # Flows too short to measure are reported as such rather than being
        # given a fabricated jitter or loss figure.
        if "insufficient_samples" in conn_data.columns:
            stats["insufficient_samples"] = bool(conn_data["insufficient_samples"].all())
        if "is_multicast" in conn_data.columns:
            stats["is_multicast"] = bool(conn_data["is_multicast"].any())

        for col, prefix in (("ipd", "ipd"), ("jitter", "jitter"),
                            ("congestion_score", "congestion_score")):
            if col in conn_data.columns:
                data = conn_data[col].dropna()
                stats[f"{prefix}_mean"] = data.mean() if not data.empty else np.nan
                stats[f"{prefix}_max"] = data.max() if not data.empty else np.nan

        if "possible_loss" in conn_data.columns:
            loss = conn_data["possible_loss"].fillna(0).sum()
            stats["possible_loss_sum"] = loss
            denominator = len(conn_data) + loss
            stats["packet_loss_pct"] = (loss / denominator * 100) if denominator else 0.0

        conn_stats[conn_id] = stats

    if "jitter" in df_udp.columns:
        df_udp["jitter_category"] = safe_cut(df_udp["jitter"], ["Low", "Medium", "High"])

    if "congestion_score" in df_udp.columns:
        df_udp["congestion_level"] = safe_cut(df_udp["congestion_score"])

    return df_udp, conn_stats


def analyze_mqtt_delays(df_mqtt):
    """Summarise MQTT entities, message types and delay components."""
    if df_mqtt.empty:
        return df_mqtt, {}

    entity_counts = (
        df_mqtt.groupby("entity").size().to_dict() if "entity" in df_mqtt.columns else {}
    )
    msg_type_stats = (
        df_mqtt.groupby("msg_type_name").size().to_dict()
        if "msg_type_name" in df_mqtt.columns else {}
    )

    detected_clients, detected_brokers = set(), set()
    if "entity" in df_mqtt.columns and "src_ip" in df_mqtt.columns:
        detected_clients = set(df_mqtt.loc[df_mqtt["entity"] == "CLIENT", "src_ip"].unique())
        detected_brokers = set(df_mqtt.loc[df_mqtt["entity"] == "BROKER", "src_ip"].unique())

    for delay_type in MQTT_DELAY_TYPES:
        if delay_type in df_mqtt.columns:
            df_mqtt[f"{delay_type}_category"] = safe_cut(df_mqtt[delay_type])

    components = ["device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"]
    present = [c for c in components if c in df_mqtt.columns]
    if present:
        labels = {
            "device_to_broker_delay": "Device→Broker",
            "broker_processing_delay": "Broker Processing",
            "cloud_upload_delay": "Cloud Upload",
        }
        df_mqtt["bottleneck"] = df_mqtt[present].idxmax(axis=1).map(labels)

    stats = {
        "entity_counts": entity_counts,
        "msg_type_stats": msg_type_stats,
        "detected_clients": list(detected_clients),
        "detected_brokers": list(detected_brokers),
        "total_clients": len(detected_clients),
        "total_brokers": len(detected_brokers),
        "total_messages": int(df_mqtt["msg_id"].nunique()) if "msg_id" in df_mqtt.columns else 0,
        "measurable_delays": int(df_mqtt["total_delay"].notna().sum())
        if "total_delay" in df_mqtt.columns else 0,
    }

    for delay_type in MQTT_DELAY_TYPES:
        if delay_type in df_mqtt.columns:
            stats[f"{delay_type}_mean"] = df_mqtt[delay_type].mean()
            stats[f"{delay_type}_median"] = df_mqtt[delay_type].median()
            stats[f"{delay_type}_max"] = df_mqtt[delay_type].max()
            stats[f"{delay_type}_std"] = df_mqtt[delay_type].std()

    return df_mqtt, stats


#: Metrics analysed for root cause, each on its own terms.
#: (label, frame key, column, what it measures)
ROOT_CAUSE_SOURCES = [
    (
        "TCP ACK Delay", "tcp", "ack_delay",
        "Time from sending a data segment to the peer acknowledging it.",
    ),
    (
        "UDP Inter-Packet Delay", "udp", "ipd",
        "Gap between consecutive packets on a flow. This is a sending *cadence*, "
        "not a latency — a large value usually means the source simply had nothing "
        "to send.",
    ),
    (
        "MQTT End-to-End Delay", "delays", "total_delay",
        "Client publish through to the final acknowledgement.",
    ),
]


def perform_root_cause_analysis(df_tcp=None, df_udp=None, df_delays=None):
    """Correlate each delay metric against the packet it was measured on.

    Returns one :class:`RootCauseAnalysis` per metric. Metrics are deliberately
    **not** pooled: TCP acknowledgement delay and UDP inter-packet delay are
    different quantities, and averaging them together produces figures like a
    "10,180 ms delay" for a multicast group that is really just mDNS
    announcements spaced ten seconds apart.
    """
    frames = {
        "tcp": df_tcp if df_tcp is not None else pd.DataFrame(),
        "udp": df_udp if df_udp is not None else pd.DataFrame(),
        "delays": df_delays if df_delays is not None else pd.DataFrame(),
    }

    analyses = []
    for label, key, column, description in ROOT_CAUSE_SOURCES:
        df = frames[key]
        if df.empty or column not in df.columns:
            continue
        subset = df.loc[df[column].notna(), :]
        if subset.empty:
            continue

        # TCP uses ack_delay, not rtt: tshark attaches ack_rtt to the
        # *acknowledgement*, which carries no payload, so every rtt row has
        # payload_size 0 and correlating it against size yields one empty bucket.
        observations = pd.DataFrame({
            "delay": subset[column].astype(float),
            "packet_size": subset.get("payload_size", pd.Series(0, index=subset.index)),
            "protocol": subset.get("protocol", pd.Series("UNKNOWN", index=subset.index)),
            "source_ip": subset.get("src_ip", pd.Series("unknown", index=subset.index)),
            "destination_ip": subset.get("dst_ip", pd.Series("unknown", index=subset.index)),
            "is_retrans": subset.get("is_retrans", pd.Series(False, index=subset.index)),
            # A zero-window event is a receiver-side stall, so it is one of the
            # few factors that can *explain* a delay rather than merely accompany it.
            "zero_window": subset.get("zero_window", pd.Series(False, index=subset.index)),
        })
        analyses.append(RootCauseAnalysis(observations, metric=label, description=description))

    return analyses


def root_cause_report(analyses):
    """Plain-text report across every analysed metric, for download."""
    if not analyses:
        return (
            "=== Root Cause Analysis ===\n"
            "No delay measurements available to analyse.\n\n"
            "Delay needs a completed round trip: an acknowledged TCP segment, a "
            "multi-packet UDP flow, or an MQTT PUBLISH paired with its PUBACK."
        )
    return "\n\n".join(analysis.generate_report() for analysis in analyses)
