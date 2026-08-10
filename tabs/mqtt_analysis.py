import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from analysis import analyze_mqtt_delays
from tabs.delay_analysis import show_delay_analysis_tab
from tabs.insights import show_insights_tab
from visualizations import (
    delay_over_time,
    format_ms,
    hist_with_boundaries,
    mqtt_delay_components,
)

CATEGORY_COLOURS = {
    "Low": "green",
    "Normal": "blue",
    "High": "orange",
    "Very High": "red",
}

COMM_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "msg_type_name",
    "device_to_broker_delay", "broker_processing_delay",
]


def show_mqtt_analysis_tab(df_mqtt, df_delays=None):
    """MQTT analysis for genuinely decoded (unencrypted) MQTT traffic."""
    st.header("MQTT")

    if df_mqtt is None or df_mqtt.empty:
        st.warning("No decoded MQTT data in this capture.")
        st.caption(
            "MQTT carried over TLS (port 8883) is encrypted, so message types and "
            "IDs cannot be read. That traffic is counted as **MQTT (encrypted)** and "
            "analysed on the **TCP** tab, where transport-level metrics still apply."
        )
        return

    df_mqtt, stats = analyze_mqtt_delays(df_mqtt.copy())

    _show_overview(df_mqtt, stats)

    mqtt_tabs = st.tabs([
        "Delay Components",
        "Client-Broker",
        "Broker Processing",
        "Topology",
        "Delay Breakdown",
        "Insights",
    ])

    with mqtt_tabs[0]:
        _show_components(df_mqtt)
    with mqtt_tabs[1]:
        _show_delay(df_mqtt, "device_to_broker_delay", "Client-Broker Delay", "blue")
    with mqtt_tabs[2]:
        _show_delay(df_mqtt, "broker_processing_delay", "Broker Processing Delay", "green")
    with mqtt_tabs[3]:
        _show_topology(df_mqtt, stats)
    with mqtt_tabs[4]:
        show_delay_analysis_tab(df_delays)
    with mqtt_tabs[5]:
        show_insights_tab(df_delays)


def _show_overview(df_mqtt, stats):
    st.subheader("MQTT Performance Overview")
    col1, col2, col3 = st.columns(3)

    for col, column, label in (
        (col1, "device_to_broker_delay", "Avg Device→Broker Delay"),
        (col2, "broker_processing_delay", "Avg Broker Processing Delay"),
    ):
        if column in df_mqtt.columns and df_mqtt[column].notna().any():
            col.metric(label, format_ms(df_mqtt[column].dropna().mean()))
        else:
            col.metric(label, "N/A")

    col3.metric("Brokers", f"{stats.get('total_brokers', 0)}")
    col3.metric("Clients", f"{stats.get('total_clients', 0)}")

    # Explain an empty delay table rather than leaving it silently blank.
    total_messages = stats.get("total_messages", 0)
    measurable = stats.get("measurable_delays", 0)
    if total_messages and not measurable:
        st.info(
            f"{total_messages} MQTT messages seen, but **0 have a measurable delay**.\n\n"
            "Delay components pair a PUBLISH with its PUBACK. QoS 0 — the default, and "
            "what this capture uses — sends no PUBACK, so no end-to-end delay can be "
            "derived. Capture QoS 1 traffic to populate these metrics."
        )


def _show_components(df_mqtt):
    st.subheader("MQTT Delay Component Analysis")
    st.plotly_chart(mqtt_delay_components(df_mqtt), use_container_width=True)

    if "bottleneck" in df_mqtt.columns and df_mqtt["bottleneck"].notna().any():
        counts = df_mqtt["bottleneck"].value_counts().reset_index()
        counts.columns = ["Bottleneck", "Count"]
        fig = px.pie(
            counts, values="Count", names="Bottleneck",
            title="Distribution of Delay Bottlenecks",
            color="Bottleneck",
            color_discrete_map={
                "Device→Broker": "blue",
                "Broker Processing": "green",
                "Cloud Upload": "red",
            },
        )
        st.plotly_chart(fig, use_container_width=True)


def _show_delay(df_mqtt, column, label, colour):
    st.subheader(f"{label} Analysis")
    if column not in df_mqtt.columns:
        st.warning(f"No {label} data available.")
        return

    data = df_mqtt[df_mqtt[column].notna()]
    if data.empty:
        st.warning(f"No {label.lower()} measurements detected in this capture.")
        return

    st.plotly_chart(
        hist_with_boundaries(data, column, f"{label} Distribution", color=colour),
        use_container_width=True,
    )

    if "timestamp" in data.columns:
        fig, _ = delay_over_time(data, column, label, group_col="msg_type_name")
        st.plotly_chart(fig, use_container_width=True)

    category_col = f"{column}_category"
    if category_col in df_mqtt.columns and df_mqtt[category_col].notna().any():
        counts = df_mqtt[category_col].value_counts().reset_index()
        counts.columns = ["Category", "Count"]
        fig = px.bar(
            counts, x="Category", y="Count", title=f"{label} Categories",
            color="Category", color_discrete_map=CATEGORY_COLOURS,
        )
        st.plotly_chart(fig, use_container_width=True)


def _show_topology(df_mqtt, stats):
    st.subheader("Network Topology Analysis")

    brokers = list(stats.get("detected_brokers", []))
    clients = list(stats.get("detected_clients", []))

    if not brokers and not clients:
        st.warning("No network topology data available.")
    else:
        _draw_topology(df_mqtt, brokers, clients)

    st.subheader("Message Communication Table")
    # Only select columns that exist: the delay columns are present only when a
    # PUBLISH/PUBACK pair was found, which QoS-0 captures never produce.
    available = [c for c in COMM_COLUMNS if c in df_mqtt.columns]
    if not available:
        st.warning("No communication data available for the table.")
        return

    comm_df = df_mqtt[available].copy()
    if "timestamp" in comm_df.columns:
        comm_df["timestamp"] = pd.to_datetime(comm_df["timestamp"], unit="s")
    if "src_ip" in comm_df.columns and clients:
        comm_df["direction"] = np.where(
            comm_df["src_ip"].isin(clients), "Client→Broker", "Broker→Client"
        )

    column_config = {
        "timestamp": "Time",
        "src_ip": "Source",
        "dst_ip": "Destination",
        "msg_type_name": "Message Type",
    }
    for column, label in (
        ("device_to_broker_delay", "Client→Broker Delay (ms)"),
        ("broker_processing_delay", "Processing Delay (ms)"),
    ):
        if column in comm_df.columns:
            column_config[column] = st.column_config.NumberColumn(label, format="%.4f")

    sort_col = "timestamp" if "timestamp" in comm_df.columns else available[0]
    st.dataframe(
        comm_df.sort_values(sort_col, ascending=False),
        column_config=column_config,
        height=400,
        use_container_width=True,
    )


def _draw_topology(df_mqtt, brokers, clients):
    """Bipartite client/broker graph.

    Edges are only drawn to IPs actually identified as brokers. Taking the first
    destination address a client ever talked to yields the client's own IP when a
    broker-to-client packet sorts first, producing a self-edge or a lookup that
    raises.
    """
    nodes = [{"id": b, "label": b, "type": "broker"} for b in brokers]
    nodes += [{"id": c, "label": c, "type": "client"} for c in clients]
    index_by_id = {node["id"]: i for i, node in enumerate(nodes)}

    broker_set = set(brokers)
    edges = []
    if {"src_ip", "dst_ip"}.issubset(df_mqtt.columns):
        for client in clients:
            involved = df_mqtt[(df_mqtt["src_ip"] == client) | (df_mqtt["dst_ip"] == client)]
            peers = set(involved["dst_ip"]) | set(involved["src_ip"])
            for peer in peers & broker_set:
                if peer in index_by_id:
                    edges.append((index_by_id[peer], index_by_id[client]))

    xs = [0 if node["type"] == "broker" else 1 for node in nodes]
    ys = list(range(len(nodes)))

    edge_x, edge_y = [], []
    for source, target in edges:
        edge_x += [xs[source], xs[target], None]
        edge_y += [ys[source], ys[target], None]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(color="rgb(210,210,210)", width=1), hoverinfo="none",
    ))
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text",
        marker=dict(
            symbol="circle-dot", size=18,
            color=["#6175c1" if n["type"] == "broker" else "#DB4551" for n in nodes],
            line=dict(color="rgb(50,50,50)", width=1),
        ),
        text=[n["label"] for n in nodes],
        textposition="middle right",
        hoverinfo="text", opacity=0.85,
    ))
    fig.update_layout(
        title="Client-Broker Topology (blue: brokers, red: clients)",
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.3, 1.6]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=max(300, 60 * max(len(nodes), 1)),
        margin=dict(l=40, r=40, b=40, t=60),
    )
    st.plotly_chart(fig, use_container_width=True)
