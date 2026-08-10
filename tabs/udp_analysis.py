import pandas as pd
import plotly.express as px
import streamlit as st

from analysis import analyze_udp_delays
from pcap_parser import MIN_UDP_SAMPLES
from visualizations import (
    congestion_heatmap,
    delay_over_time,
    format_ms,
    hist_with_boundaries,
    shorten_endpoint,
    udp_jitter_plot,
)


def show_udp_analysis_tab(df_udp):
    """Display UDP analysis, distinguishing measurable flows from too-short ones."""
    st.header("UDP")

    if df_udp is None or df_udp.empty:
        st.warning("No UDP data available in this capture.")
        return

    df_udp, conn_stats = analyze_udp_delays(df_udp.copy())

    measurable = _describe_coverage(df_udp)

    _show_overview(df_udp, conn_stats)

    udp_tabs = st.tabs([
        "Inter-Packet Delay",
        "Jitter Analysis",
        "Packet Loss",
        "Congestion Analysis",
        "Connections",
    ])

    with udp_tabs[0]:
        _show_metric(df_udp, "ipd", "Inter-Packet Delay", "green", measurable)
    with udp_tabs[1]:
        _show_metric(df_udp, "jitter", "Jitter", "orange", measurable)
    with udp_tabs[2]:
        _show_loss(df_udp, measurable)
    with udp_tabs[3]:
        _show_congestion(df_udp, measurable)
    with udp_tabs[4]:
        _show_connections(df_udp, conn_stats)


def _describe_coverage(df_udp):
    """Warn when flows are too short to measure, instead of charting noise.

    Request/response traffic such as DNS and mDNS arrives in two-packet
    exchanges. Jitter and loss estimates over two samples are not measurements,
    so the parser flags those flows and the UI says so.
    """
    if "insufficient_samples" not in df_udp.columns:
        return df_udp

    short = df_udp["insufficient_samples"].fillna(False).astype(bool)
    measurable = df_udp[~short]

    if short.any():
        short_conns = df_udp.loc[short, "conn_id"].nunique()
        st.info(
            f"{short_conns} UDP flow(s) have fewer than {MIN_UDP_SAMPLES} packets — "
            "typically DNS or mDNS request/response exchanges. Jitter, loss and "
            "congestion are not estimated for them, because a handful of samples "
            "cannot support those statistics."
        )

    if "is_multicast" in df_udp.columns:
        multicast = df_udp["is_multicast"].fillna(False).astype(bool)
        if multicast.any():
            st.info(
                f"{df_udp.loc[multicast, 'conn_id'].nunique()} flow(s) are **multicast** "
                "(IPv4 224.0.0.0/4 or IPv6 ff00::/8), such as mDNS. These are one-way "
                "to a group address, not two-way conversations, so round-trip style "
                "metrics do not apply to them."
            )

    return measurable


def _show_overview(df_udp, conn_stats):
    st.subheader("UDP Performance Overview")

    ipd = df_udp["ipd"].dropna() if "ipd" in df_udp.columns else pd.Series(dtype=float)
    jitter = df_udp["jitter"].dropna() if "jitter" in df_udp.columns else pd.Series(dtype=float)

    total_loss = sum(s.get("possible_loss_sum", 0) or 0 for s in conn_stats.values())
    total_packets = sum(s.get("total_packets", 0) or 0 for s in conn_stats.values())
    denominator = total_packets + total_loss

    # One metric per column. Stacking two into a single column left the second
    # one orphaned on its own row, out of line with everything beside it.
    tiles = [
        ("Median Inter-Packet Delay", format_ms(ipd.median()) if not ipd.empty else "N/A", None),
        ("Median Jitter", format_ms(jitter.median()) if not jitter.empty else "N/A", None),
        ("Max Jitter", format_ms(jitter.max()) if not jitter.empty else "N/A", None),
        (
            "Estimated Packet Loss",
            f"{(total_loss / denominator * 100):.2f}%" if denominator else "N/A",
            "Inferred from RTP sequence numbers where available, timing gaps otherwise.",
        ),
        ("UDP Flows", f"{df_udp['conn_id'].nunique()}" if "conn_id" in df_udp.columns else "N/A", None),
    ]

    for column, (label, value, help_text) in zip(st.columns(len(tiles)), tiles):
        column.metric(label, value, help=help_text)


def _show_metric(df_udp, column, label, colour, measurable):
    st.subheader(f"{label} Analysis")
    if column not in measurable.columns:
        st.warning(f"No {label} data available.")
        return

    data = measurable[measurable[column].notna()]
    if data.empty:
        st.warning(f"No {label.lower()} measurements could be made on this capture.")
        return

    st.plotly_chart(
        hist_with_boundaries(data, column, f"UDP {label} Distribution", color=colour),
        use_container_width=True,
        key=f"udp_hist_{column}",
    )

    if "timestamp" in data.columns:
        fig, log_scale = delay_over_time(data, column, label)
        st.plotly_chart(fig, use_container_width=True, key=f"udp_time_{column}")
        if log_scale:
            st.caption(
                "Y-axis is logarithmic: this metric is heavily right-tailed, so a "
                "linear axis would flatten every point onto the baseline."
            )


def _show_loss(df_udp, measurable):
    st.subheader("Packet Loss Analysis")
    if "possible_loss" not in measurable.columns:
        st.warning("No packet loss data available.")
        return

    loss_data = measurable[measurable["possible_loss"].fillna(0) > 0]
    if loss_data.empty:
        st.info("No packet loss inferred from this capture.")
        return

    label_col = "conn_label" if "conn_label" in loss_data.columns else "conn_id"
    over_time = loss_data.copy()
    over_time["time"] = pd.to_datetime(over_time["timestamp"], unit="s")
    # Endpoint pairs run to ~70 characters for IPv6; unshortened they push the
    # legend across the figure and squash the data into a strip.
    over_time["Flow"] = over_time[label_col].map(shorten_endpoint)

    fig = px.scatter(
        over_time, x="time", y="possible_loss", size="possible_loss",
        color="Flow" if over_time["Flow"].nunique() <= 8 else None,
        hover_data=[label_col],
        title="Estimated Packet Loss Events Over Time",
        labels={"possible_loss": "Estimated Lost Packets", "time": "Time"},
        height=420,
    )
    fig.update_layout(
        legend=dict(orientation="h", yanchor="bottom", y=-0.42, x=0,
                    font=dict(size=10), title=None),
        margin=dict(l=70, r=25, t=55, b=70),
    )
    st.plotly_chart(fig, use_container_width=True, key="udp_analysis_chart_2")

    by_conn = loss_data.groupby(label_col)["possible_loss"].sum().reset_index()
    by_conn["Flow"] = by_conn[label_col].map(shorten_endpoint)
    fig = px.bar(
        by_conn.sort_values("possible_loss", ascending=False),
        x="Flow", y="possible_loss",
        hover_data=[label_col],
        title="Total Estimated Packet Loss by Flow",
        labels={"possible_loss": "Estimated Lost Packets", "Flow": "Flow"},
        height=400,
    )
    fig.update_layout(xaxis={"tickangle": 25}, margin=dict(l=70, r=25, t=55, b=110))
    st.plotly_chart(fig, use_container_width=True, key="udp_analysis_chart_3")

    if "seq_loss" in loss_data.columns and loss_data["seq_loss"].notna().any():
        st.caption(
            "Sequence-based loss (from RTP sequence numbers) is more reliable than "
            "the timing-gap estimate above."
        )
        st.metric("Sequence gaps detected", f"{int(loss_data['seq_loss'].fillna(0).sum())}")


def _show_congestion(df_udp, measurable):
    st.subheader("Congestion Analysis")
    if "congestion_score" not in measurable.columns:
        st.warning("No congestion data available.")
        return

    data = measurable[measurable["congestion_score"].notna()]
    if data.empty:
        st.warning("No congestion measurements could be made on this capture.")
        return

    st.plotly_chart(udp_jitter_plot(data), use_container_width=True, key="udp_analysis_chart_4")
    st.plotly_chart(congestion_heatmap(data), use_container_width=True, key="udp_analysis_chart_5")

    if "congestion_level" in data.columns:
        counts = data["congestion_level"].value_counts().reset_index()
        counts.columns = ["Congestion Level", "Count"]
        fig = px.pie(
            counts, values="Count", names="Congestion Level",
            title="Distribution of Congestion Levels",
            color="Congestion Level",
            color_discrete_map={
                "Low": "green", "Medium": "yellow", "High": "orange", "Very High": "red",
            },
        )
        st.plotly_chart(fig, use_container_width=True, key="udp_analysis_chart_6")


def _show_connections(df_udp, conn_stats):
    st.subheader("UDP Flow Summary")
    if not conn_stats:
        st.info("No flow statistics available.")
        return

    label_by_conn = {}
    if "conn_label" in df_udp.columns:
        label_by_conn = df_udp.groupby("conn_id")["conn_label"].first().to_dict()

    rows = []
    for conn_id, stats in conn_stats.items():
        row = {"flow": label_by_conn.get(conn_id, conn_id)}
        row.update(stats)
        rows.append(row)

    st.dataframe(pd.DataFrame(rows), use_container_width=True)
