"""Plotly chart builders shared across tabs.

Every builder returns a figure, including for empty or unusable input, so a tab
can render a placeholder instead of raising.
"""

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

PLOT_BG = "rgba(240, 240, 240, 0.8)"
GRID = "rgba(200, 200, 200, 0.2)"


def _empty_figure(message):
    """A titled, empty figure used wherever there is nothing to plot."""
    fig = go.Figure()
    fig.update_layout(title=message)
    return fig


def _styled(fig):
    """Apply the shared axis and background styling."""
    fig.update_layout(
        plot_bgcolor=PLOT_BG,
        xaxis=dict(showgrid=True, gridcolor=GRID),
        yaxis=dict(showgrid=True, gridcolor=GRID),
    )
    return fig


#: Above this many distinct series a legend stops being readable and is dropped.
MAX_LEGEND_SERIES = 8

#: A heavy tail (p99 far above the median) makes a linear axis useless -- every
#: point collapses onto the baseline while one outlier owns the range.
HEAVY_TAIL_RATIO = 50


def shorten_endpoint(label, keep=14):
    """Abbreviate an endpoint pair for a legend.

    IPv6 connection labels run to ~70 characters, which on a plot pushes the
    legend across the whole figure and squashes the data into a strip.
    """
    if not isinstance(label, str):
        return str(label)

    def trim(part):
        part = part.strip()
        return part if len(part) <= keep else "…" + part[-keep:]

    if " - " in label:
        source, destination = label.split(" - ", 1)
        return f"{trim(source)} → {trim(destination)}"
    return trim(label)


def delay_over_time(df, value_col, label, time_col="timestamp",
                    group_col="conn_label", unit="ms", height=420):
    """Scatter of a delay metric against time, laid out to stay readable.

    Handles the two things that wreck these plots in practice: very long IPv6
    endpoint labels in the legend, and heavy-tailed delay distributions where a
    single outlier flattens every other point onto the axis.

    Always returns ``(figure, used_log_scale)`` -- callers unpack two values, so
    returning a bare figure on the empty path would raise there instead.
    """
    if df.empty or value_col not in df.columns or time_col not in df.columns:
        return _empty_figure(f"No {label.lower()} measurements to plot"), False

    plot_df = df.loc[df[value_col].notna(), :].copy()
    if plot_df.empty:
        return _empty_figure(f"No {label.lower()} measurements to plot"), False

    plot_df["_time"] = pd.to_datetime(plot_df[time_col], unit="s")

    colour_col = None
    hover = []
    if group_col and group_col in plot_df.columns:
        series_count = plot_df[group_col].nunique()
        if series_count <= MAX_LEGEND_SERIES:
            plot_df["Flow"] = plot_df[group_col].map(shorten_endpoint)
            colour_col = "Flow"
            hover = [group_col]

    fig = px.scatter(
        plot_df,
        x="_time",
        y=value_col,
        color=colour_col,
        hover_data=hover,
        title=f"{label} Over Time",
        labels={value_col: f"{label} ({unit})", "_time": "Time"},
        opacity=0.65,
        height=height,
    )
    fig.update_traces(marker=dict(size=5))

    values = plot_df[value_col]
    median = values.median()
    p99 = values.quantile(0.99)
    log_scale = median > 0 and p99 / median > HEAVY_TAIL_RATIO and values.min() > 0
    if log_scale:
        fig.update_yaxes(type="log")

    fig.update_layout(
        # Legend below the plot, so it never steals horizontal space from it.
        legend=dict(
            orientation="h", yanchor="bottom", y=-0.42,
            xanchor="left", x=0, font=dict(size=10), title=None,
        ),
        margin=dict(l=70, r=25, t=55, b=70),
        xaxis=dict(tickformat="%H:%M:%S", nticks=8),
    )
    _styled(fig)
    return fig, log_scale


def hist_with_boundaries(df, xcol, title, color="royalblue", unit="ms"):
    """Histogram with mean, median and ±1σ annotations.

    NaNs are dropped before the bin-width calculation: ``np.percentile`` returns
    NaN for an all-NaN column and ``int(np.ceil(NaN))`` raises. An emptiness
    check on length alone does not catch that case.
    """
    if xcol not in df.columns:
        return _empty_figure(f"No data available for {xcol}")

    values = pd.to_numeric(df[xcol], errors="coerce").dropna()
    if values.empty:
        return _empty_figure(f"No usable measurements for {xcol}")

    label = xcol.replace("_", " ").title()
    axis_label = f"{label} ({unit})" if unit else label

    if values.nunique() == 1:
        fig = px.histogram(
            values.to_frame(name=xcol), x=xcol, title=title,
            labels={xcol: axis_label}, color_discrete_sequence=[color],
        )
        return _styled(fig)

    # Freedman-Diaconis bin width, clamped to a readable range.
    q75, q25 = np.percentile(values, [75, 25])
    iqr = q75 - q25
    bin_width = 2 * iqr / (len(values) ** (1 / 3)) if iqr > 0 else 0
    if bin_width > 0:
        bin_count = int(np.ceil((values.max() - values.min()) / bin_width))
    else:
        bin_count = 20
    bin_count = max(10, min(30, bin_count))

    fig = px.histogram(
        values.to_frame(name=xcol),
        x=xcol,
        nbins=bin_count,
        title=title,
        labels={xcol: axis_label},
        color_discrete_sequence=[color],
    )
    fig.update_traces(
        marker=dict(line=dict(color="rgba(0, 0, 0, 0.5)", width=1)),
        opacity=0.8,
    )

    mean_val = values.mean()
    std_val = values.std()
    median_val = values.median()

    fig.add_vline(
        x=mean_val, line_width=2, line_dash="dash", line_color="red",
        annotation_text=f"Mean: {mean_val:.3f}{unit}",
        annotation_position="top right", annotation_font=dict(size=12),
    )
    fig.add_vline(
        x=median_val, line_width=2, line_dash="dot", line_color="green",
        annotation_text=f"Median: {median_val:.3f}{unit}",
        annotation_position="top left", annotation_font=dict(size=12),
    )
    if not np.isnan(std_val) and std_val > 0:
        fig.add_vrect(
            x0=mean_val - std_val, x1=mean_val + std_val,
            fillcolor="rgba(0, 100, 80, 0.2)", opacity=0.4, line_width=0,
            annotation_text=f"±1σ: {std_val:.3f}{unit}",
            annotation_position="bottom right",
        )

    fig.update_layout(bargap=0.1)
    return _styled(fig)


def tcp_delay_distribution(df_tcp, delay_type, title=None):
    """Histogram of a TCP delay metric."""
    if df_tcp.empty or delay_type not in df_tcp.columns:
        return _empty_figure(f"No data available for {delay_type}")

    if title is None:
        title = f"TCP {delay_type.replace('_', ' ').title()} Distribution"
    return hist_with_boundaries(df_tcp, delay_type, title, color="blue")


def tcp_health_timeline(df_tcp):
    """Timeline of TCP health events -- the direct causes of transmission delay.

    A zero-window event is a receiver-side stall rather than a network problem,
    so plotting these against time is what makes a delay spike attributable.
    """
    event_columns = {
        "is_retrans": ("Retransmission", "#d62728"),
        "zero_window": ("Zero Window", "#9467bd"),
        "window_full": ("Window Full", "#ff7f0e"),
        "duplicate_ack": ("Duplicate ACK", "#1f77b4"),
        "out_of_order": ("Out of Order", "#2ca02c"),
        "spurious_retrans": ("Spurious Retrans", "#8c564b"),
    }
    present = [c for c in event_columns if c in df_tcp.columns]
    if df_tcp.empty or not present or "timestamp" not in df_tcp.columns:
        return _empty_figure("No TCP health events available")

    rows = []
    for column in present:
        hits = df_tcp.loc[df_tcp[column].fillna(False).astype(bool), "timestamp"]
        label = event_columns[column][0]
        rows.extend({"time": t, "event": label} for t in hits)

    if not rows:
        return _empty_figure("No TCP health events detected in this capture")

    df_events = pd.DataFrame(rows)
    df_events["time"] = pd.to_datetime(df_events["time"], unit="s")

    fig = px.scatter(
        df_events, x="time", y="event", color="event",
        title="TCP Health Events Over Time",
        labels={"time": "Time", "event": "Event"},
        color_discrete_map={v[0]: v[1] for v in event_columns.values()},
    )
    fig.update_traces(marker=dict(size=9, symbol="line-ns", line=dict(width=2)))
    fig.update_layout(showlegend=False)
    return _styled(fig)


def udp_jitter_plot(df_udp):
    """Jitter against estimated packet loss."""
    if df_udp.empty or not all(c in df_udp.columns for c in ("jitter", "possible_loss")):
        return _empty_figure("No UDP jitter or packet loss data available")

    plot_df = df_udp.dropna(subset=["jitter", "possible_loss"])
    if plot_df.empty:
        return _empty_figure("No UDP jitter measurements available")

    fig = px.scatter(
        plot_df,
        x="jitter",
        y="possible_loss",
        size="payload_size" if "payload_size" in plot_df.columns else None,
        color="congestion_level" if "congestion_level" in plot_df.columns else None,
        hover_data=[c for c in ("timestamp", "conn_label") if c in plot_df.columns],
        title="UDP Jitter vs Estimated Packet Loss",
        labels={
            "jitter": "Jitter (ms)",
            "possible_loss": "Estimated Packet Loss",
            "payload_size": "Payload Size",
        },
    )
    return _styled(fig)


def mqtt_delay_components(df_mqtt):
    """Grouped bar chart of MQTT delay components."""
    if df_mqtt.empty:
        return _empty_figure("No MQTT delay data available")

    components = []
    for delay_type in ("device_to_broker_delay", "broker_processing_delay", "cloud_upload_delay"):
        if delay_type in df_mqtt.columns:
            values = df_mqtt[delay_type].dropna()
            if not values.empty:
                components.append({
                    "component": delay_type.replace("_", " ").title(),
                    "mean": values.mean(),
                    "median": values.median(),
                    "p95": values.quantile(0.95),
                })

    if not components:
        return _empty_figure("No MQTT delay components available")

    df_components = pd.DataFrame(components)
    fig = go.Figure()
    for name, column, colour in (
        ("Mean", "mean", "rgb(55, 83, 109)"),
        ("Median", "median", "rgb(26, 118, 255)"),
        ("95th Percentile", "p95", "rgb(246, 78, 139)"),
    ):
        fig.add_trace(go.Bar(
            x=df_components["component"], y=df_components[column],
            name=name, marker_color=colour,
        ))

    fig.update_layout(
        title="MQTT Delay Components",
        xaxis_title="Delay Component",
        yaxis_title="Time (ms)",
        barmode="group", bargap=0.15, bargroupgap=0.1,
    )
    return fig


def connection_rtt_chart(df_tcp, top_n=10):
    """Mean RTT for the busiest connections."""
    if df_tcp.empty or "rtt" not in df_tcp.columns:
        return _empty_figure("No RTT data available")

    label_col = "conn_label" if "conn_label" in df_tcp.columns else "conn_id"
    if label_col not in df_tcp.columns:
        return _empty_figure("No connection identifiers available")

    rtt_by_conn = (
        df_tcp.dropna(subset=["rtt"])
        .groupby(label_col)["rtt"].mean()
        .reset_index()
        .sort_values("rtt", ascending=False)
        .head(top_n)
    )
    if rtt_by_conn.empty:
        return _empty_figure("No RTT measurements available")

    rtt_by_conn["Flow"] = rtt_by_conn[label_col].map(shorten_endpoint)
    fig = px.bar(
        rtt_by_conn, x="Flow", y="rtt",
        hover_data=[label_col],
        title=f"Top {top_n} Connections by Mean RTT",
        labels={"Flow": "Connection", "rtt": "RTT (ms)"},
        height=400,
    )
    fig.update_layout(xaxis={"tickangle": 25}, margin=dict(l=70, r=25, t=55, b=120))
    return _styled(fig)


def congestion_heatmap(df_udp, sample_size=500, random_state=0):
    """Congestion score per connection over time.

    Takes a copy before adding the rounded-time column: assigning into the
    result of ``.sample()`` both warns and mutates the caller's frame. The
    sample is seeded so the chart does not change on every rerun.
    """
    if df_udp.empty or "congestion_score" not in df_udp.columns:
        return _empty_figure("No congestion data available")

    plot_df = df_udp.dropna(subset=["congestion_score"]).copy()
    if plot_df.empty:
        return _empty_figure("No congestion measurements available")

    if len(plot_df) > sample_size:
        plot_df = plot_df.sample(sample_size, random_state=random_state)

    label_col = "conn_label" if "conn_label" in plot_df.columns else "conn_id"
    plot_df["time"] = pd.to_datetime(plot_df["timestamp"], unit="s").dt.round("1s")

    fig = px.density_heatmap(
        plot_df, x="time", y=label_col, z="congestion_score",
        title="Connection Congestion Over Time",
        labels={"time": "Time", label_col: "Connection",
                "congestion_score": "Congestion Score"},
    )
    fig.update_layout(coloraxis_colorbar={"title": "Congestion Score"})
    return fig
