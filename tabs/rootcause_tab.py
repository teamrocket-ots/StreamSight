import pandas as pd
import plotly.express as px
import streamlit as st

from analysis import perform_root_cause_analysis, root_cause_report
from visualizations import shorten_endpoint

FACTOR_LABELS = [
    ("packet_size", "Packet Size"),
    ("protocol", "Protocol"),
    ("source_ip", "Source"),
    ("destination_ip", "Destination"),
]

#: Group means built from very few samples are noise, not signal.
MIN_SAMPLES_FOR_TREND = 3


@st.cache_data(show_spinner="Correlating delays…")
def _analyse(df_tcp, df_udp, df_delays):
    analyses = perform_root_cause_analysis(df_tcp, df_udp, df_delays)
    return [
        {
            "metric": a.metric,
            "description": a.description,
            "stats": a.compute_statistics(),
            "numeric": a.numeric_correlations(),
            "factors": a.correlate_factors(),
        }
        for a in analyses
    ], root_cause_report(analyses)


def show_rootcause_tab(df_tcp=None, df_udp=None, df_delays=None):
    """Correlate each delay metric against the packets it was measured on."""
    st.subheader("Root Cause Analysis")
    st.markdown(
        "Each delay metric is correlated against the packet it was measured on — "
        "its size, protocol and endpoints. Metrics are analysed **separately**: "
        "TCP acknowledgement delay and UDP inter-packet delay are different "
        "quantities and averaging them together is meaningless."
    )

    frames = [df if df is not None else pd.DataFrame() for df in (df_tcp, df_udp, df_delays)]
    if all(df.empty for df in frames):
        st.info("No measurements available to analyse.")
        return

    # Deliberately no button: any widget that triggers a rerun resets st.tabs to
    # the first tab, which reads as the app throwing you back to the start.
    results, report = _analyse(*frames)

    if not results:
        st.info(
            "No delay measurements to correlate.\n\n"
            "Delay needs a completed round trip: an acknowledged TCP segment, a "
            "multi-packet UDP flow, or an MQTT PUBLISH paired with its PUBACK."
        )
        return

    for result in results:
        _show_metric(result)
        st.divider()

    st.download_button(
        "Download full report",
        report,
        file_name="streamsight_root_cause.txt",
        mime="text/plain",
        key="download_root_cause",
    )


def _show_metric(result):
    stats = result["stats"]
    st.markdown(f"### {result['metric']}")
    st.caption(result["description"])

    cols = st.columns(5)
    cols[0].metric("Samples", f"{stats['count']:,}")
    cols[1].metric("Median", f"{stats['median_delay']:.3f} ms")
    cols[2].metric("Mean", f"{stats['avg_delay']:.3f} ms")
    cols[3].metric("95th pct", f"{stats['p95_delay']:.3f} ms")
    cols[4].metric("Max", f"{stats['max_delay']:.3f} ms")

    numeric = result["numeric"]
    if numeric:
        st.markdown("**How strongly each factor tracks the delay**")
        corr_cols = st.columns(len(numeric))
        for col, (factor, value) in zip(corr_cols, numeric.items()):
            col.metric(
                factor.replace("_", " ").title(),
                f"r = {value:+.3f}",
                help="Pearson correlation. Above ±0.5 is strong, below ±0.1 negligible.",
            )
    else:
        st.caption("No numeric factor varied enough to correlate against.")

    _show_factor_charts(result["factors"])


def _show_factor_charts(factors):
    available = [
        (key, label) for key, label in FACTOR_LABELS if factors.get(key)
    ]
    if not available:
        st.caption("No factor in this capture has more than one distinct value.")
        return

    tabs = st.tabs([label for _, label in available])
    for tab, (key, label) in zip(tabs, available):
        with tab:
            entries = factors[key]
            rows = [
                {
                    "Value": shorten_endpoint(name) if "ip" in key else name,
                    "Mean Delay (ms)": mean,
                    "Samples": count,
                }
                for name, (mean, count) in entries.items()
            ]
            df = pd.DataFrame(rows)

            trusted = df[df["Samples"] >= MIN_SAMPLES_FOR_TREND]
            thin = len(df) - len(trusted)

            if trusted.empty:
                st.info("Every group here has too few samples to read as a trend.")
                st.dataframe(df, use_container_width=True, hide_index=True)
                return

            fig = px.bar(
                trusted.sort_values("Mean Delay (ms)", ascending=False),
                x="Value", y="Mean Delay (ms)",
                hover_data=["Samples"],
                title=f"Mean Delay by {label}",
                height=380,
            )
            fig.update_layout(
                xaxis={"tickangle": 30}, margin=dict(l=60, r=25, t=55, b=90)
            )
            st.plotly_chart(fig, use_container_width=True)

            if thin:
                st.caption(
                    f"{thin} group(s) with fewer than {MIN_SAMPLES_FOR_TREND} samples "
                    "are excluded from the chart but listed below."
                )
            st.dataframe(
                df.sort_values("Mean Delay (ms)", ascending=False),
                use_container_width=True, hide_index=True,
            )
