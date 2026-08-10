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

SEVERITY_ICON = {"warn": "🟠", "info": "🔵"}


@st.cache_data(show_spinner="Correlating delays…")
def _analyse(df_tcp, df_udp, df_delays):
    analyses = perform_root_cause_analysis(df_tcp, df_udp, df_delays)
    return [
        {
            "metric": a.metric,
            "stats": a.compute_statistics(),
            "findings": a.findings(),
            "factors": a.correlate_factors(),
        }
        for a in analyses
    ], root_cause_report(analyses)


def show_rootcause_tab(df_tcp=None, df_udp=None, df_delays=None):
    """What looks wrong in this capture, and what it tracks with."""
    st.subheader("Root Cause Analysis")

    frames = [df if df is not None else pd.DataFrame() for df in (df_tcp, df_udp, df_delays)]
    if all(df.empty for df in frames):
        st.info("No measurements available to analyse.")
        return

    # Deliberately no button: any widget that triggers a rerun resets st.tabs to
    # the first tab, which reads as the app throwing you back to the start.
    results, report = _analyse(*frames)

    if not results:
        st.info(
            "No delay measurements to correlate. Delay needs a completed round trip: "
            "an acknowledged TCP segment, a multi-packet UDP flow, or an MQTT PUBLISH "
            "paired with its PUBACK."
        )
        return

    if not sum(len(r["findings"]) for r in results):
        st.success(
            "Nothing stands out — no long tails, slow endpoints or strong correlations found."
        )

    for result in results:
        _show_metric(result)

    with st.expander("Full text report"):
        st.code(report, language="text")
    st.download_button(
        "Download report",
        report,
        file_name="streamsight_root_cause.txt",
        mime="text/plain",
        key="download_root_cause",
    )


def _show_metric(result):
    stats = result["stats"]
    findings = result["findings"]

    st.markdown(f"**{result['metric']}**")

    # One compact line rather than five tiles. st.metric truncates any value too
    # wide for its column, which turned "335.306 ms" into "335.306 …".
    st.caption(
        f"{stats['count']:,} samples · median {stats['median_delay']:.2f} ms · "
        f"p95 {stats['p95_delay']:.2f} ms · max {stats['max_delay']:.2f} ms"
    )

    if findings:
        for finding in findings:
            icon = SEVERITY_ICON.get(finding["severity"], "•")
            st.markdown(f"{icon} **{finding['title']}**")
            st.caption(finding["detail"])
    else:
        st.caption("No issues stood out for this metric.")

    with st.expander("Breakdown by factor"):
        _show_factor_charts(result["factors"])

    st.divider()


def _show_factor_charts(factors):
    available = [(key, label) for key, label in FACTOR_LABELS if factors.get(key)]
    if not available:
        st.caption("No factor in this capture has more than one distinct value.")
        return

    tabs = st.tabs([label for _, label in available])
    for tab, (key, label) in zip(tabs, available):
        with tab:
            df = pd.DataFrame([
                {
                    "Value": shorten_endpoint(name) if "ip" in key else name,
                    "Mean Delay (ms)": mean,
                    "Samples": count,
                }
                for name, (mean, count) in factors[key].items()
            ])

            trusted = df[df["Samples"] >= MIN_SAMPLES_FOR_TREND]
            if trusted.empty:
                st.caption("Every group here has too few samples to read as a trend.")
                st.dataframe(df, use_container_width=True, hide_index=True)
                continue

            fig = px.bar(
                trusted.sort_values("Mean Delay (ms)", ascending=False),
                x="Value", y="Mean Delay (ms)",
                hover_data=["Samples"],
                height=320,
            )
            fig.update_layout(
                xaxis={"tickangle": 25},
                margin=dict(l=60, r=20, t=20, b=90),
            )
            st.plotly_chart(fig, use_container_width=True)

            dropped = len(df) - len(trusted)
            if dropped:
                st.caption(
                    f"{dropped} group(s) under {MIN_SAMPLES_FOR_TREND} samples "
                    "excluded from the chart."
                )
            st.dataframe(
                df.sort_values("Mean Delay (ms)", ascending=False),
                use_container_width=True, hide_index=True,
            )
