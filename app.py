import logging
import os
import shutil
import tempfile

import streamlit as st

from data_generator import generate_dummy_packets
from pcap_parser import parse_pcap
from tabs.explore import show_explore_tab
from tabs.mqtt_analysis import show_mqtt_analysis_tab
from tabs.overview import show_overview_tab
from tabs.tcp_analysis import show_tcp_analysis_tab
from tabs.timeline import show_timeline_tab
from tabs.udp_analysis import show_udp_analysis_tab

try:
    # pyshark signals a missing tshark with its own exception type, not
    # FileNotFoundError, so it has to be caught by name to give a useful message.
    from pyshark.tshark.tshark import TSharkNotFoundException
except ImportError:  # pragma: no cover - depends on the pyshark version
    TSharkNotFoundException = None

logging.basicConfig(level=logging.INFO)

st.set_page_config(
    page_title="StreamSight",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

MISSING_TSHARK_HELP = (
    "StreamSight needs Wireshark's `tshark` on your PATH to read capture files.\n\n"
    "Install Wireshark from https://www.wireshark.org/download.html, then make sure "
    "its install directory (on Windows, usually `C:\\Program Files\\Wireshark`) is on "
    "PATH and restart the app. Verify with `tshark --version`."
)

# Tightens Streamlit's default spacing and makes the tab bar read as a single
# control strip rather than plain text. Colours are inherited from the active
# theme, so this works in both light and dark mode.
STYLE = """
<style>
  .block-container { padding-top: 2.2rem; padding-bottom: 3rem; }

  div[data-testid="stTabs"] > div[role="tablist"] {
      gap: 0.15rem;
      border-bottom: 1px solid rgba(128,128,128,0.25);
      margin-bottom: 0.6rem;
      overflow-x: auto;
  }
  div[data-testid="stTabs"] button[role="tab"] {
      padding: 0.55rem 1.05rem;
      border-radius: 6px 6px 0 0;
      font-weight: 600;
      white-space: nowrap;
  }
  div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
      background: rgba(128,128,128,0.12);
  }
  /* Nested tabs sit inside a panel, so they read lighter than the top level. */
  div[data-testid="stTabs"] div[data-testid="stTabs"] button[role="tab"] {
      padding: 0.35rem 0.8rem;
      font-weight: 500;
      font-size: 0.9rem;
  }

  div[data-testid="stMetric"] {
      background: rgba(128,128,128,0.07);
      border: 1px solid rgba(128,128,128,0.18);
      border-radius: 8px;
      padding: 0.7rem 0.9rem;
  }
  div[data-testid="stMetricLabel"] { opacity: 0.75; }

  h1 { font-size: 1.9rem; margin-bottom: 0.1rem; }
  h2 { font-size: 1.35rem; padding-top: 0.4rem; }
  h3 { font-size: 1.1rem; }
</style>
"""


@st.cache_data(show_spinner="Parsing capture…")
def parse_uploaded_pcap(file_bytes: bytes, filename: str):
    """Parse an uploaded capture, cached on the file's contents.

    Streamlit reruns the whole script on every widget interaction -- every
    keystroke in a text filter included. Without this cache a large capture is
    re-parsed each time. Keyed on the bytes rather than the uploader handle so
    the cache survives reruns.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        temp_path = os.path.join(temp_dir, filename)
        with open(temp_path, "wb") as handle:
            handle.write(file_bytes)
        return parse_pcap(temp_path)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def load_data(uploaded_file):
    """Return the six frames, from an upload if present and demo data otherwise."""
    if uploaded_file is None:
        st.sidebar.info("No capture uploaded — showing generated demo data.")
        return generate_dummy_packets(), False

    missing_tshark = tuple(
        exc for exc in (TSharkNotFoundException, FileNotFoundError) if exc is not None
    )

    try:
        data = parse_uploaded_pcap(uploaded_file.getvalue(), uploaded_file.name)
    except missing_tshark:
        st.sidebar.error("Could not run **tshark**.")
        st.error(MISSING_TSHARK_HELP)
        return None, True
    except Exception as exc:
        st.sidebar.error("Failed to parse the capture.")
        st.error(f"Could not parse `{uploaded_file.name}`: {exc}")
        st.caption(
            "Check the file is a valid .pcap/.pcapng capture. Partially corrupted "
            "captures can also fail part-way through."
        )
        return None, True

    st.sidebar.success(f"Parsed **{uploaded_file.name}**")
    return data, False


@st.cache_data(ttl=3600)
def _tshark_status():
    """Cached so the version subprocess runs once per hour, not per rerun."""
    from tshark_backend import tshark_version
    return tshark_version()


def _sidebar_capture_support():
    """Warn when the host cannot read capture files.

    tshark is an OS package, not a Python dependency, so on a hosted deployment
    it can be missing while everything else works — and the first sign of
    trouble would otherwise be an upload failing for no visible reason.

    Silent on success: a working install is the expected case and does not need
    a line of its own.
    """
    if _tshark_status():
        return

    st.sidebar.error("tshark not found — uploads will fail")
    st.sidebar.caption(
        "Demo data still works. To read captures, install Wireshark and make "
        "sure `tshark` is on PATH."
    )


def _sidebar_summary(df_packets, df_tcp, df_udp, df_mqtt):
    """Capture facts worth having visible from every tab."""
    if df_packets.empty:
        return

    st.sidebar.divider()
    st.sidebar.caption("CAPTURE")

    duration = df_packets["timestamp"].max() - df_packets["timestamp"].min()
    left, right = st.sidebar.columns(2)
    left.metric("Packets", f"{len(df_packets):,}")
    right.metric("Duration", f"{duration:,.1f} s")

    left, right = st.sidebar.columns(2)
    left.metric("TCP flows", f"{df_tcp['conn_id'].nunique() if not df_tcp.empty else 0}")
    right.metric("UDP flows", f"{df_udp['conn_id'].nunique() if not df_udp.empty else 0}")

    counts = df_packets["protocol"].value_counts()
    st.sidebar.caption("PROTOCOLS")
    for protocol, count in counts.items():
        st.sidebar.write(f"**{protocol}** — {count:,}")


def main():
    st.markdown(STYLE, unsafe_allow_html=True)

    st.title("StreamSight")
    st.caption("Network delay characterisation for IoT traffic — TCP, UDP and MQTT.")

    st.sidebar.title("📡 StreamSight")
    uploaded_file = st.sidebar.file_uploader(
        "Upload a capture", type=["pcap", "pcapng"]
    )
    _sidebar_capture_support()

    data, failed = load_data(uploaded_file)
    if failed or data is None:
        return

    df_packets, df_delays, df_retrans, df_tcp, df_udp, df_mqtt = data
    _sidebar_summary(df_packets, df_tcp, df_udp, df_mqtt)

    overview, tcp, udp, mqtt, timeline, explore = st.tabs([
        "Overview",
        "TCP",
        "UDP",
        "MQTT",
        "Timeline",
        "Explore",
    ])

    with overview:
        show_overview_tab(df_packets, df_delays, df_retrans)
    with tcp:
        show_tcp_analysis_tab(df_packets, df_retrans, df_tcp)
    with udp:
        show_udp_analysis_tab(df_udp)
    with mqtt:
        show_mqtt_analysis_tab(df_mqtt, df_delays)
    with timeline:
        show_timeline_tab(df_delays, df_retrans, df_tcp, df_udp)
    with explore:
        show_explore_tab(df_packets, df_delays, df_retrans, df_tcp, df_udp)


if __name__ == "__main__":
    main()
