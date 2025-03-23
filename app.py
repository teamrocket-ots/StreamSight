import streamlit as st
import tempfile
import os
import pandas as pd

from pcap_parser import parse_pcap
from data_generator import generate_dummy_packets
from tabs.overview import show_overview_tab
from tabs.delay_analysis import show_delay_analysis_tab
from tabs.insights import show_insights_tab
from tabs.timeline import show_timeline_tab
from tabs.search import show_search_tab
from tabs.explorer import show_explorer_tab
from tabs.tcp_analysis import show_tcp_analysis_tab
from tabs.udp_analysis import show_udp_analysis_tab
from tabs.mqtt_analysis import show_mqtt_analysis_tab

# New import for our root cause tab:
from tabs.rootcause_tab import show_rootcause_tab

st.set_page_config(page_title="StreamSight", layout="wide")

def main():
    st.title("StreamSight: IoT Network Analytics")

    uploaded_file = st.sidebar.file_uploader("Upload a PCAP/PCAPNG file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        st.sidebar.write("Parsing PCAP file, please wait...")
        temp_dir = tempfile.TemporaryDirectory()
        temp_path = os.path.join(temp_dir.name, uploaded_file.name)

        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())

        df_packets, df_delays, df_retrans, df_tcp, df_udp, df_mqtt = parse_pcap(temp_path)
        st.sidebar.success("PCAP parsed successfully!")
    else:
        st.sidebar.info("No PCAP uploaded. Using dummy data.")
        df_packets, df_delays, df_retrans = generate_dummy_packets()
        df_tcp = pd.DataFrame()
        df_udp = pd.DataFrame()
        df_mqtt = pd.DataFrame()

    # Existing session state usage
    st.session_state.setdefault("filter_protocol", "")
    st.session_state.setdefault("filter_ip", "")
    st.session_state.setdefault("filter_port", "")

    # Create tabs
    tabs = st.tabs([
        "Overview",
        "TCP Analysis",
        "UDP Analysis",
        "MQTT Analysis",
        "Timeline Analysis",
        "Search & Filter",
        "Data Explorer",
        "Root Cause Analysis"   # <-- New Tab
    ])

    with tabs[0]:
        show_overview_tab(df_packets, df_delays, df_retrans)

    with tabs[1]:
        show_tcp_analysis_tab(df_packets, df_retrans)

    with tabs[2]:
        show_udp_analysis_tab(df_udp)

    with tabs[3]:
        show_mqtt_analysis_tab(df_mqtt)

    with tabs[4]:
        show_timeline_tab(df_delays, df_retrans)

    with tabs[5]:
        show_search_tab(df_packets, df_delays)

    with tabs[6]:
        show_explorer_tab(df_packets, df_delays, df_retrans)

    # Root Cause Analysis tab
    with tabs[7]:
        show_rootcause_tab(df_packets, df_delays)

if __name__ == "__main__":
    main()