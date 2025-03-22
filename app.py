import streamlit as st
import tempfile
import os
import pandas as pd

# Import modules
from pcap_parser import parse_pcap
from data_generator import generate_dummy_packets
from tabs.overview import show_overview_tab
from tabs.delay_analysis import show_delay_analysis_tab
from tabs.insights import show_insights_tab
from tabs.timeline import show_timeline_tab
from tabs.search import show_search_tab
from tabs.explorer import show_explorer_tab

# Page Setup
st.set_page_config(page_title="StreamSight", layout="wide")

st.markdown("""
<style>
body {
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}
.sidebar .sidebar-content {
    background: linear-gradient(#2e7bcf, #2e7bcf);
    color: white;
}
</style>
""", unsafe_allow_html=True)

def main():
    st.title("StreamSight: IoT Network Analytics")

    # Sidebar file upload
    uploaded_file = st.sidebar.file_uploader("Upload a PCAP/PCAPNG file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        st.sidebar.write("Parsing PCAP file, please wait...")
        temp_dir = tempfile.TemporaryDirectory()
        temp_path = os.path.join(temp_dir.name, uploaded_file.name)
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())
        df_packets, df_delays, df_retrans, clients, brokers = parse_pcap(temp_path)
        st.sidebar.success("PCAP parsed successfully!")
    else:
        st.sidebar.info("No PCAP uploaded. Using dummy data.")
        df_packets, df_delays, df_retrans = generate_dummy_packets()
        # For dummy data, set clients and brokers to empty sets
        clients, brokers = set(), set()


    # Add session state for filtering
    st.session_state.setdefault("filter_protocol", "")
    st.session_state.setdefault("filter_ip", "")
    st.session_state.setdefault("filter_port", "")

    # Create tabs
    tabs = st.tabs([
        "Overview", 
        "Delay Analysis", 
        "Insights & Categorization", 
        "Timeline Analysis", 
        "Search & Filter", 
        "Data Explorer"
    ])

    # Display each tab
    with tabs[0]:
        show_overview_tab(df_packets, df_delays, df_retrans)
    
    with tabs[1]:
        show_delay_analysis_tab(df_delays)
    
    with tabs[2]:
        show_insights_tab(df_delays)
    
    with tabs[3]:
        show_timeline_tab(df_delays, df_retrans)
    
    with tabs[4]:
        show_search_tab(df_packets, df_delays)
    
    with tabs[5]:
        show_explorer_tab(df_packets, df_delays, df_retrans)

if __name__ == "__main__":
    main()