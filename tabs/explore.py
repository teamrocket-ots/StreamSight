"""Combined data-exploration tab: filtering, raw tables and root-cause correlation."""

import streamlit as st

from tabs.explorer import show_explorer_tab
from tabs.rootcause_tab import show_rootcause_tab
from tabs.search import show_search_tab


def show_explore_tab(df_packets, df_delays, df_retrans, df_tcp=None, df_udp=None):
    """Search, raw tables and root-cause analysis as sub-tabs."""
    st.header("Explore")

    search_tab, tables_tab, rootcause_tab = st.tabs(
        ["Search & Filter", "Raw Tables", "Root Cause"]
    )

    with search_tab:
        show_search_tab(df_packets, df_delays)
    with tables_tab:
        show_explorer_tab(df_packets, df_delays, df_retrans, df_tcp, df_udp)
    with rootcause_tab:
        show_rootcause_tab(df_tcp, df_udp, df_delays)
