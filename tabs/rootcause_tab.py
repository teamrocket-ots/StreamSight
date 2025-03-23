import streamlit as st
from rootcause_analysis import RootCauseAnalysis
from analysis import perform_root_cause_analysis

def show_rootcause_tab(df_packets, df_delays):
    """
    Display a new tab in the Streamlit GUI that runs and shows Root Cause Analysis.
    """
    st.header("Root Cause Analysis")

    if st.button("Run Root Cause Analysis"):
        report = perform_root_cause_analysis(df_packets, df_delays)
        st.text(report)
    else:
        st.info("Click the button above to perform root cause analysis.")