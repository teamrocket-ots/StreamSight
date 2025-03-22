import streamlit as st
from visualizations import hist_with_boundaries

def show_delay_analysis_tab(df_delays):
    """
    Display the Delay Analysis tab with histograms for each delay type.
    """
    st.header("Delay Analysis")
    
    # Two columns layout for histograms
    col1, col2 = st.columns(2)
    
    with col1:
        # Device to Broker delay histogram
        if "device_to_broker_delay" in df_delays.columns and not df_delays.empty:
            fig1 = hist_with_boundaries(
                df_delays, 
                "device_to_broker_delay", 
                "Device→Broker Delay", 
                color="#1E88E5"
            )
            if fig1:
                st.plotly_chart(fig1, use_container_width=True)
            else:
                st.info("No Device→Broker delay data available.")
        else:
            st.info("No Device→Broker delay data available.")
        
        # Broker processing delay histogram
        if "broker_processing_delay" in df_delays.columns and not df_delays.empty:
            fig2 = hist_with_boundaries(
                df_delays, 
                "broker_processing_delay", 
                "Broker Processing Delay", 
                color="#FFC107"
            )
            if fig2:
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("No Broker Processing delay data available.")
        else:
            st.info("No Broker Processing delay data available.")
        
    with col2:
        # Cloud upload delay histogram
        if "cloud_upload_delay" in df_delays.columns and not df_delays.empty:
            fig3 = hist_with_boundaries(
                df_delays, 
                "cloud_upload_delay", 
                "Cloud Upload Delay", 
                color="#4CAF50"
            )
            if fig3:
                st.plotly_chart(fig3, use_container_width=True)
            else:
                st.info("No Cloud Upload delay data available.")
        else:
            st.info("No Cloud Upload delay data available.")
        
        # Total E2E delay histogram
        if "total_delay" in df_delays.columns and not df_delays.empty:
            fig4 = hist_with_boundaries(
                df_delays, 
                "total_delay", 
                "Total E2E Delay", 
                color="#9C27B0"
            )
            if fig4:
                st.plotly_chart(fig4, use_container_width=True)
            else:
                st.info("No Total E2E delay data available.")
        else:
            st.info("No Total E2E delay data available.")
    
    # Display average metrics in a row; check if columns exist and have data
    def safe_avg(col_name):
        if col_name in df_delays.columns and not df_delays.empty:
            return f"{df_delays[col_name].mean():.3f}s"
        return "N/A"
    
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Avg Dev→Broker", safe_avg("device_to_broker_delay"))
    c2.metric("Avg Broker Proc", safe_avg("broker_processing_delay"))
    c3.metric("Avg Cloud Up", safe_avg("cloud_upload_delay"))
    c4.metric("Avg Total", safe_avg("total_delay"))
