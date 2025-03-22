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
        fig1 = hist_with_boundaries(
            df_delays, 
            "device_to_broker_delay", 
            "Device→Broker Delay", 
            color="#1E88E5"
        )
        st.plotly_chart(fig1, use_container_width=True)
        
        # Broker processing delay histogram
        fig2 = hist_with_boundaries(
            df_delays, 
            "broker_processing_delay", 
            "Broker Processing Delay", 
            color="#FFC107"
        )
        st.plotly_chart(fig2, use_container_width=True)
        
    with col2:
        # Cloud upload delay histogram
        fig3 = hist_with_boundaries(
            df_delays, 
            "cloud_upload_delay", 
            "Cloud Upload Delay", 
            color="#4CAF50"
        )
        st.plotly_chart(fig3, use_container_width=True)
        
        # Total E2E delay histogram
        fig4 = hist_with_boundaries(
            df_delays, 
            "total_delay", 
            "Total E2E Delay", 
            color="#9C27B0"
        )
        st.plotly_chart(fig4, use_container_width=True)

    # Display average metrics in a row
    avg_dev = df_delays["device_to_broker_delay"].mean()
    avg_broker = df_delays["broker_processing_delay"].mean()
    avg_cloud = df_delays["cloud_upload_delay"].mean()
    avg_total = df_delays["total_delay"].mean()

    # Metrics for average delays
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Avg Dev→Broker", f"{avg_dev:.3f}s")
    c2.metric("Avg Broker Proc", f"{avg_broker:.3f}s")
    c3.metric("Avg Cloud Up", f"{avg_cloud:.3f}s")
    c4.metric("Avg Total", f"{avg_total:.3f}s")