import streamlit as st


def show_explorer_tab(df_packets, df_delays, df_retrans):
    """
    Display raw data tables for exploration
    """
    st.header("Data Explorer")
    
    # Show packets data
    st.subheader("Packets Table")
    if not df_packets.empty:
        with st.expander("View all packets", expanded=True):
            st.dataframe(df_packets)
    else:
        st.info("No packet data available.")
        
    # Show delay data
    st.subheader("MQTT Delays")
    if not df_delays.empty:
        with st.expander("View all delay measurements", expanded=True):
            st.dataframe(df_delays)
    else:
        st.info("No delay data available.")
        
    # Show retransmission data
    st.subheader("Retransmissions")
    if not df_retrans.empty:
        with st.expander("View all retransmission events", expanded=True):
            st.dataframe(df_retrans)
    else:
        st.info("No retransmission data available.")
    
    # Add download buttons for the data
    st.subheader("Download Data")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if not df_packets.empty:
            csv_packets = df_packets.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Packets CSV",
                data=csv_packets,
                file_name="streamsight_packets.csv",
                mime="text/csv"
            )
    
    with col2:
        if not df_delays.empty:
            csv_delays = df_delays.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Delays CSV",
                data=csv_delays,
                file_name="streamsight_delays.csv",
                mime="text/csv"
            )
    
    with col3:
        if not df_retrans.empty:
            csv_retrans = df_retrans.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Retransmissions CSV",
                data=csv_retrans,
                file_name="streamsight_retransmissions.csv",
                mime="text/csv"
            )