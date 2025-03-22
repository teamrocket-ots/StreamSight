import streamlit as st
import pandas as pd


def show_search_tab(df_packets, df_delays):
    """
    Display search and filter functionality for packet and delay data
    """
    st.header("Search & Filter")
    st.markdown("""
    Narrow down your analysis by filtering on **protocol, IP, or port**. 
    Identify specific communication flows to pinpoint performance bottlenecks.
    """)

    # Get user input
    filter_proto = st.text_input("Protocol (MQTT/TCP/UDP) to filter", "")
    filter_ip = st.text_input("IP (src or dst) to filter", "")
    filter_port = st.text_input("Port (src or dst) to filter", "")

    # Apply filters to packets
    if not df_packets.empty:
        filtered_df = df_packets.copy()
        if filter_proto.strip():
            filtered_df = filtered_df[filtered_df["protocol"].str.contains(filter_proto.strip(), case=False, na=False)]
        if filter_ip.strip():
            # match if src_ip or dst_ip has that substring
            mask_ip = filtered_df["src_ip"].str.contains(filter_ip.strip(), na=False) | \
                    filtered_df["dst_ip"].str.contains(filter_ip.strip(), na=False)
            filtered_df = filtered_df[mask_ip]
        if filter_port.strip():
            # match if src_port or dst_port
            mask_port = filtered_df["src_port"].astype(str).str.contains(filter_port.strip()) | \
                        filtered_df["dst_port"].astype(str).str.contains(filter_port.strip())
            filtered_df = filtered_df[mask_port]

        # Display filtered results
        st.write(f"Filtered Packet Count: {len(filtered_df)}")
        st.dataframe(filtered_df)
    else:
        st.info("No packet data available to filter.")
    
    # Add filter for delay types
    st.subheader("Delay Filtering")
    
    if not df_delays.empty:
        delay_filter_options = st.multiselect(
            "Filter by Delay Categories", 
            ["Low", "Normal", "High", "Very High"],
            default=["High", "Very High"]
        )
        
        delay_type_options = [col for col in df_delays.columns if col.endswith("_delay") and not col.endswith("_category")]
        delay_type_filter = st.selectbox(
            "Select Delay Type to Filter",
            delay_type_options,
            index=0 if delay_type_options else None
        )
        
        if delay_filter_options and delay_type_filter:
            category_col = f"{delay_type_filter}_category"
            if category_col in df_delays.columns:
                filtered_delays = df_delays[df_delays[category_col].isin(delay_filter_options)]
                st.write(f"Found {len(filtered_delays)} messages with {delay_type_filter.replace('_', ' ')} in categories: {', '.join(delay_filter_options)}")
                
                # Determine display columns based on what's available
                display_cols = ["msg_id", delay_type_filter, category_col]
                if "bottleneck" in df_delays.columns:
                    display_cols.append("bottleneck")
                if "is_anomaly" in df_delays.columns:
                    display_cols.append("is_anomaly")
                
                st.dataframe(filtered_delays[display_cols])
            else:
                st.warning(f"Category column '{category_col}' not found. Run categorize_delays() first.")
    else:
        st.info("No delay data available to filter.")