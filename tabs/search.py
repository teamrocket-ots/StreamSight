import pandas as pd
import streamlit as st

DELAY_CATEGORIES = ["Low", "Normal", "High", "Very High"]


def show_search_tab(df_packets, df_delays):
    """Filter packets by protocol, address or port, and delays by category."""
    st.subheader("Search & Filter")
    st.markdown(
        "Narrow the analysis by **protocol, IP, or port** to isolate a specific flow."
    )

    _show_packet_filters(df_packets)
    st.divider()
    _show_delay_filters(df_delays)


def _show_packet_filters(df_packets):
    if df_packets is None or df_packets.empty:
        st.info("No packet data available to filter.")
        return

    protocols = sorted(df_packets["protocol"].dropna().unique()) \
        if "protocol" in df_packets.columns else []

    col1, col2, col3 = st.columns(3)
    selected_protocols = col1.multiselect("Protocol", protocols, default=[])
    filter_ip = col2.text_input("IP contains (source or destination)", "")
    filter_port = col3.text_input("Port (source or destination)", "")

    filtered = df_packets
    if selected_protocols:
        filtered = filtered[filtered["protocol"].isin(selected_protocols)]

    if filter_ip.strip():
        needle = filter_ip.strip()
        mask = pd.Series(False, index=filtered.index)
        for column in ("src_ip", "dst_ip"):
            if column in filtered.columns:
                mask |= filtered[column].astype(str).str.contains(needle, case=False, na=False)
        filtered = filtered[mask]

    if filter_port.strip():
        # Ports are numeric, so match on the value rather than a substring of its
        # string form -- "88" should not match port 8883.
        try:
            port = int(filter_port.strip())
        except ValueError:
            st.warning("Port filter must be a number.")
            port = None
        if port is not None:
            mask = pd.Series(False, index=filtered.index)
            for column in ("src_port", "dst_port"):
                if column in filtered.columns:
                    mask |= pd.to_numeric(filtered[column], errors="coerce") == port
            filtered = filtered[mask]

    st.write(f"Matching packets: **{len(filtered)}** of {len(df_packets)}")
    st.dataframe(filtered, use_container_width=True)

    if not filtered.empty:
        st.download_button(
            "Download filtered packets (CSV)",
            filtered.to_csv(index=False).encode("utf-8"),
            file_name="streamsight_filtered_packets.csv",
            mime="text/csv",
        )


def _show_delay_filters(df_delays):
    st.subheader("Delay Filtering")

    if df_delays is None or df_delays.empty:
        st.info("No delay data available to filter.")
        return

    delay_types = [
        col for col in df_delays.columns
        if col.endswith("_delay") and not col.endswith("_category")
    ]
    if not delay_types:
        st.info("No delay columns available to filter.")
        return

    col1, col2 = st.columns(2)
    delay_type = col1.selectbox("Delay type", delay_types)
    categories = col2.multiselect(
        "Categories", DELAY_CATEGORIES, default=["High", "Very High"]
    )

    category_col = f"{delay_type}_category"
    if category_col not in df_delays.columns:
        st.warning(
            f"'{delay_type}' has not been categorised. Open the Insights tab first, "
            "which computes the categories."
        )
        return

    if not categories:
        st.info("Select at least one category.")
        return

    filtered = df_delays[df_delays[category_col].isin(categories)]
    st.write(
        f"Found **{len(filtered)}** messages with "
        f"{delay_type.replace('_', ' ')} in: {', '.join(categories)}"
    )

    display_cols = [c for c in ("msg_id", delay_type, category_col, "bottleneck", "is_anomaly")
                    if c in filtered.columns]
    st.dataframe(filtered[display_cols], use_container_width=True)
