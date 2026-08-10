import streamlit as st


def show_explorer_tab(df_packets, df_delays, df_retrans, df_tcp=None, df_udp=None):
    """Raw data tables with CSV export."""
    st.subheader("Raw Tables")

    frames = [
        ("Packets", df_packets, "streamsight_packets.csv"),
        ("TCP Metrics", df_tcp, "streamsight_tcp.csv"),
        ("UDP Metrics", df_udp, "streamsight_udp.csv"),
        ("MQTT Delays", df_delays, "streamsight_delays.csv"),
        ("Retransmissions", df_retrans, "streamsight_retransmissions.csv"),
    ]

    for label, df, filename in frames:
        if df is None:
            continue

        st.subheader(label)
        if df.empty:
            st.info(f"No {label.lower()} data available.")
            continue

        st.caption(f"{len(df):,} rows x {len(df.columns)} columns")
        with st.expander(f"View {label.lower()}", expanded=(label == "Packets")):
            st.dataframe(df, use_container_width=True)

        st.download_button(
            label=f"Download {label} CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=filename,
            mime="text/csv",
            key=f"download_{filename}",
        )
