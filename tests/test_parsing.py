"""End-to-end parsing against the bundled captures.

Skipped automatically when tshark is unavailable.
"""

import shutil

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None, reason="tshark is not installed or not on PATH"
)


def test_ipv6_addresses_are_extracted(parsed_ipv6):
    """IPv6 packets must carry real addresses.

    Checking only for an ``ip`` layer leaves every IPv6 packet with src_ip=None,
    which then falls back to a per-packet connection key and destroys the
    connection grouping that every TCP metric depends on.
    """
    df_packets = parsed_ipv6[0]

    assert not df_packets.empty
    addresses = set(df_packets["src_ip"].astype(str))
    assert "None" not in addresses
    assert "::1" in addresses


def test_ipv6_traffic_groups_into_few_connections(parsed_ipv6):
    """A capture of a handful of conversations must not yield one per packet."""
    df_tcp = parsed_ipv6[3]

    assert not df_tcp.empty
    assert df_tcp["conn_id"].nunique() < 10
    assert df_tcp["conn_id"].nunique() < len(df_tcp)


def test_ipv6_capture_produces_rtt_and_ack_delay(parsed_ipv6):
    df_tcp = parsed_ipv6[3]

    assert df_tcp["rtt"].notna().any()
    assert df_tcp["ack_delay"].notna().any()


def test_tcp_flags_are_parsed(parsed_ipv6):
    """Flags render as "True"/"False" on modern tshark, not "1"/"0".

    Testing only for "1" makes every flag read as unset, which silently disables
    handshake detection and ACK pairing.
    """
    df_tcp = parsed_ipv6[3]

    assert df_tcp["flags_ack"].sum() > 0
    assert df_tcp["flags_syn"].sum() > 0


def test_qos0_messages_get_distinct_ids(parsed_ipv4):
    """QoS 0 publishes carry no msgid and must not collapse into one bucket."""
    df_mqtt = parsed_ipv4[5]

    assert not df_mqtt.empty
    assert df_mqtt["msg_id"].nunique() > 2


def test_mqtt_rows_are_labelled_mqtt(parsed_ipv4):
    """The protocol label must not be the stale transport-layer value."""
    df_mqtt = parsed_ipv4[5]
    assert set(df_mqtt["protocol"].unique()) == {"MQTT"}


def test_retransmission_frame_uses_time_column(parsed_ipv4):
    """The timeline tab reads this column by name; renaming it silently breaks it."""
    df_retrans = parsed_ipv4[2]
    assert list(df_retrans.columns) == ["time", "event"]


def test_parse_twice_in_one_process(ipv4_capture):
    """A second parse must not inherit a closed event loop from the first."""
    from pcap_parser import parse_pcap

    first = parse_pcap(ipv4_capture)
    second = parse_pcap(ipv4_capture)
    assert len(first[0]) == len(second[0])
