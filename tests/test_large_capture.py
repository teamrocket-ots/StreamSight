"""Regression checks against the full 13 MB capture, cross-checked with tshark.

Skipped by default: the capture is too large to version, and parsing it takes
minutes. Run explicitly with::

    pytest tests/test_large_capture.py --run-slow

Ground truth was established with tshark:

    tshark -r <capture> -Y "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"
    tshark -r <capture> -q -z conv,tcp
    tshark -r <capture> -Y "tcp.analysis.zero_window"

Note the retransmission filter is a *union*, not a sum: tshark also flags fast
and spurious retransmissions as plain retransmissions, so adding the individual
counts double-counts the same packets.
"""

import os
import shutil

import pytest

from pcap_parser import PROTO_MQTT_TLS

CAPTURE_NAME = "20_11_24_bro_rpi_10ms_2min.pcapng"
CAPTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), CAPTURE_NAME
)

# Verified against tshark on this capture.
EXPECTED_RETRANSMISSIONS = 31
EXPECTED_TCP_CONVERSATIONS = 4
EXPECTED_ZERO_WINDOW = 32
EXPECTED_DUPLICATE_ACK = 23
EXPECTED_WINDOW_FULL = 4
EXPECTED_IPV6_FRAMES = 13607

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        shutil.which("tshark") is None, reason="tshark is not installed or not on PATH"
    ),
    pytest.mark.skipif(
        not os.path.exists(CAPTURE_PATH), reason=f"{CAPTURE_NAME} not present"
    ),
]


@pytest.fixture(scope="module")
def parsed_large():
    from pcap_parser import parse_pcap
    return parse_pcap(CAPTURE_PATH)


def test_retransmissions_are_not_double_counted(parsed_large):
    """Previously reported 61 for a capture with 31 retransmitted packets."""
    df_retrans = parsed_large[2]
    assert len(df_retrans) == EXPECTED_RETRANSMISSIONS


def test_connections_match_tshark_conversation_count(parsed_large):
    """Previously 13,606, because IPv6 packets each became their own connection."""
    df_tcp = parsed_large[3]
    assert df_tcp["conn_id"].nunique() == EXPECTED_TCP_CONVERSATIONS


def test_no_addresses_are_lost(parsed_large):
    df_packets = parsed_large[0]
    assert (df_packets["src_ip"].astype(str) == "None").sum() == 0


def test_ipv6_frames_are_present(parsed_large):
    df_packets = parsed_large[0]
    assert (df_packets["ip_version"] == 6).sum() == EXPECTED_IPV6_FRAMES


def test_health_signals_match_tshark(parsed_large):
    df_tcp = parsed_large[3]
    assert int(df_tcp["zero_window"].sum()) == EXPECTED_ZERO_WINDOW
    assert int(df_tcp["duplicate_ack"].sum()) == EXPECTED_DUPLICATE_ACK
    assert int(df_tcp["window_full"].sum()) == EXPECTED_WINDOW_FULL


def test_rtt_and_ack_delay_are_populated(parsed_large):
    """Both were structurally impossible to compute before."""
    df_tcp = parsed_large[3]
    assert df_tcp["rtt"].notna().sum() > 20000
    assert df_tcp["ack_delay"].notna().sum() > 20000


def test_no_mqtt_claimed_in_a_capture_without_mqtt(parsed_large):
    """tshark reports 0 mqtt frames; the 8883 traffic is TLS and must be labelled so."""
    df_packets, df_mqtt = parsed_large[0], parsed_large[5]

    assert df_mqtt.empty
    assert PROTO_MQTT_TLS in set(df_packets["protocol"])
    assert "MQTT" not in set(df_packets["protocol"])
