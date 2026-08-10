"""TCP metric computation.

Every test here corresponds to a bug that was reproduced against the real code:
RTT and ACK delay were structurally impossible to compute, retransmissions were
counted twice, and TCP flags never parsed at all.
"""

from collections import defaultdict

import pytest

from pcap_parser import calculate_tcp_metrics


def _packet(timestamp, from_client, seq, ack, syn=0, ack_flag=1, payload=0, retrans=False):
    return {
        "packet_id": 0,
        "timestamp": timestamp,
        "src_ip": "10.0.0.1" if from_client else "10.0.0.2",
        "dst_ip": "10.0.0.2" if from_client else "10.0.0.1",
        "protocol": "TCP",
        "src_port": 5000 if from_client else 8883,
        "dst_port": 8883 if from_client else 5000,
        "seq_num": seq,
        "ack_num": ack,
        "flags_syn": syn,
        "flags_ack": ack_flag,
        "flags_rst": 0,
        "flags_fin": 0,
        "payload_size": payload,
        "is_retrans": retrans,
        "ack_rtt": float("nan"),
        "conn_id": "tcp-0",
        "conn_label": "10.0.0.1:5000 - 10.0.0.2:8883",
    }


@pytest.fixture
def handshake_connection():
    """SYN -> SYN/ACK -> data -> ACK, both directions in one stream."""
    packets = [
        _packet(0.00, True, 0, 0, syn=1, ack_flag=0),
        _packet(0.05, False, 0, 1, syn=1),
        _packet(0.10, True, 1, 1, payload=10),
        _packet(0.13, False, 1, 11),
    ]
    return defaultdict(list, {"tcp-0": packets})


def test_handshake_rtt_is_measured(handshake_connection):
    """Both directions must share a connection key, or RTT can never be computed.

    Keying on "src:sport-dst:dport" puts the SYN and the SYN/ACK in separate
    buckets, so the column was absent entirely rather than merely empty.
    """
    df = calculate_tcp_metrics(handshake_connection)

    assert "handshake_rtt" in df.columns
    measured = df["handshake_rtt"].dropna()
    assert len(measured) == 1
    assert measured.iloc[0] == pytest.approx(50.0)  # 0.05 s -> 50 ms


def test_ack_delay_is_measured(handshake_connection):
    """ACK delay pairs a data segment with the peer's acknowledgement."""
    df = calculate_tcp_metrics(handshake_connection)

    assert "ack_delay" in df.columns
    measured = df["ack_delay"].dropna()
    assert len(measured) == 1
    assert measured.iloc[0] == pytest.approx(30.0)  # 0.03 s -> 30 ms


def test_durations_are_reported_in_milliseconds(handshake_connection):
    """A 50 ms gap must read as 50.0, not 0.05."""
    df = calculate_tcp_metrics(handshake_connection)
    assert df["ipd"].dropna().iloc[0] == pytest.approx(50.0)


def test_ack_delay_matches_cumulatively():
    """One ACK covering several segments must resolve all of them.

    Requiring ack_num == seq + len exactly misses most acknowledgements once TCP
    reassembly coalesces segments.
    """
    packets = [
        _packet(0.00, True, 1, 1, payload=100),
        _packet(0.01, True, 101, 1, payload=100),
        _packet(0.05, False, 1, 201),  # single ACK covering both segments
    ]
    df = calculate_tcp_metrics(defaultdict(list, {"tcp-0": packets}))

    measured = df["ack_delay"].dropna()
    assert len(measured) == 2


def test_retransmission_is_not_double_counted():
    """A retransmitted packet must appear once in the metric frame."""
    packets = [
        _packet(0.00, True, 1, 1, payload=50),
        _packet(0.20, True, 1, 1, payload=50, retrans=True),
    ]
    df = calculate_tcp_metrics(defaultdict(list, {"tcp-0": packets}))
    assert int(df["is_retrans"].sum()) == 1


def test_retransmission_delay_measured_per_direction():
    packets = [
        _packet(0.00, True, 1, 1, payload=50),
        _packet(0.20, True, 1, 1, payload=50, retrans=True),
    ]
    df = calculate_tcp_metrics(defaultdict(list, {"tcp-0": packets}))
    assert df["retrans_delay"].dropna().iloc[0] == pytest.approx(200.0)


def test_empty_input_returns_empty_frame():
    assert calculate_tcp_metrics({}).empty


def test_retransmission_delay_only_on_actual_retransmissions():
    """Bare ACKs share a sequence number and must not be paired as retransmissions.

    An ACK carries no payload and does not advance the sender's sequence number,
    so every ACK in a flow has the same seq_num. Matching on seq_num alone paired
    unrelated ACKs and reported the gap between them as a retransmission delay --
    producing 37 values, averaging 11 seconds, on a capture with zero
    retransmissions.
    """
    packets = [
        _packet(0.00, True, 1, 1, payload=10),
        _packet(0.10, False, 1, 11),   # bare ACK
        _packet(5.00, False, 1, 11),   # another bare ACK, same seq_num
        _packet(60.0, False, 1, 11),   # and another, a minute later
    ]
    df = calculate_tcp_metrics(defaultdict(list, {"tcp-0": packets}))

    measured = df["retrans_delay"].dropna() if "retrans_delay" in df.columns else []
    assert len(measured) == 0, "no packet here is a retransmission"


def test_retransmission_delay_measured_from_the_original():
    packets = [
        _packet(0.00, True, 1, 1, payload=50),
        _packet(0.05, False, 1, 51),                      # ACK, must be ignored
        _packet(0.30, True, 1, 1, payload=50, retrans=True),
    ]
    df = calculate_tcp_metrics(defaultdict(list, {"tcp-0": packets}))

    measured = df["retrans_delay"].dropna()
    assert len(measured) == 1
    assert measured.iloc[0] == pytest.approx(300.0)
