"""The fast tshark reader and the PyShark reader must agree.

The fast path only pays off if it is a drop-in replacement, so these compare the
two backends field by field on real captures.
"""

import shutil

import pandas as pd
import pytest

from pcap_parser import parse_pcap

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None, reason="tshark is not installed or not on PATH"
)

FRAME_NAMES = ["packets", "delays", "retrans", "tcp", "udp", "mqtt"]


@pytest.fixture(scope="module")
def both_backends(request):
    path = request.param if hasattr(request, "param") else None
    return path


def _compare(capture):
    fast = parse_pcap(capture, backend="tshark")
    slow = parse_pcap(capture, backend="pyshark")
    return fast, slow


@pytest.mark.parametrize("capture_fixture", ["ipv4_capture", "ipv6_capture"])
def test_backends_agree_on_row_counts(capture_fixture, request):
    capture = request.getfixturevalue(capture_fixture)
    fast, slow = _compare(capture)

    for name, fast_df, slow_df in zip(FRAME_NAMES, fast, slow):
        assert len(fast_df) == len(slow_df), f"{name} row count differs"


@pytest.mark.parametrize("capture_fixture", ["ipv4_capture", "ipv6_capture"])
def test_backends_agree_on_packet_fields(capture_fixture, request):
    capture = request.getfixturevalue(capture_fixture)
    fast, slow = _compare(capture)

    columns = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    pd.testing.assert_frame_equal(
        fast[0][columns].reset_index(drop=True),
        slow[0][columns].reset_index(drop=True),
        check_dtype=False,
    )


@pytest.mark.parametrize("capture_fixture", ["ipv4_capture", "ipv6_capture"])
def test_backends_agree_on_tcp_metrics(capture_fixture, request):
    capture = request.getfixturevalue(capture_fixture)
    fast, slow = _compare(capture)
    fast_tcp, slow_tcp = fast[3], slow[3]

    assert fast_tcp["conn_id"].nunique() == slow_tcp["conn_id"].nunique()

    for column in ("rtt", "ack_delay", "ipd", "jitter", "payload_size", "seq_num"):
        if column in fast_tcp.columns and column in slow_tcp.columns:
            pd.testing.assert_series_equal(
                fast_tcp[column].reset_index(drop=True),
                slow_tcp[column].reset_index(drop=True),
                check_dtype=False,
                check_names=False,
            )


@pytest.mark.parametrize("capture_fixture", ["ipv4_capture", "ipv6_capture"])
def test_backends_agree_on_flags_and_health(capture_fixture, request):
    capture = request.getfixturevalue(capture_fixture)
    fast, slow = _compare(capture)
    fast_tcp, slow_tcp = fast[3], slow[3]

    for column in ("flags_syn", "flags_ack", "flags_rst", "flags_fin",
                   "is_retrans", "zero_window", "duplicate_ack", "window_full"):
        assert int(fast_tcp[column].sum()) == int(slow_tcp[column].sum()), column


def test_backends_agree_on_mqtt_message_keys(ipv4_capture):
    fast, slow = _compare(ipv4_capture)
    assert fast[5]["msg_id"].nunique() == slow[5]["msg_id"].nunique()
    assert set(fast[5]["msg_type_name"]) == set(slow[5]["msg_type_name"])


def test_explicit_backend_selection_is_honoured(ipv4_capture):
    """A bad backend name must fail loudly rather than silently picking one."""
    with pytest.raises(ValueError):
        parse_pcap(ipv4_capture, backend="nonsense")
