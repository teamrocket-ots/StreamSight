"""Analysis helpers, binning and the UDP heuristics.

Each test corresponds to a crash or a fabricated statistic reproduced against
the original implementation.
"""

import numpy as np
import pandas as pd
import pytest

from analysis import (
    analyze_tcp_delays,
    analyze_udp_delays,
    categorize_delays,
    compute_retransmission_rate,
    safe_cut,
)
from pcap_parser import (
    MAX_INFERRED_LOSS,
    PROTO_MQTT_TLS,
    MIN_UDP_SAMPLES,
    calculate_udp_metrics,
    ensure_dataframe_types,
)
from visualizations import hist_with_boundaries


def _delay_frame(values):
    return pd.DataFrame({
        "device_to_broker_delay": values,
        "broker_processing_delay": values,
        "cloud_upload_delay": values,
        "total_delay": [v * 3 for v in values],
    })


def test_categorize_delays_survives_skewed_data():
    """Right-skewed delay is the normal shape; mean/std bins go non-monotonic on it.

    Previously raised ValueError: bins must increase monotonically.
    """
    df = _delay_frame([0.01] * 20 + [5.0])
    result = categorize_delays(df)
    assert "device_to_broker_delay_category" in result.columns


def test_categorize_delays_survives_uniform_data():
    """Identical values collapse the bin edges to a single point."""
    result = categorize_delays(_delay_frame([0.05] * 10))
    assert "device_to_broker_delay_category" in result.columns


def test_safe_cut_handles_constant_series():
    """Previously raised ValueError: Bin edges must be unique."""
    result = safe_cut(pd.Series([0.0] * 5))
    assert result.isna().all()


def test_safe_cut_handles_empty_and_nan():
    assert safe_cut(pd.Series([], dtype=float)).empty
    assert safe_cut(pd.Series([np.nan, np.nan])).isna().all()


def test_analyze_udp_delays_survives_zero_jitter():
    """Timer-driven telemetry produces perfectly uniform spacing."""
    df = pd.DataFrame({
        "conn_id": ["a"] * 5,
        "jitter": [0.0] * 5,
        "ipd": [10.0] * 5,
        "congestion_score": [0.0] * 5,
        "possible_loss": [0] * 5,
    })
    result, stats = analyze_udp_delays(df)
    assert "jitter_category" in result.columns
    assert stats


def test_analyze_functions_always_return_a_tuple():
    """Callers unpack two values; a bare frame on the empty branch is a crash."""
    empty = pd.DataFrame()
    assert isinstance(analyze_udp_delays(empty), tuple)
    assert isinstance(analyze_tcp_delays(empty), tuple)


def test_histogram_survives_all_nan_column():
    """Previously raised ValueError: cannot convert float NaN to integer."""
    fig = hist_with_boundaries(pd.DataFrame({"x": [np.nan, np.nan]}), "x", "title")
    assert fig is not None


def test_histogram_survives_single_valued_column():
    fig = hist_with_boundaries(pd.DataFrame({"x": [1.0, 1.0, 1.0]}), "x", "title")
    assert fig is not None


def test_nan_boolean_does_not_become_true():
    """A bare astype(bool) turns NaN into True, inventing retransmissions."""
    df = ensure_dataframe_types(pd.DataFrame({"is_retrans": [True, np.nan, False]}))
    assert list(df["is_retrans"]) == [True, False, False]


def test_retransmission_rate_uses_tcp_denominator():
    """Overview and the TCP tab must report the same number."""
    packets = pd.DataFrame({"protocol": ["TCP"] * 50 + ["UDP"] * 50})
    retrans = pd.DataFrame({"time": [0.0] * 5, "event": ["r"] * 5})
    assert compute_retransmission_rate(packets, retrans) == pytest.approx(10.0)


def test_retransmission_rate_counts_mqtt_as_tcp():
    packets = pd.DataFrame({"protocol": ["MQTT"] * 50 + [PROTO_MQTT_TLS] * 50})
    retrans = pd.DataFrame({"time": [0.0] * 10, "event": ["r"] * 10})
    assert compute_retransmission_rate(packets, retrans) == pytest.approx(10.0)


def _udp_flow(count, spacing=0.01):
    return [
        {
            "packet_id": i,
            "timestamp": 1000.0 + i * spacing,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "UDP",
            "src_port": 5004,
            "dst_port": 5004,
            "payload_size": 200,
            "conn_id": "udp-0",
            "conn_label": "flow",
            "is_multicast": False,
            "seq_num": None,
        }
        for i in range(count)
    ]


def test_short_udp_flow_is_flagged_not_measured():
    """A two-packet DNS exchange cannot support a jitter or loss estimate."""
    df = calculate_udp_metrics({"udp-0": _udp_flow(2)})

    assert df["insufficient_samples"].all()
    assert "jitter" not in df.columns or df["jitter"].isna().all()
    assert "possible_loss" not in df.columns or df["possible_loss"].fillna(0).sum() == 0


def test_sufficient_udp_flow_is_measured():
    df = calculate_udp_metrics({"udp-0": _udp_flow(MIN_UDP_SAMPLES + 10)})

    assert not df["insufficient_samples"].any()
    assert df["jitter"].notna().any()


def test_udp_jitter_starts_from_zero():
    """RFC 3550 seeds the jitter estimator at 0, not at the first delta."""
    df = calculate_udp_metrics({"udp-0": _udp_flow(20)})
    jitter = df["jitter"].dropna()
    assert jitter.iloc[0] >= 0
    # Perfectly uniform spacing means the estimator must converge on ~0.
    assert jitter.iloc[-1] == pytest.approx(0.0, abs=1e-6)


def test_udp_durations_in_milliseconds():
    df = calculate_udp_metrics({"udp-0": _udp_flow(10, spacing=0.05)})
    assert df["ipd"].dropna().iloc[0] == pytest.approx(50.0)


def test_bursty_flow_does_not_fabricate_loss():
    """A near-zero median IPD must not turn one idle gap into thousands of losses.

    Reproduced on a real 49-packet H.263-over-RTP capture, where fragmented video
    frames arrive back-to-back (median IPD 0.016 ms) and a single 324 ms gap was
    reported as 20,137 lost packets.
    """
    packets = _udp_flow(30, spacing=0.00002)  # back-to-back burst
    packets.append({**packets[-1], "packet_id": 99, "timestamp": packets[-1]["timestamp"] + 0.5})
    df = calculate_udp_metrics({"udp-0": packets})

    inferred = df["possible_loss"].fillna(0).max() if "possible_loss" in df.columns else 0
    assert inferred <= MAX_INFERRED_LOSS
    assert inferred < len(packets), "inferred loss exceeded the size of the capture"


def test_sequence_numbers_take_priority_over_timing_gaps():
    """With sequence numbers present and contiguous, loss must be reported as zero."""
    packets = _udp_flow(30, spacing=0.00002)
    for i, pkt in enumerate(packets):
        pkt["seq_num"] = 500 + i
    packets.append({
        **packets[-1], "packet_id": 99,
        "timestamp": packets[-1]["timestamp"] + 0.5, "seq_num": 530,
    })
    df = calculate_udp_metrics({"udp-0": packets})

    assert df["possible_loss"].fillna(0).sum() == 0


def test_sequence_loss_is_detected_and_wraparound_safe():
    packets = _udp_flow(10)
    for i, pkt in enumerate(packets):
        pkt["seq_num"] = 65530 + i  # wraps past 65535 partway through
    packets[5]["seq_num"] = (packets[4]["seq_num"] + 4) % 65536  # a real 3-packet gap
    df = calculate_udp_metrics({"udp-0": packets})

    losses = df["seq_loss"].fillna(0)
    assert losses.sum() == 3, "wraparound must not be counted as a 65,000-packet loss"


def test_congestion_score_is_bounded():
    packets = _udp_flow(30, spacing=0.00002)
    packets.append({**packets[-1], "packet_id": 99, "timestamp": packets[-1]["timestamp"] + 0.5})
    df = calculate_udp_metrics({"udp-0": packets})

    if "congestion_score" in df.columns:
        assert df["congestion_score"].dropna().max() <= 1.0


def test_delay_over_time_always_returns_a_pair():
    """Callers unpack two values; a bare figure on the empty path is a crash."""
    from visualizations import delay_over_time

    for frame in (
        pd.DataFrame(),
        pd.DataFrame({"timestamp": [1.0], "rtt": [np.nan]}),
        pd.DataFrame({"timestamp": [1.0, 2.0], "rtt": [1.0, 2.0]}),
    ):
        result = delay_over_time(frame, "rtt", "RTT")
        assert isinstance(result, tuple) and len(result) == 2


def test_endpoint_labels_are_shortened_for_legends():
    """IPv6 endpoint pairs run ~70 chars and destroy chart layout unshortened."""
    from visualizations import shorten_endpoint

    long_label = (
        "2402:8100:2a50:185a:241d:5a85:9efb:c8b4:5900 - "
        "2402:8100:2a50:185a:91ff:8485:e832:c46d:58964"
    )
    short = shorten_endpoint(long_label)
    assert len(short) < len(long_label) / 2
    assert "→" in short
    # A short label is left intact.
    assert shorten_endpoint("10.0.0.1:80 - 10.0.0.2:90") == "10.0.0.1:80 → 10.0.0.2:90"
