"""Root-cause findings.

The tab reports problems rather than statistics, so the thing worth testing is
what it stays quiet about.
"""

import pandas as pd

from rootcause_analysis import MIN_SAMPLES_FOR_FINDING, RootCauseAnalysis


def _observations(delays, source="10.0.0.1", size=100):
    return pd.DataFrame({
        "delay": delays,
        "packet_size": [size] * len(delays),
        "protocol": ["TCP"] * len(delays),
        "source_ip": [source] * len(delays),
        "destination_ip": ["10.0.0.2"] * len(delays),
        "is_retrans": [False] * len(delays),
        "zero_window": [False] * len(delays),
    })


def test_healthy_traffic_reports_nothing():
    """Uniform, unremarkable delay should produce an empty findings list."""
    analysis = RootCauseAnalysis(_observations([20.0] * 50), kind="latency")
    assert analysis.findings() == []


def test_long_tail_is_reported_for_a_latency():
    delays = [1.0] * 95 + [500.0] * 5
    findings = RootCauseAnalysis(_observations(delays), kind="latency").findings()

    assert any(f["severity"] == "warn" and "Long tail" in f["title"] for f in findings)


def test_long_tail_is_not_an_alarm_for_a_cadence():
    """A quiet sender is not a slow sender.

    Inter-packet delay measures how often something sends. mDNS announcing every
    ten seconds has a huge tail and nothing is wrong with it.
    """
    delays = [1.0] * 95 + [500.0] * 5
    findings = RootCauseAnalysis(_observations(delays), kind="cadence").findings()

    assert all(f["severity"] != "warn" for f in findings)
    assert any("Irregular sending" in f["title"] for f in findings)


def test_slow_endpoint_is_reported_for_a_latency():
    fast = _observations([1.0] * 40, source="10.0.0.1")
    slow = _observations([100.0] * 40, source="10.0.0.9")
    combined = pd.concat([fast, slow], ignore_index=True)

    findings = RootCauseAnalysis(combined, kind="latency").findings()
    assert any("10.0.0.9" in f["title"] for f in findings)


def test_endpoints_are_not_ranked_for_a_cadence():
    """Ranking endpoints by sending gap would flag the least chatty as the worst."""
    chatty = _observations([1.0] * 40, source="10.0.0.1")
    quiet = _observations([100.0] * 40, source="10.0.0.9")
    combined = pd.concat([chatty, quiet], ignore_index=True)

    findings = RootCauseAnalysis(combined, kind="cadence").findings()
    assert not any("slower" in f["title"] for f in findings)


def test_tiny_samples_produce_no_findings():
    delays = [1.0, 900.0]
    assert len(delays) < MIN_SAMPLES_FOR_FINDING
    assert RootCauseAnalysis(_observations(delays), kind="latency").findings() == []


def test_correlation_is_reported_only_when_it_is_strong():
    sizes = list(range(1, 61))
    tracking = _observations([float(s) * 2 for s in sizes])
    tracking["packet_size"] = sizes

    findings = RootCauseAnalysis(tracking, kind="latency").findings()
    assert any("packet size" in f["title"] for f in findings)


def test_findings_have_the_expected_shape():
    delays = [1.0] * 95 + [500.0] * 5
    for finding in RootCauseAnalysis(_observations(delays), kind="latency").findings():
        assert set(finding) == {"severity", "title", "detail"}
        assert finding["severity"] in {"warn", "info"}
        assert finding["title"] and finding["detail"]
