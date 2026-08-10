"""Shared fixtures and the --run-slow option.

The two capture files under ``fixtures/`` are small enough to version and are
deliberately chosen: ``mqtt_delays.pcapng`` is a pure IPv6 (``::1``) capture, so
it is the natural regression guard for IPv6 address extraction.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def pytest_addoption(parser):
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="run tests against the full 13 MB capture (takes several minutes)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: needs the full capture; minutes to run")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-slow"):
        return
    skip_slow = pytest.mark.skip(reason="needs --run-slow")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)


def _fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"fixture {name} not available")
    return path


@pytest.fixture(scope="session")
def ipv6_capture():
    """An MQTT-over-IPv6-loopback capture (all addresses are ``::1``)."""
    return _fixture("mqtt_delays.pcapng")


@pytest.fixture(scope="session")
def ipv4_capture():
    """An MQTT-over-IPv4 capture using QoS 0 publishes."""
    return _fixture("mqtt_packets.pcapng")


@pytest.fixture(scope="session")
def parsed_ipv6(ipv6_capture):
    from pcap_parser import parse_pcap
    return parse_pcap(ipv6_capture)


@pytest.fixture(scope="session")
def parsed_ipv4(ipv4_capture):
    from pcap_parser import parse_pcap
    return parse_pcap(ipv4_capture)
