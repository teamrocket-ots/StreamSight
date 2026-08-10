"""Fast capture reader that drives ``tshark -T fields`` directly.

PyShark's default path deserialises tshark's full PDML (XML) for every packet,
building a Python object graph per layer. Almost all of that is discarded --
StreamSight reads about thirty fields. Asking tshark for exactly those fields as
tab-separated text removes both the XML generation and its parsing.

This module yields the same normalised row dicts as the PyShark path in
:mod:`pcap_parser`, so the two backends are interchangeable and can be compared
against each other (see ``tests/test_backends.py``).
"""

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)

#: Requested in this exact order; the output columns line up with it.
TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.flags.fin",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.ack_rtt",
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
    "udp.length",
    "rtp.seq",
    "mqtt.msgtype",
    "mqtt.msgid",
    "mqtt.qos",
    "tls.handshake.type",
    "tls.record.content_type",
]

FIELD_INDEX = {name: i for i, name in enumerate(TSHARK_FIELDS)}

SEPARATOR = "\t"
AGGREGATOR = ","

#: TLS record content type 22 is "handshake".
TLS_HANDSHAKE_CONTENT_TYPE = "22"

#: Boolean fields render as "True"/"False" on modern tshark and "1"/"0" on older
#: builds. Presence-only fields (the tcp.analysis.* flags) render as "1" or empty.
TRUTHY = {"1", "true", "True", "TRUE"}


class TSharkUnavailable(RuntimeError):
    """Raised when tshark cannot be located or refuses to run."""


def tshark_path():
    """Locate the tshark executable, preferring PyShark's configured path."""
    try:
        from pyshark.tshark.tshark import get_process_path
        return get_process_path()
    except Exception:
        path = shutil.which("tshark")
        if not path:
            raise TSharkUnavailable("tshark not found on PATH")
        return path


def tshark_version():
    """Return the installed tshark version string, or None if unavailable.

    Used to surface capture support in the UI. On a hosted deployment tshark is
    an OS package rather than a Python dependency, so it can be missing while
    everything else works -- without this the first sign of trouble is an
    upload failing.
    """
    try:
        path = tshark_path()
    except Exception:
        return None

    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None
    first_line = (result.stdout or "").strip().splitlines()
    return first_line[0] if first_line else "unknown version"


def _first(value):
    """First occurrence of a possibly multi-valued field.

    Fields are requested with ``occurrence=a`` so that a TCP segment carrying
    several MQTT messages yields all of their message types. Scalar fields can
    also repeat (reassembled segments), so everything except the MQTT fields
    takes the first value only.
    """
    if not value:
        return None
    return value.split(AGGREGATOR, 1)[0]


def _num(value, cast=int):
    raw = _first(value)
    if raw is None or raw == "":
        return None
    try:
        return cast(raw)
    except (ValueError, TypeError):
        return None


def _flag(value):
    return 1 if _first(value) in TRUTHY else 0


def _present(value):
    """True for a presence-only field such as ``tcp.analysis.zero_window``."""
    return bool(value)


def iter_rows(file_path, display_filter="mqtt or tcp or udp"):
    """Yield one normalised row dict per packet.

    Streams tshark's stdout, so memory stays flat regardless of capture size.
    """
    command = [
        tshark_path(),
        "-r", file_path,
        "-Y", display_filter,
        "-T", "fields",
        "-E", f"separator={SEPARATOR}",
        "-E", "occurrence=a",
        "-E", f"aggregator={AGGREGATOR}",
        "-E", "quote=n",
    ]
    for field in TSHARK_FIELDS:
        command += ["-e", field]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except (OSError, FileNotFoundError) as exc:
        raise TSharkUnavailable(f"could not launch tshark: {exc}") from exc

    expected = len(TSHARK_FIELDS)
    try:
        for packet_id, line in enumerate(process.stdout):
            values = line.rstrip("\n").split(SEPARATOR)
            if len(values) < expected:
                # A short row means a field was dropped; pad so indexing is safe.
                values += [""] * (expected - len(values))
            row = _build_row(values, packet_id)
            if row is not None:
                yield row
    finally:
        if process.stdout:
            process.stdout.close()
        stderr = process.stderr.read() if process.stderr else ""
        if process.stderr:
            process.stderr.close()
        code = process.wait()
        if code != 0:
            # tshark exits non-zero for an unreadable file, but also warns
            # noisily about truncated captures while still producing output.
            message = (stderr or "").strip().splitlines()
            detail = message[-1] if message else f"exit code {code}"
            raise TSharkUnavailable(f"tshark failed: {detail}")
        if stderr.strip():
            logger.debug("tshark stderr: %s", stderr.strip())


def _build_row(values, packet_id):
    """Normalise one tshark output line into the shared row shape."""
    def value(name):
        return values[FIELD_INDEX[name]]

    epoch = _first(value("frame.time_epoch"))
    if not epoch:
        return None
    try:
        timestamp = float(epoch)
    except ValueError:
        return None

    protocols = value("frame.protocols") or ""
    layers = set(protocols.split(":")) if protocols else set()

    src_ip = _first(value("ip.src"))
    dst_ip = _first(value("ip.dst"))
    ip_version = 4 if src_ip else None
    if src_ip is None:
        src_ip = _first(value("ipv6.src"))
        dst_ip = _first(value("ipv6.dst"))
        ip_version = 6 if src_ip else None

    has_tcp = "tcp" in layers
    has_udp = "udp" in layers and not has_tcp

    if has_tcp:
        src_port = _num(value("tcp.srcport"))
        dst_port = _num(value("tcp.dstport"))
    elif has_udp:
        src_port = _num(value("udp.srcport"))
        dst_port = _num(value("udp.dstport"))
    else:
        src_port = dst_port = None

    is_retrans = any(
        _present(value(field))
        for field in (
            "tcp.analysis.retransmission",
            "tcp.analysis.fast_retransmission",
            "tcp.analysis.spurious_retransmission",
        )
    )

    mqtt_types = [t for t in (value("mqtt.msgtype") or "").split(AGGREGATOR) if t]
    mqtt_ids = [i for i in (value("mqtt.msgid") or "").split(AGGREGATOR) if i]

    return {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "layers": layers,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_version": ip_version,
        "src_port": src_port,
        "dst_port": dst_port,
        "has_tcp": has_tcp,
        "has_udp": has_udp,
        "has_mqtt": "mqtt" in layers,
        "tcp_stream": _first(value("tcp.stream")),
        "seq_num": _num(value("tcp.seq")) or 0,
        "ack_num": _num(value("tcp.ack")) or 0,
        "payload_size": _num(value("tcp.len")) or 0,
        "flags_syn": _flag(value("tcp.flags.syn")),
        "flags_ack": _flag(value("tcp.flags.ack")),
        "flags_rst": _flag(value("tcp.flags.reset")),
        "flags_fin": _flag(value("tcp.flags.fin")),
        "is_retrans": is_retrans,
        "zero_window": _present(value("tcp.analysis.zero_window")),
        "window_full": _present(value("tcp.analysis.window_full")),
        "duplicate_ack": _present(value("tcp.analysis.duplicate_ack")),
        "out_of_order": _present(value("tcp.analysis.out_of_order")),
        "spurious_retrans": _present(value("tcp.analysis.spurious_retransmission")),
        "ack_rtt": _num(value("tcp.analysis.ack_rtt"), float),
        "udp_stream": _first(value("udp.stream")),
        "udp_length": _num(value("udp.length")),
        "rtp_seq": _num(value("rtp.seq")),
        "mqtt_types": mqtt_types,
        "mqtt_ids": mqtt_ids,
        "mqtt_qos": _num(value("mqtt.qos")) or 0,
        "is_tls_handshake": bool(value("tls.handshake.type"))
        or _first(value("tls.record.content_type")) == TLS_HANDSHAKE_CONTENT_TYPE,
    }
