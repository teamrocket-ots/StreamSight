"""Unit conversion constants shared across the parsing and analysis modules.

PyShark reports ``frame_info.time_epoch`` in **seconds**, so every delay derived
from a timestamp difference is a value in seconds. The UI presents delays in
milliseconds, so durations are converted once, at the point they are computed,
using :data:`SEC_TO_MS`.

Absolute timestamps are deliberately *not* converted: they stay in epoch seconds
so they can be handed to ``pd.to_datetime(..., unit='s')``.

This lives in its own module because ``pcap_parser`` imports ``data_generator``,
so placing the constant in either of them would create an import cycle.
"""

SEC_TO_MS = 1000.0
