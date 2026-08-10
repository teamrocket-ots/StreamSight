"""Small Streamlit helpers that keep the app working across Streamlit versions.

Streamlit replaced ``use_container_width=True`` with ``width="stretch"``. The
old argument was scheduled for removal after 2025-12-31 and now emits a
deprecation warning on every call, which on a chart-heavy page means hundreds of
lines of log noise per page load.

The two arguments cannot simply be swapped, because the versions do not overlap:
Streamlit 1.43 has no ``width`` parameter on ``plotly_chart`` at all, while 1.61
deprecates ``use_container_width``. Passing the wrong one raises on one version
or warns on the other, so which to use is decided once, here, from the running
version rather than hardcoded.
"""

import inspect

import streamlit as st

#: Streamlit grew a ``width`` parameter on plotly_chart in the same release
#: series that deprecated use_container_width, so its presence is a reliable
#: signal for which argument this version wants.
_SUPPORTS_WIDTH = "width" in inspect.signature(st.plotly_chart).parameters

#: Spread with ** at call sites: ``st.plotly_chart(fig, **STRETCH)``.
STRETCH = {"width": "stretch"} if _SUPPORTS_WIDTH else {"use_container_width": True}


def compact_count(value):
    """Abbreviate a count so it fits a narrow column.

    The sidebar is about 300px wide and splits into two columns, which is not
    enough for ``st.metric`` to show "21,368" — it truncates to "21,...".
    """
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "N/A"

    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if abs(value) >= 10_000:
        return f"{value / 1_000:.0f}k"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.1f}k"
    return f"{value:,.0f}"


def compact_duration(seconds):
    """Abbreviate a duration in seconds for the same narrow columns."""
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "N/A"

    if seconds >= 3600:
        return f"{seconds / 3600:.1f}h"
    if seconds >= 60:
        return f"{seconds / 60:.1f}m"
    return f"{seconds:.0f}s"
