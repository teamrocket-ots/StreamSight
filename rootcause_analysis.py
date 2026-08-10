"""Correlate measured delays against the packet attributes that might explain them.

All delays are in milliseconds (see :mod:`units`).
"""

import numpy as np
import pandas as pd

#: Packet-size buckets. Grouping by exact byte count produces one bucket per
#: distinct size, which is not a correlation -- it is a list.
SIZE_BINS = [-1, 0, 64, 256, 512, 1024, 1460, np.inf]
SIZE_LABELS = ["0 (control)", "1-64", "65-256", "257-512", "513-1024", "1025-1460", ">1460"]

REQUIRED_COLUMNS = [
    "delay", "packet_size", "protocol", "source_ip", "destination_ip",
]


class RootCauseAnalysis:
    """Summarise a set of delay observations and what correlates with them."""

    def __init__(self, records=None, metric="Delay", description=""):
        """Accepts a DataFrame of observations, or nothing to build one incrementally."""
        self.metric = metric
        self.description = description
        if records is None:
            self.df = pd.DataFrame(columns=REQUIRED_COLUMNS)
        elif isinstance(records, pd.DataFrame):
            self.df = records.copy()
        else:
            self.df = pd.DataFrame(list(records), columns=REQUIRED_COLUMNS)

    def add_record(self, delay, packet_size, protocol, source_ip, destination_ip):
        """Append a single observation. Kept for incremental/manual use."""
        row = {
            "delay": delay,
            "packet_size": packet_size,
            "protocol": protocol,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        }
        self.df = pd.concat([self.df, pd.DataFrame([row])], ignore_index=True)

    @property
    def records(self):
        """The observations as a list of dicts."""
        return self.df.to_dict("records")

    def compute_statistics(self):
        """Overall delay statistics in milliseconds."""
        if self.df.empty:
            return {"min_delay": 0.0, "max_delay": 0.0, "avg_delay": 0.0,
                    "median_delay": 0.0, "p95_delay": 0.0, "count": 0}

        delays = pd.to_numeric(self.df["delay"], errors="coerce").dropna()
        if delays.empty:
            return {"min_delay": 0.0, "max_delay": 0.0, "avg_delay": 0.0,
                    "median_delay": 0.0, "p95_delay": 0.0, "count": 0}

        return {
            "min_delay": float(delays.min()),
            "max_delay": float(delays.max()),
            "avg_delay": float(delays.mean()),
            "median_delay": float(delays.median()),
            "p95_delay": float(delays.quantile(0.95)),
            "count": int(delays.size),
        }

    def correlate_factors(self, top_n=10):
        """Mean delay grouped by each candidate explanatory factor."""
        if self.df.empty:
            return {"packet_size": {}, "protocol": {}, "source_ip": {}, "destination_ip": {}}

        df = self.df.copy()
        df["delay"] = pd.to_numeric(df["delay"], errors="coerce")
        df = df.dropna(subset=["delay"])
        if df.empty:
            return {"packet_size": {}, "protocol": {}, "source_ip": {}, "destination_ip": {}}

        df["size_bucket"] = pd.cut(
            pd.to_numeric(df["packet_size"], errors="coerce").fillna(0),
            bins=SIZE_BINS,
            labels=SIZE_LABELS,
        )

        def group_mean(column, limit=None):
            # A factor with only one distinct value explains nothing -- reporting
            # it just pads the output with a restatement of the overall mean.
            if df[column].nunique(dropna=True) < 2:
                return {}
            # Sample counts travel with the means: a bucket holding one outlier
            # otherwise reads exactly like a real trend.
            grouped = df.groupby(column, observed=True)["delay"].agg(["mean", "count"])
            grouped = grouped.sort_values("mean", ascending=False)
            if limit:
                grouped = grouped.head(limit)
            return {
                str(k): (float(row["mean"]), int(row["count"]))
                for k, row in grouped.iterrows()
            }

        return {
            "packet_size": group_mean("size_bucket"),
            "protocol": group_mean("protocol"),
            "source_ip": group_mean("source_ip", top_n),
            "destination_ip": group_mean("destination_ip", top_n),
        }

    def numeric_correlations(self):
        """Pearson correlation of delay against numeric attributes.

        A coefficient says whether a factor actually tracks delay; group means
        alone cannot distinguish a real relationship from an uneven sample.
        """
        if self.df.empty:
            return {}

        df = self.df.copy()
        df["delay"] = pd.to_numeric(df["delay"], errors="coerce")

        results = {}
        for column in ("packet_size", "is_retrans", "zero_window"):
            if column not in df.columns:
                continue
            series = pd.to_numeric(df[column], errors="coerce")
            paired = pd.concat([df["delay"], series], axis=1).dropna()
            if len(paired) < 3 or paired.iloc[:, 1].nunique() < 2:
                continue
            results[column] = float(paired.iloc[:, 0].corr(paired.iloc[:, 1]))
        return results

    def generate_report(self):
        """A plain-text summary of the delay statistics and correlations."""
        stats = self.compute_statistics()
        if not stats["count"]:
            return (
                f"=== {self.metric} ===\n"
                "No measurements available to analyse."
            )

        correlation = self.correlate_factors()
        numeric = self.numeric_correlations()

        lines = [
            f"=== {self.metric} ===",
            self.description,
            "",
            f"Observations: {stats['count']}",
            f"Min Delay:    {stats['min_delay']:.4f} ms",
            f"Max Delay:    {stats['max_delay']:.4f} ms",
            f"Avg Delay:    {stats['avg_delay']:.4f} ms",
            f"Median Delay: {stats['median_delay']:.4f} ms",
            f"95th pct:     {stats['p95_delay']:.4f} ms",
            "",
        ]

        if numeric:
            lines.append("--- Correlation Coefficients (Pearson, vs delay) ---")
            for factor, value in numeric.items():
                strength = _describe_correlation(value)
                lines.append(f"  {factor}: r = {value:+.3f}  ({strength})")
            lines.append("")

        for title, key in (
            ("Correlation by Packet Size", "packet_size"),
            ("Correlation by Protocol", "protocol"),
            ("Correlation by Source IP (top 10)", "source_ip"),
            ("Correlation by Destination IP (top 10)", "destination_ip"),
        ):
            lines.append(f"--- {title} ---")
            entries = correlation.get(key, {})
            if not entries:
                lines.append("  (no data)")
            for name, (avg_delay, count) in entries.items():
                note = "  [single sample - not a trend]" if count < 3 else ""
                lines.append(
                    f"  {name:<24} avg {avg_delay:10.4f} ms   n={count}{note}"
                )
            lines.append("")

        return "\n".join(lines).rstrip()


def _describe_correlation(value):
    """Plain-language strength of a correlation coefficient."""
    magnitude = abs(value)
    if magnitude < 0.1:
        return "negligible"
    if magnitude < 0.3:
        return "weak"
    if magnitude < 0.5:
        return "moderate"
    return "strong"
