import statistics
from typing import List, Dict, Any

class RootCauseAnalysis:
    """
    This class provides functionality to correlate delays with factors
    such as packet size, protocol type, source IP, and destination IP.
    """

    def __init__(self):
        """
        Initializes the RootCauseAnalysis object.
        Can be extended for additional data or config if needed.
        """
        self.records = []

    def add_record(self, delay: float, packet_size: int, protocol: str,
                   source_ip: str, destination_ip: str) -> None:
        """
        Store an individual record for analysis.

        :param delay: Delay measurement (e.g., total delay, round-trip time, etc.)
        :param packet_size: Size of the packet (bytes)
        :param protocol: Protocol name (e.g. 'TCP', 'UDP', 'MQTT', etc.)
        :param source_ip: Source IP address
        :param destination_ip: Destination IP address
        """
        self.records.append({
            "delay": delay,
            "packet_size": packet_size,
            "protocol": protocol,
            "source_ip": source_ip,
            "destination_ip": destination_ip
        })

    def compute_statistics(self) -> Dict[str, float]:
        """
        Compute overall statistics for delays in the records.

        :return: Dictionary with min, max, average, and median.
        """
        if not self.records:
            return {"min_delay": 0.0, "max_delay": 0.0, "avg_delay": 0.0, "median_delay": 0.0}

        delays = [r["delay"] for r in self.records]
        return {
            "min_delay": min(delays),
            "max_delay": max(delays),
            "avg_delay": sum(delays) / len(delays),
            "median_delay": statistics.median(delays)
        }

    def correlate_factors(self) -> Dict[str, Dict[Any, float]]:
        """
        Correlate average delays by packet size, protocol, source IP, and destination IP.

        :return: Nested dictionary with average delay for each factor grouping.
        """
        factor_buckets = {
            "packet_size": {},
            "protocol": {},
            "source_ip": {},
            "destination_ip": {}
        }

        for record in self.records:
            for factor in factor_buckets:
                key = record[factor]
                if key not in factor_buckets[factor]:
                    factor_buckets[factor][key] = []
                factor_buckets[factor][key].append(record["delay"])

        # Compute average delays per factor
        for factor, value_map in factor_buckets.items():
            for key, values in value_map.items():
                factor_buckets[factor][key] = sum(values) / len(values)

        return factor_buckets

    def generate_report(self) -> str:
        """
        Generate a plain-text report summarizing the overall delay stats
        and the correlation results.

        :return: A formatted multiline string with the analysis findings.
        """
        stats = self.compute_statistics()
        correlation = self.correlate_factors()

        lines = []
        lines.append("=== Root Cause Analysis Report ===")
        lines.append(f"Min Delay: {stats['min_delay']:.4f} ms")
        lines.append(f"Max Delay: {stats['max_delay']:.4f} ms")
        lines.append(f"Avg Delay: {stats['avg_delay']:.4f} ms")
        lines.append(f"Median Delay: {stats['median_delay']:.4f} ms")
        lines.append("")

        # Correlation details
        lines.append("--- Correlation by Packet Size ---")
        for size, avg_delay in sorted(correlation["packet_size"].items()):
            lines.append(f"  Size: {size} bytes -> Avg Delay: {avg_delay:.4f} ms")
        lines.append("")

        lines.append("--- Correlation by Protocol ---")
        for proto, avg_delay in correlation["protocol"].items():
            lines.append(f"  Protocol: {proto} -> Avg Delay: {avg_delay:.4f} ms")
        lines.append("")

        lines.append("--- Correlation by Source IP ---")
        for s_ip, avg_delay in correlation["source_ip"].items():
            lines.append(f"  Source IP: {s_ip} -> Avg Delay: {avg_delay:.4f} ms")
        lines.append("")

        lines.append("--- Correlation by Destination IP ---")
        for d_ip, avg_delay in correlation["destination_ip"].items():
            lines.append(f"  Destination IP: {d_ip} -> Avg Delay: {avg_delay:.4f} ms")

        return "\n".join(lines)